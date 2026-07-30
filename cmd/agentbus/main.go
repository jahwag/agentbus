// agentbus is the client CLI. `agentbus wait` is the background-task
// primitive: it retries timeouts and connection errors internally and exits
// only when mail arrives, so a parked wait costs an agent zero tokens.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jahwag/agentbus/internal/buildinfo"
	"github.com/jahwag/agentbus/internal/credentialfile"
)

const (
	maxCLIResponseBytes = 512 * 1024
	maxTokenFileBytes   = 8 * 1024
)

const topLevelHelp = `Usage: agentbus <command> [options]

Agent commands:
  wait     wait through transient failures and print one validated delivery
  send     send an idempotent direct or broadcast message
  ack      acknowledge a delivery after processing
  roster   list active mailboxes

Admin commands:
mint     mint or rotate an identity into a protected token file
bind-identity bind an OIDC issuer/subject to an agent or operator mailbox
unbind-identity remove an OIDC issuer/subject binding
  skip     dead-letter one poison receipt with an audit reason
  retire   retire a mailbox with an audit reason
  prune    prune terminal mail using a retention or explicit cutoff
  backlog  inspect unsettled receipt totals by mailbox
  activity inspect body-free since-tracking traffic by mailbox
  audit    inspect recent administrative audit events
  ui-session mint a short-lived one-time code for the loopback dashboard

Run "agentbus <command> --help" for command flags.
Environment: AGENTBUS_SERVER, AGENTBUS_NAME, AGENTBUS_TOKEN,
AGENTBUS_TOKEN_FILE, AGENTBUS_ADMIN_TOKEN_FILE.
`

const (
	defaultPollTimeout = 290 * time.Second
	pollDeadlineMargin = 10 * time.Second
	oneShotTimeout     = 30 * time.Second
	initialRetryDelay  = 100 * time.Millisecond
	maximumRetryDelay  = 10 * time.Second
	maximumRetryAfter  = 30 * time.Second
	maxUILoginCodeTTL  = 3 * time.Minute
)

// execute is the command module's interface. Parsing, credential loading, and
// HTTP behavior stay behind this seam so main and tests exercise the same path.
func execute(ctx context.Context, args []string, stdout, stderr io.Writer, client *http.Client) error {
	if len(args) == 0 {
		return errors.New("usage: agentbus <command> [options]")
	}
	switch args[0] {
	case "-h", "--help", "help":
		_, err := io.WriteString(stdout, topLevelHelp)
		return err
	case "--version", "version":
		_, err := fmt.Fprintln(stdout, buildinfo.String())
		return err
	case "ui-session":
		fs := flag.NewFlagSet("ui-session", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777"), "AgentBus server URL")
		adminTokenFile := fs.String("admin-token-file", os.Getenv("AGENTBUS_ADMIN_TOKEN_FILE"), "admin bearer-token file")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if *adminTokenFile == "" {
			return errors.New("ui-session requires --admin-token-file or AGENTBUS_ADMIN_TOKEN_FILE")
		}
		adminToken, err := readTokenFile(*adminTokenFile)
		if err != nil {
			return err
		}
		out, err := requestJSON(ctx, client, http.MethodPost,
			strings.TrimRight(*server, "/")+"/ui/bootstrap", adminToken, struct{}{})
		if err != nil {
			return err
		}
		if err := validateUISessionResponse(out, time.Now()); err != nil {
			return err
		}
		return writeOutput(stdout, out)
	case "backlog", "activity", "audit":
		command := args[0]
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777"), "AgentBus server URL")
		adminTokenFile := fs.String("admin-token-file", os.Getenv("AGENTBUS_ADMIN_TOKEN_FILE"), "admin bearer-token file")
		var afterID *int64
		var limit *int
		if command == "audit" {
			afterID = fs.Int64("after-id", 0, "return events with IDs greater than this value")
			limit = fs.Int("limit", 100, "maximum events to return (1-1000)")
		}
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		endpoint := strings.TrimRight(*server, "/") + "/" + command
		if command == "audit" {
			if *afterID < 0 {
				return errors.New("--after-id must not be negative")
			}
			if *limit < 1 || *limit > 1000 {
				return errors.New("--limit must be between 1 and 1000")
			}
			query := url.Values{}
			query.Set("after_id", strconv.FormatInt(*afterID, 10))
			query.Set("limit", strconv.Itoa(*limit))
			endpoint += "?" + query.Encode()
		}
		adminToken, err := readTokenFile(*adminTokenFile)
		if err != nil {
			return err
		}
		out, err := requestNoBody(ctx, client, http.MethodGet, endpoint, adminToken)
		if err != nil {
			return err
		}
		return writeOutput(stdout, out)
	case "prune":
		fs := flag.NewFlagSet("prune", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777"), "AgentBus server URL")
		adminTokenFile := fs.String("admin-token-file", os.Getenv("AGENTBUS_ADMIN_TOKEN_FILE"), "admin bearer-token file")
		before := fs.String("before", "", "prune terminal mail before RFC3339 time")
		retention := fs.Duration("retention", 720*time.Hour, "terminal-mail retention (default 720h)")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		retentionSet := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "retention" {
				retentionSet = true
			}
		})
		if *before != "" && retentionSet {
			return errors.New("--before and --retention are mutually exclusive")
		}
		if *retention <= 0 {
			return errors.New("--retention must be greater than zero")
		}
		cutoff := time.Now().Add(-*retention).UTC()
		if *before != "" {
			parsed, err := time.Parse(time.RFC3339, *before)
			if err != nil {
				return fmt.Errorf("--before must be RFC3339: %w", err)
			}
			cutoff = parsed.UTC()
		}
		adminToken, err := readTokenFile(*adminTokenFile)
		if err != nil {
			return err
		}
		out, err := requestJSON(ctx, client, http.MethodPost, strings.TrimRight(*server, "/")+"/prune", adminToken,
			map[string]string{"before": cutoff.Format(time.RFC3339Nano)})
		if err != nil {
			return err
		}
		return writeOutput(stdout, out)
	case "retire":
		fs := flag.NewFlagSet("retire", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777"), "AgentBus server URL")
		adminTokenFile := fs.String("admin-token-file", os.Getenv("AGENTBUS_ADMIN_TOKEN_FILE"), "admin bearer-token file")
		name := fs.String("name", "", "mailbox name")
		reason := fs.String("reason", "", "audit reason")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if *name == "" || *reason == "" {
			return errors.New("retire requires --name and --reason")
		}
		adminToken, err := readTokenFile(*adminTokenFile)
		if err != nil {
			return err
		}
		_, err = requestJSON(ctx, client, http.MethodPost, strings.TrimRight(*server, "/")+"/retire", adminToken,
			map[string]string{"name": *name, "reason": *reason})
		return err
	case "bind-identity":
		fs := flag.NewFlagSet("bind-identity", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", "http://127.0.0.1:7777", "AgentBus base URL")
		adminTokenFile := fs.String("admin-token-file", os.Getenv("AGENTBUS_ADMIN_TOKEN_FILE"), "administrator token file")
		name := fs.String("name", "", "mailbox name")
		kind := fs.String("kind", "", "agent or operator")
		issuer := fs.String("issuer", "", "OIDC issuer")
		subject := fs.String("subject", "", "OIDC subject")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" || *kind == "" || *issuer == "" || *subject == "" || *adminTokenFile == "" {
			return errors.New("bind-identity requires --name, --kind, --issuer, --subject, and --admin-token-file")
		}
		adminToken, err := readTokenFile(*adminTokenFile)
		if err != nil {
			return err
		}
		out, err := requestJSON(ctx, client, http.MethodPost, strings.TrimRight(*server, "/")+"/bind-identity", adminToken, map[string]string{
			"name": *name, "kind": *kind, "issuer": *issuer, "subject": *subject,
		})
		if err != nil {
			return err
		}
		return writeOutput(stdout, out)
	case "unbind-identity":
		fs := flag.NewFlagSet("unbind-identity", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", "http://127.0.0.1:7777", "AgentBus base URL")
		adminTokenFile := fs.String("admin-token-file", os.Getenv("AGENTBUS_ADMIN_TOKEN_FILE"), "administrator token file")
		issuer := fs.String("issuer", "", "OIDC issuer")
		subject := fs.String("subject", "", "OIDC subject")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *issuer == "" || *subject == "" || *adminTokenFile == "" {
			return errors.New("unbind-identity requires --issuer, --subject, and --admin-token-file")
		}
		adminToken, err := readTokenFile(*adminTokenFile)
		if err != nil {
			return err
		}
		out, err := requestJSON(ctx, client, http.MethodPost, strings.TrimRight(*server, "/")+"/unbind-identity", adminToken, map[string]string{
			"issuer": *issuer, "subject": *subject,
		})
		if err != nil {
			return err
		}
		return writeOutput(stdout, out)
	case "mint":
		fs := flag.NewFlagSet("mint", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777"), "AgentBus server URL")
		adminTokenFile := fs.String("admin-token-file", os.Getenv("AGENTBUS_ADMIN_TOKEN_FILE"), "admin bearer-token file")
		name := fs.String("name", "", "mailbox name")
		tokenOut := fs.String("token-out", "", "new 0600 token file (must not exist)")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if *name == "" || *tokenOut == "" {
			return errors.New("mint requires --name and --token-out")
		}
		adminToken, err := readTokenFile(*adminTokenFile)
		if err != nil {
			return err
		}
		return mintCredential(ctx, client, *server, adminToken, *name, *tokenOut, stdout)
	case "wait":
		fs := flag.NewFlagSet("wait", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777"), "AgentBus server URL")
		tokenFile := fs.String("token-file", os.Getenv("AGENTBUS_TOKEN_FILE"), "agent bearer-token file")
		name := fs.String("name", os.Getenv("AGENTBUS_NAME"), "local auth-off mailbox claim")
		timeout := fs.Duration("timeout", defaultPollTimeout, "long-poll timeout")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if *timeout <= 0 || *timeout > defaultPollTimeout {
			return fmt.Errorf("--timeout must be greater than zero and at most %s", defaultPollTimeout)
		}
		token, err := readAgentToken(*tokenFile)
		if err != nil {
			return err
		}
		if *name == "" && token == "" {
			return errors.New("wait requires --name/AGENTBUS_NAME in auth-off mode or an agent token")
		}
		out, err := waitForDelivery(ctx, client, *server, *name, token, *timeout)
		if err != nil {
			return err
		}
		return writeOutput(stdout, out)
	case "roster":
		fs := flag.NewFlagSet("roster", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777"), "AgentBus server URL")
		tokenFile := fs.String("token-file", os.Getenv("AGENTBUS_TOKEN_FILE"), "agent bearer-token file")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		token, err := readAgentToken(*tokenFile)
		if err != nil {
			return err
		}
		out, err := requestNoBody(ctx, client, http.MethodGet, strings.TrimRight(*server, "/")+"/roster", token)
		if err != nil {
			return err
		}
		return writeOutput(stdout, out)
	case "ack":
		fs := flag.NewFlagSet("ack", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777"), "AgentBus server URL")
		tokenFile := fs.String("token-file", os.Getenv("AGENTBUS_TOKEN_FILE"), "agent bearer-token file")
		name := fs.String("name", os.Getenv("AGENTBUS_NAME"), "local auth-off mailbox claim")
		deliveryID := fs.String("delivery-id", "", "delivery ID to acknowledge")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if *deliveryID == "" {
			return errors.New("ack requires --delivery-id")
		}
		token, err := readAgentToken(*tokenFile)
		if err != nil {
			return err
		}
		if *name == "" && token == "" {
			return errors.New("ack requires --name/AGENTBUS_NAME in auth-off mode or an agent token")
		}
		out, err := requestJSON(ctx, client, http.MethodPost, strings.TrimRight(*server, "/")+"/ack", token,
			map[string]string{"name": *name, "delivery_id": *deliveryID})
		if err != nil {
			return err
		}
		return writeOutput(stdout, out)
	case "send":
		fs := flag.NewFlagSet("send", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777"), "AgentBus server URL")
		tokenFile := fs.String("token-file", os.Getenv("AGENTBUS_TOKEN_FILE"), "agent bearer-token file")
		from := fs.String("from", os.Getenv("AGENTBUS_NAME"), "local auth-off sender claim")
		to := fs.String("to", "", "recipient mailbox or *")
		body := fs.String("body", "", "message body")
		data := fs.String("data", "", "optional JSON data")
		replyTo := fs.String("reply-to", "", "message ID being replied to")
		clientMessageID := fs.String("client-message-id", "", "required idempotency key")
		allowNew := fs.Bool("allow-new", false, "reserve an unknown direct mailbox")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if *to == "" || *clientMessageID == "" {
			return errors.New("send requires --to and --client-message-id")
		}
		token, err := readAgentToken(*tokenFile)
		if err != nil {
			return err
		}
		if *from == "" && token == "" {
			return errors.New("send requires --from/AGENTBUS_NAME in auth-off mode or an agent token")
		}
		var rawData json.RawMessage
		if *data != "" {
			rawData = json.RawMessage(*data)
			if !json.Valid(rawData) {
				return errors.New("--data must be valid JSON")
			}
		}
		request := struct {
			From            string          `json:"from"`
			To              string          `json:"to"`
			Body            string          `json:"body"`
			Data            json.RawMessage `json:"data,omitempty"`
			ReplyTo         string          `json:"reply_to,omitempty"`
			ClientMessageID string          `json:"client_message_id"`
			AllowNew        bool            `json:"allow_new,omitempty"`
		}{*from, *to, *body, rawData, *replyTo, *clientMessageID, *allowNew}
		out, err := requestJSON(ctx, client, http.MethodPost, strings.TrimRight(*server, "/")+"/send", token, request)
		if err != nil {
			return err
		}
		return writeOutput(stdout, out)
	case "skip":
		fs := flag.NewFlagSet("skip", flag.ContinueOnError)
		fs.SetOutput(stderr)
		server := fs.String("server", envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777"), "AgentBus server URL")
		tokenFile := fs.String("admin-token-file", os.Getenv("AGENTBUS_ADMIN_TOKEN_FILE"), "admin bearer-token file")
		name := fs.String("name", "", "mailbox name")
		messageID := fs.String("message-id", "", "message ID to dead-letter")
		reason := fs.String("reason", "", "audit reason")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if *name == "" || *messageID == "" || *reason == "" {
			return errors.New("skip requires --name, --message-id, and --reason")
		}
		token, err := readTokenFile(*tokenFile)
		if err != nil {
			return err
		}
		_, err = requestJSON(ctx, client, http.MethodPost, strings.TrimRight(*server, "/")+"/skip", token,
			map[string]string{"name": *name, "message_id": *messageID, "reason": *reason})
		return err
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s: unexpected arguments: %s", fs.Name(), strings.Join(fs.Args(), " "))
	}
	return nil
}

func mintCredential(ctx context.Context, client *http.Client, server, adminToken, name, tokenOut string, stdout io.Writer) (err error) {
	sink, err := os.OpenFile(tokenOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create token output: %w", err)
	}
	keep := false
	defer func() {
		_ = sink.Close()
		if !keep {
			_ = os.Remove(tokenOut)
		}
	}()

	out, err := requestJSON(ctx, client, http.MethodPost, strings.TrimRight(server, "/")+"/mint", adminToken,
		map[string]string{"name": name})
	if err != nil {
		return err
	}
	var minted struct {
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	if err := dec.Decode(&minted); err != nil || minted.Name != name || minted.Token == "" {
		return errors.New("mint returned an invalid credential response")
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("mint returned an invalid credential response")
	}
	if _, err := fmt.Fprintln(sink, minted.Token); err != nil {
		return fmt.Errorf("write token output: %w", err)
	}
	if err := sink.Sync(); err != nil {
		return fmt.Errorf("sync token output: %w", err)
	}
	if err := sink.Close(); err != nil {
		return fmt.Errorf("close token output: %w", err)
	}
	keep = true
	return json.NewEncoder(stdout).Encode(map[string]any{
		"minted": true, "name": minted.Name, "token_file": tokenOut,
	})
}

func waitForDelivery(ctx context.Context, client *http.Client, server, name, token string, pollTimeout time.Duration) ([]byte, error) {
	if err := validateEndpoint(server); err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(strings.TrimRight(server, "/") + "/wait")
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("name", name)
	query.Set("timeout", fmt.Sprintf("%g", pollTimeout.Seconds()))
	endpoint.RawQuery = query.Encode()

	backoff := initialRetryDelay
	for {
		pollCtx, cancel := context.WithTimeout(ctx, pollTimeout+pollDeadlineMargin)
		req, reqErr := http.NewRequestWithContext(pollCtx, http.MethodGet, endpoint.String(), nil)
		if reqErr != nil {
			cancel()
			return nil, reqErr
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, doErr := doWithoutRedirects(client, req)
		if doErr != nil {
			cancel()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err := sleepWithBackoff(ctx, backoff); err != nil {
				return nil, err
			}
			backoff = min(backoff*2, maximumRetryDelay)
			continue
		}

		out, readErr := readResponse(resp)
		cancel()
		if readErr != nil {
			return nil, readErr
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			if err := validateDelivery(out); err != nil {
				return nil, err
			}
			return out, nil
		case resp.StatusCode == http.StatusNoContent:
			backoff = initialRetryDelay
			continue
		case resp.StatusCode == http.StatusTooManyRequests:
			if delay, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
				if err := sleepFor(ctx, delay); err != nil {
					return nil, err
				}
			} else if err := sleepWithBackoff(ctx, backoff); err != nil {
				return nil, err
			}
			backoff = min(backoff*2, maximumRetryDelay)
			continue
		case resp.StatusCode >= 500:
			if err := sleepWithBackoff(ctx, backoff); err != nil {
				return nil, err
			}
			backoff = min(backoff*2, maximumRetryDelay)
			continue
		default:
			return nil, fmt.Errorf("wait failed (%d): %s", resp.StatusCode, out)
		}
	}
}

func sleepWithBackoff(ctx context.Context, upper time.Duration) error {
	// Equal jitter preserves exponential growth without synchronizing every
	// background waiter after a daemon or network outage.
	lower := upper / 2
	delay := lower
	if span := upper - lower; span > 0 {
		delay += time.Duration(rand.Int64N(int64(span) + 1))
	}
	return sleepFor(ctx, delay)
}

func sleepFor(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		if seconds >= int64(maximumRetryAfter/time.Second) {
			return maximumRetryAfter, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := when.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return min(delay, maximumRetryAfter), true
}

func validateDelivery(raw []byte) error {
	var delivery struct {
		ID       string `json:"delivery_id"`
		Messages []struct {
			ID string `json:"message_id"`
		} `json:"messages"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&delivery); err != nil {
		return errors.New("wait returned invalid delivery JSON")
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("wait returned invalid delivery JSON")
	}
	if delivery.ID == "" || len(delivery.Messages) == 0 {
		return errors.New("wait returned an empty delivery")
	}
	for _, message := range delivery.Messages {
		if message.ID == "" {
			return errors.New("wait returned a delivery with an invalid message")
		}
	}
	return nil
}

func validateUISessionResponse(raw []byte, now time.Time) error {
	var response struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expires_at"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&response); err != nil {
		return errors.New("ui-session returned invalid JSON")
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("ui-session returned invalid JSON")
	}
	if len(response.Code) < 20 || len(response.Code) > 64 || strings.ContainsAny(response.Code, " \t\r\n") {
		return errors.New("ui-session returned an invalid login code")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	if err != nil || !expiresAt.After(now.Add(-5*time.Second)) || expiresAt.After(now.Add(maxUILoginCodeTTL)) {
		return errors.New("ui-session returned an invalid expiry")
	}
	return nil
}

func readAgentToken(path string) (string, error) {
	if path != "" {
		return readTokenFile(path)
	}
	return strings.TrimSpace(os.Getenv("AGENTBUS_TOKEN")), nil
}

func writeOutput(w io.Writer, out []byte) error {
	if len(out) == 0 {
		return nil
	}
	_, err := fmt.Fprintln(w, string(out))
	return err
}

func readTokenFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := credentialfile.Read(path, maxTokenFileBytes)
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", errors.New("token file is empty")
	}
	return token, nil
}

func requestJSON(ctx context.Context, client *http.Client, method, endpoint, token string, body any) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return doRequest(ctx, client, method, endpoint, token, bytes.NewReader(buf), true)
}

func requestNoBody(ctx context.Context, client *http.Client, method, endpoint, token string) ([]byte, error) {
	return doRequest(ctx, client, method, endpoint, token, nil, false)
}

func doRequest(ctx context.Context, client *http.Client, method, endpoint, token string, body io.Reader, jsonBody bool) ([]byte, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, oneShotTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	if jsonBody {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := doWithoutRedirects(client, req)
	if err != nil {
		return nil, err
	}
	out, err := readResponse(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("request failed (%d): %s", resp.StatusCode, out)
	}
	return out, nil
}

func doWithoutRedirects(client *http.Client, req *http.Request) (*http.Response, error) {
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return copy.Do(req)
}

func readResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxCLIResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxCLIResponseBytes {
		return nil, errors.New("response exceeds 512 KiB limit")
	}
	return bytes.TrimSpace(out), nil
}

func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid AgentBus server URL %q", raw)
	}
	if u.User != nil {
		return errors.New("AgentBus server URL must not contain credentials")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("refusing plain HTTP AgentBus server %q: plain HTTP is loopback-only", raw)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	err := execute(ctx, os.Args[1:], os.Stdout, os.Stderr, http.DefaultClient)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentbus:", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
