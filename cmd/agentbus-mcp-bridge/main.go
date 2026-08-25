// agentbus-mcp-bridge exposes a remote authenticated AgentBus MCP resource as
// local stdio. It keeps native or short-lived Entra credentials out of the MCP
// client process and refreshes Entra client-credential tokens automatically.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/jahwag/agentbus/internal/buildinfo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

type azureTokenSource struct {
	ctx        context.Context
	credential azcore.TokenCredential
	scope      string
}

func (source azureTokenSource) Token() (*oauth2.Token, error) {
	token, err := source.credential.GetToken(
		source.ctx,
		policy.TokenRequestOptions{Scopes: []string{source.scope}},
	)
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken: token.Token,
		TokenType:   "Bearer",
		Expiry:      token.ExpiresOn,
	}, nil
}

func (transport bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := transport.base
	if base == nil {
		base = http.DefaultTransport
	}
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer "+transport.token)
	return base.RoundTrip(clone)
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(buildinfo.String())
		return
	}
	ctx := context.Background()
	endpoint := strings.TrimSpace(os.Getenv("AGENTBUS_MCP_URL"))
	if err := validateEndpoint(endpoint); err != nil {
		log.Fatal(err)
	}
	httpClient, err := authenticatedClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	remoteClient := mcp.NewClient(
		&mcp.Implementation{Name: "agentbus-bridge", Version: buildinfo.Version},
		nil,
	)
	remote, err := remoteClient.Connect(
		ctx,
		&mcp.StreamableClientTransport{
			Endpoint:             endpoint,
			HTTPClient:           httpClient,
			DisableStandaloneSSE: true,
		},
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer remote.Close()
	listed, err := remote.ListTools(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	local := mcp.NewServer(
		&mcp.Implementation{Name: "agentbus-bridge", Version: buildinfo.Version},
		nil,
	)
	for _, tool := range listed.Tools {
		tool := tool
		name := tool.Name
		local.AddTool(tool, func(
			ctx context.Context,
			request *mcp.CallToolRequest,
		) (*mcp.CallToolResult, error) {
			return remote.CallTool(ctx, &mcp.CallToolParams{
				Name: name, Arguments: request.Params.Arguments,
			})
		})
	}
	if err := local.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

func authenticatedClient(ctx context.Context) (*http.Client, error) {
	if token := strings.TrimSpace(os.Getenv("AGENTBUS_TOKEN")); token != "" {
		return &http.Client{
			Transport:     bearerTransport{token: token, base: http.DefaultTransport},
			CheckRedirect: rejectAuthenticatedRedirect,
		}, nil
	}
	scope := strings.TrimSpace(os.Getenv("AGENTBUS_SCOPE"))
	if scope == "" {
		audience := strings.TrimSuffix(
			strings.TrimSpace(os.Getenv("AGENTBUS_AUDIENCE")),
			"/",
		)
		if audience == "" {
			return nil, errors.New("AGENTBUS_SCOPE or AGENTBUS_AUDIENCE is required")
		}
		scope = audience + "/.default"
	}
	credential, err := azidentity.NewDefaultAzureCredential(
		&azidentity.DefaultAzureCredentialOptions{
			RequireAzureTokenCredentials: true,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("initialize Azure credential: %w", err)
	}
	tokens := oauth2.ReuseTokenSource(nil, azureTokenSource{
		ctx: ctx, credential: credential, scope: scope,
	})
	client := oauth2.NewClient(ctx, tokens)
	client.CheckRedirect = rejectAuthenticatedRedirect
	return client, nil
}

func rejectAuthenticatedRedirect(*http.Request, []*http.Request) error {
	return errors.New("authenticated MCP redirects are disabled")
}

func validateEndpoint(raw string) error {
	if raw == "" {
		return errors.New("AGENTBUS_MCP_URL is required")
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.User != nil || endpoint.Host == "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("AGENTBUS_MCP_URL must be an absolute URL without credentials, query, or fragment")
	}
	if endpoint.Scheme == "https" {
		return nil
	}
	host := endpoint.Hostname()
	ip := net.ParseIP(host)
	if endpoint.Scheme == "http" &&
		(host == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return errors.New("AGENTBUS_MCP_URL must use HTTPS, except for HTTP loopback development")
}
