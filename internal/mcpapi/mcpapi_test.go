package mcpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jahwag/agentbus/internal/bus"
)

// Slice 9: the send → wait → ack loop works end-to-end through a real MCP
// client session; errors surface as tool errors, not transport failures.
func TestMCPRoundtrip(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	ctx := context.Background()
	serverTr, clientTr := mcp.NewInMemoryTransports()
	if _, err := NewServer(b, "").Connect(ctx, serverTr, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })

	call := func(name string, args any) map[string]any {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.IsError {
			t.Fatalf("%s returned tool error: %+v", name, res.Content)
		}
		raw, _ := json.Marshal(res.StructuredContent)
		var out map[string]any
		json.Unmarshal(raw, &out)
		return out
	}

	call("send", map[string]any{
		"from": "codex", "to": "claude", "body": "review please",
		"data": map[string]any{"pr": 7}, "client_message_id": "mcp-roundtrip", "allow_new": true,
	})

	out := call("wait", map[string]any{"name": "claude", "timeout_seconds": 2})
	if out["mail"] != true {
		t.Fatalf("wait must return mail, got %+v", out)
	}
	delivery := out["delivery"].(map[string]any)
	msgs := delivery["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["body"] != "review please" {
		t.Fatalf("wrong delivery: %+v", delivery)
	}

	ack := call("ack", map[string]any{"name": "claude", "delivery_id": delivery["delivery_id"]})
	if ack["acked"] != true || ack["delivery_id"] != delivery["delivery_id"] {
		t.Fatalf("ack must confirm the opaque delivery, got %+v", ack)
	}

	out = call("wait", map[string]any{"name": "claude", "timeout_seconds": 0.05})
	if out["mail"] != false {
		t.Fatalf("empty wait must return mail=false, got %+v", out)
	}

	roster := call("roster", map[string]any{})
	if agents := roster["agents"].([]any); len(agents) != 2 {
		t.Fatalf("roster must list both agents, got %+v", roster)
	}

	// A bus-level rejection surfaces as a tool error, not a transport error.
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "send", Arguments: map[string]any{"from": "codex", "to": "ghost", "body": "x", "client_message_id": "mcp-unknown"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("unknown recipient must be a tool error")
	}
}

// Slice 10 (MCP side): a bound server pins identity to the credential; a lied
// "from" is overridden.
func TestBoundServerPinsIdentity(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	ctx := context.Background()
	serverTr, clientTr := mcp.NewInMemoryTransports()
	if _, err := NewServer(b, "worker-1").Connect(ctx, serverTr, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "send", Arguments: map[string]any{"from": "lead", "to": "lead", "body": "hi", "client_message_id": "mcp-bound", "allow_new": true},
	})
	if err != nil || res.IsError {
		t.Fatalf("send: %v %+v", err, res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var m struct{ From string }
	json.Unmarshal(raw, &m)
	if m.From != "worker-1" {
		t.Fatalf("bound server must stamp the credential identity, got from=%q", m.From)
	}
}

// Claude Code's TypeScript MCP SDK validates tools/list strictly: a boolean
// JSON Schema under properties ("data": true, inferred for Go `any` fields)
// fails validation and the client discards the entire tool list. Every
// property schema must serialize as a JSON object.
func TestToolSchemasSerializeWithoutBooleanProperties(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	ctx := context.Background()
	serverTr, clientTr := mcp.NewInMemoryTransports()
	if _, err := NewServer(b, "").Connect(ctx, serverTr, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) == 0 {
		t.Fatal("server must expose tools")
	}
	for _, tool := range tools.Tools {
		raw, err := json.Marshal(tool)
		if err != nil {
			t.Fatal(err)
		}
		var node any
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatal(err)
		}
		requireObjectPropertySchemas(t, tool.Name, "", node)
	}
}

func requireObjectPropertySchemas(t *testing.T, tool, path string, node any) {
	t.Helper()
	switch v := node.(type) {
	case map[string]any:
		for key, val := range v {
			if key == "properties" {
				props, _ := val.(map[string]any)
				for name, ps := range props {
					if _, ok := ps.(map[string]any); !ok {
						t.Errorf("%s: %s/properties/%s is %v, not an object schema", tool, path, name, ps)
					}
				}
			}
			requireObjectPropertySchemas(t, tool, path+"/"+key, val)
		}
	case []any:
		for i, item := range v {
			requireObjectPropertySchemas(t, tool, fmt.Sprintf("%s/%d", path, i), item)
		}
	}
}

func TestHandlerBoundsRequestBodies(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	h := Handler(b)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(bytes.Repeat([]byte("x"), 256*1024+1)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code < 400 {
		t.Fatalf("oversized MCP request must be rejected, got %d", rec.Code)
	}
}

func TestMCPDoesNotExposeStorageErrors(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	serverTr, clientTr := mcp.NewInMemoryTransports()
	if _, err := NewServer(b, "").Connect(ctx, serverTr, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "roster", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("closed storage must produce a tool error")
	}
	raw, _ := json.Marshal(res.Content)
	if got := string(raw); strings.Contains(got, "database") || strings.Contains(got, "sql:") {
		t.Fatalf("storage detail leaked: %s", got)
	}
}
