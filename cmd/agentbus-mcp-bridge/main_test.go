package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateEndpointRequiresHTTPSOrLoopback(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		ok       bool
	}{
		{"https://agentbus.example.com/mcp", true},
		{"http://127.0.0.1:7777/mcp", true},
		{"http://[::1]:7777/mcp", true},
		{"http://agentbus.example.com/mcp", false},
		{"https://user:secret@agentbus.example.com/mcp", false},
		{"https://agentbus.example.com/mcp?token=secret", false},
		{"", false},
	} {
		err := validateEndpoint(tc.endpoint)
		if tc.ok && err != nil {
			t.Errorf("validateEndpoint(%q) = %v", tc.endpoint, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("validateEndpoint(%q) unexpectedly succeeded", tc.endpoint)
		}
	}
}

func TestAuthenticatedClientSupportsNativeTokenWithoutLeakingItIntoURL(t *testing.T) {
	t.Setenv("AGENTBUS_TOKEN", "native-agent-token")
	t.Setenv("AGENTBUS_SCOPE", "")
	t.Setenv("AGENTBUS_AUDIENCE", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer native-agent-token" {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("credential leaked into URL: %s", r.URL)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := authenticatedClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestAuthenticatedClientRejectsRedirectWithoutForwardingToken(t *testing.T) {
	t.Setenv("AGENTBUS_TOKEN", "native-agent-token")
	t.Setenv("AGENTBUS_SCOPE", "")
	t.Setenv("AGENTBUS_AUDIENCE", "")
	targetHit := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusTemporaryRedirect))
	defer redirect.Close()

	client, err := authenticatedClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(redirect.URL); err == nil {
		t.Fatal("authenticated client followed redirect")
	}
	select {
	case authorization := <-targetHit:
		t.Fatalf("redirect target received Authorization %q", authorization)
	default:
	}
}

func TestEntraClientRequiresPinnedCredentialChain(t *testing.T) {
	t.Setenv("AGENTBUS_TOKEN", "")
	t.Setenv("AGENTBUS_SCOPE", "api://agentbus/.default")
	t.Setenv("AGENTBUS_AUDIENCE", "")
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "")
	if _, err := authenticatedClient(context.Background()); err == nil {
		t.Fatal("missing AZURE_TOKEN_CREDENTIALS did not fail closed")
	}
}
