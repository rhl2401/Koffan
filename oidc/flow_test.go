package oidc

import (
	"strings"
	"testing"
	"time"
)

func TestFlowRoundTrip(t *testing.T) {
	flow, err := NewFlow("oidc")
	if err != nil {
		t.Fatal(err)
	}
	if flow.State == flow.Nonce || len(flow.State) != 64 || len(flow.Verifier) < 43 {
		t.Fatalf("weak flow: %#v", flow)
	}
	decoded, err := DecodeFlow(flow.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if *decoded != *flow {
		t.Fatalf("decoded %#v, want %#v", decoded, flow)
	}
}

func TestDecodeFlowRejectsBadCookies(t *testing.T) {
	expired := &Flow{Provider: "oidc", State: "s", Nonce: "n", Verifier: "v", CreatedAt: time.Now().Add(-FlowMaxAge - time.Minute).Unix()}
	future := &Flow{Provider: "oidc", State: "s", Nonce: "n", Verifier: "v", CreatedAt: time.Now().Add(time.Hour).Unix()}
	incomplete := &Flow{Provider: "oidc", State: "s", CreatedAt: time.Now().Unix()}
	noProvider := &Flow{State: "s", Nonce: "n", Verifier: "v", CreatedAt: time.Now().Unix()}
	for name, value := range map[string]string{
		"empty":       "",
		"garbage":     "not base64!",
		"not json":    strings.Repeat("A", 20),
		"expired":     expired.Encode(),
		"future":      future.Encode(),
		"incomplete":  incomplete.Encode(),
		"no provider": noProvider.Encode(),
	} {
		if _, err := DecodeFlow(value); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
