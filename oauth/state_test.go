package oauth

import (
	"testing"
	"time"
)

func TestFlowRoundTrip(t *testing.T) {
	flow, err := NewFlow("generic")
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}
	encoded, err := flow.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := DecodeFlow(encoded)
	if err != nil {
		t.Fatalf("DecodeFlow: %v", err)
	}
	if decoded.Provider != flow.Provider || decoded.State != flow.State || decoded.Nonce != flow.Nonce {
		t.Fatalf("decoded flow %+v does not match original %+v", decoded, flow)
	}
}

func TestDecodeFlowRejectsTamperingAndEmpty(t *testing.T) {
	flow, err := NewFlow("google")
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}
	encoded, err := flow.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if _, err := DecodeFlow(encoded + "tampered"); err == nil {
		t.Fatal("expected an error decoding a tampered cookie")
	}
	if _, err := DecodeFlow(""); err == nil {
		t.Fatal("expected an error decoding an empty cookie")
	}
}

func TestDecodeFlowRejectsExpired(t *testing.T) {
	flow := &Flow{
		Provider:  "generic",
		State:     "state",
		Nonce:     "nonce",
		CreatedAt: time.Now().Add(-FlowMaxAge - time.Minute).Unix(),
	}
	encoded, err := flow.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeFlow(encoded); err == nil {
		t.Fatal("expected an error decoding an expired flow cookie")
	}
}

func TestDecodeFlowRejectsIncomplete(t *testing.T) {
	flow := &Flow{Provider: "generic", CreatedAt: time.Now().Unix()} // missing state/nonce
	encoded, err := flow.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeFlow(encoded); err == nil {
		t.Fatal("expected an error decoding an incomplete flow cookie")
	}
}
