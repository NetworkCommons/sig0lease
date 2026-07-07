package handlers

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestChainPreservesMessageBetweenHandlers(t *testing.T) {
	msg := dns.NewMsg("example.com.", dns.TypeA)
	if msg == nil {
		t.Fatalf("expected non-nil message")
	}

	var secondSawName string

	h1 := func(ctx context.Context, _ dns.ResponseWriter, r *dns.Msg) (*dns.Msg, context.Context, error) {
		if r == nil || len(r.Question) != 1 {
			t.Fatalf("first handler received unexpected message")
		}
		// Mutate this handler-local copy; next handler should still see original.
		r.Question[0].Header().Name = "mutated.example."
		return nil, context.WithValue(ctx, "k", "v"), nil
	}

	h2 := func(ctx context.Context, _ dns.ResponseWriter, r *dns.Msg) (*dns.Msg, context.Context, error) {
		if got := ctx.Value("k"); got != "v" {
			t.Fatalf("expected context value propagated, got %v", got)
		}
		if r == nil || len(r.Question) != 1 {
			t.Fatalf("second handler received empty message")
		}
		secondSawName = r.Question[0].Header().Name
		return nil, ctx, nil
	}

	_, _, err := Chain(h1, h2)(context.Background(), nil, msg)
	if err != nil {
		t.Fatalf("chain returned error: %v", err)
	}

	if secondSawName != "example.com." {
		t.Fatalf("expected second handler to receive original content, got %q", secondSawName)
	}
}
