package webhook

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/policy"
)

func TestCloseCancelsInFlightDelivery(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-started:
		default:
			close(started)
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	defer srv.Close()

	sender := NewSender(policy.WebhookConfig{
		URL:       srv.URL,
		Events:    []string{string(EventPermit)},
		TimeoutMs: 10000,
	})

	sender.Send(Event{Type: EventPermit})

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook delivery attempt to start")
	}

	done := make(chan struct{})
	go func() {
		sender.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("Close blocked waiting on in-flight webhook delivery")
	}

	select {
	case <-release:
	default:
		close(release)
	}
}

func TestCloseInterruptsRetryBackoff(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sender := NewSender(policy.WebhookConfig{
		URL:       srv.URL,
		Events:    []string{string(EventPermit)},
		TimeoutMs: 100,
	})

	sender.Send(Event{Type: EventPermit})

	deadline := time.Now().Add(2 * time.Second)
	for attempts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if attempts.Load() == 0 {
		t.Fatal("expected at least one webhook attempt before closing sender")
	}

	start := time.Now()
	sender.Close()
	if elapsed := time.Since(start); elapsed > 800*time.Millisecond {
		t.Fatalf("Close took %s; expected retry backoff to be interrupted", elapsed)
	}
}

func TestCloseIsIdempotentAndSendAfterCloseIsNoop(t *testing.T) {
	sender := NewSender(policy.WebhookConfig{
		URL:       "http://127.0.0.1:1",
		Events:    []string{string(EventPermit)},
		TimeoutMs: 50,
	})

	sender.Close()

	done := make(chan struct{})
	go func() {
		sender.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("second Close call blocked")
	}

	// Assertion is no panic / no block.
	sender.Send(Event{Type: EventPermit})
}
