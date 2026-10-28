package oob

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestListenerRecordsHits(t *testing.T) {
	l, err := Start(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	tok := NewToken()
	other := NewToken()

	resp, err := http.Get(l.URL(tok)) // #nosec G107 -- local test listener
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	// Give the handler a beat to record.
	deadline := time.Now().Add(2 * time.Second)
	for len(l.Hits(tok)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	hits := l.Hits(tok)
	if len(hits) != 1 {
		t.Fatalf("hits for token = %d, want 1", len(hits))
	}
	if hits[0].Method != http.MethodGet {
		t.Errorf("method = %q", hits[0].Method)
	}
	if len(l.Hits(other)) != 0 {
		t.Errorf("unrelated token should have no hits")
	}
}

func TestStartWithBadBase(t *testing.T) {
	if _, err := Start(context.Background(), "://nope"); err == nil {
		t.Error("invalid base should error")
	}
}
