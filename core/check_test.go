package core

import (
	"sync"
	"testing"
)

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(CheckFunc{CheckID: "tls.b", CheckMode: ModePassive})
	r.MustRegister(CheckFunc{CheckID: "app.sqli", CheckMode: ModeActive})
	r.MustRegister(CheckFunc{CheckID: "headers.csp", CheckMode: ModePassive})

	if err := r.Register(CheckFunc{CheckID: "tls.b"}); err == nil {
		t.Fatal("duplicate ID should be rejected")
	}
	if err := r.Register(CheckFunc{}); err == nil {
		t.Fatal("empty ID should be rejected")
	}

	all := r.All()
	want := []string{"app.sqli", "headers.csp", "tls.b"}
	if len(all) != len(want) {
		t.Fatalf("len = %d", len(all))
	}
	for i, c := range all {
		if c.ID() != want[i] {
			t.Fatalf("All()[%d] = %s, want %s (must be sorted)", i, c.ID(), want[i])
		}
	}

	passive := r.Filter(func(c Check) bool { return c.Mode() <= ModePassive })
	if len(passive) != 2 {
		t.Fatalf("passive filter = %d checks", len(passive))
	}
	if _, ok := r.Get("app.sqli"); !ok {
		t.Fatal("Get failed")
	}
}

func TestRegistryConcurrent(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = r.Register(CheckFunc{CheckID: string(rune('a'+i%26)) + "x"})
			_ = r.All()
		}(i)
	}
	wg.Wait()
	if r.Len() != 26 {
		t.Fatalf("Len = %d, want 26", r.Len())
	}
}
