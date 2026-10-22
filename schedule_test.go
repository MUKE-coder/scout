package scout

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
)

var schedTargets = []core.Target{
	{Name: "shop", URL: "http://localhost:1", Environment: core.EnvDev},
	{Name: "blog", URL: "http://localhost:2", Environment: core.EnvDev},
}

func TestValidateSchedules(t *testing.T) {
	ok := []Schedule{{Name: "nightly", Cron: "0 3 * * *", Targets: []string{"shop"}, Mode: "active", Timezone: "UTC"}, {Name: "hourly", Cron: "@hourly"}}
	if err := validateSchedules(ok, schedTargets); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]Schedule{
		"no name":        {{Cron: "@daily"}},
		"duplicate name": {{Name: "a", Cron: "@daily"}, {Name: "a", Cron: "@hourly"}},
		"bad cron":       {{Name: "a", Cron: "every night"}},
		"bad timezone":   {{Name: "a", Cron: "@daily", Timezone: "Mars/Olympus"}},
		"bad mode":       {{Name: "a", Cron: "@daily", Mode: "loud"}},
		"unknown target": {{Name: "a", Cron: "@daily", Targets: []string{"nope"}}},
	}
	for name, s := range bad {
		if err := validateSchedules(s, schedTargets); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := validateSchedules([]Schedule{{Name: "a", Cron: "@daily"}}, nil); err == nil {
		t.Error("a schedule with no configured targets should be rejected")
	}
}

func TestSchedulerRunsTargetsWithModeCap(t *testing.T) {
	var mu sync.Mutex
	runs := map[string]core.Mode{}
	run := func(_ context.Context, tg core.Target, mode core.Mode) {
		mu.Lock()
		runs[tg.Name] = mode
		mu.Unlock()
	}
	// "@every 1s" fires quickly; only "shop" is selected, capped at passive.
	s, start, err := newScheduler([]Schedule{{Name: "fast", Cron: "@every 1s", Targets: []string{"shop"}, Mode: "passive"}},
		schedTargets, slog.New(slog.DiscardHandler), run)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { start(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(runs)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if mode, ok := runs["shop"]; !ok || mode != core.ModePassive {
		t.Fatalf("runs = %v", runs)
	}
	if _, ok := runs["blog"]; ok {
		t.Fatal("unselected target was scanned")
	}
	if info := s.info([]Schedule{{Name: "fast", Cron: "@every 1s"}}); len(info) != 1 || info[0].Next.IsZero() {
		t.Fatalf("info = %+v", info)
	}
}

func TestScheduleConfigLoads(t *testing.T) {
	yaml := `
targets:
  - name: shop
    url: http://localhost:1
schedules:
  - name: nightly
    cron: "0 3 * * *"
    targets: [shop]
`
	c, err := LoadConfig(writeFile(t, yaml), nil)
	if err != nil || len(c.Schedules) != 1 || c.Schedules[0].Name != "nightly" {
		t.Fatalf("schedules: %+v %v", c.Schedules, err)
	}
	_, err = LoadConfig(writeFile(t, yaml+"    mode: nuclear\n"), nil)
	if err == nil || !strings.Contains(err.Error(), "nightly") {
		t.Fatalf("bad schedule mode should be rejected: %v", err)
	}
}
