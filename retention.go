package scout

import (
	"context"
	"log/slog"
	"time"

	"github.com/MUKE-coder/scout/storage"
)

// DefaultPruneInterval is how often the background pruner runs.
const DefaultPruneInterval = time.Hour

// Prune deletes scans that finished more than retention ago and returns how
// many were removed.
func Prune(ctx context.Context, store storage.Store, retention time.Duration, now time.Time) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	return store.Prune(ctx, now.Add(-retention))
}

// runPruner prunes once at start and then every interval until ctx ends.
func runPruner(ctx context.Context, store storage.Store, retention, interval time.Duration, log *slog.Logger) {
	prune := func() {
		n, err := Prune(ctx, store, retention, time.Now())
		switch {
		case err != nil && ctx.Err() == nil:
			log.Error("pruning scan history", "err", err)
		case n > 0:
			log.Info("pruned old scans", "removed", n, "retention", retention)
		}
	}
	prune()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}
