package storage

import (
	"context"
	"errors"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// ErrNotFound is returned when a scan or finding does not exist.
var ErrNotFound = errors.New("storage: not found")

// FindingFilter narrows ListFindings. Zero values mean "any".
type FindingFilter struct {
	ScanID      string
	Severity    *core.Severity
	Category    *core.Category
	Status      core.Status
	Fingerprint string
	Limit       int
}

// Store persists scans and findings. Implementations are safe for
// concurrent use.
type Store interface {
	// SaveScan inserts or replaces a scan, including its findings.
	SaveScan(ctx context.Context, s core.ScanResult) error
	GetScan(ctx context.Context, id string) (core.ScanResult, error)
	// ListScans returns scans newest first, without findings populated.
	ListScans(ctx context.Context, limit int) ([]core.ScanResult, error)
	// LatestScan returns the newest scan for a target name.
	LatestScan(ctx context.Context, target string) (core.ScanResult, error)
	ListFindings(ctx context.Context, f FindingFilter) ([]core.Finding, error)
	// Prune deletes scans that finished before the cutoff and returns how many.
	Prune(ctx context.Context, before time.Time) (int, error)
	Close() error
}
