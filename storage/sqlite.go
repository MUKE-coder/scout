package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/MUKE-coder/scout/core"
)

// scanRow is the persisted scan. The full target and bookkeeping live in
// JSON columns; frequently queried fields are real columns.
type scanRow struct {
	ID           string `gorm:"primaryKey"`
	TargetName   string `gorm:"index"`
	Mode         int
	StartedAt    time.Time
	FinishedAt   time.Time `gorm:"index"`
	Score        float64
	Grade        string
	TargetJSON   string
	SkippedJSON  string
	ErrorsJSON   string
	AssessedJSON string
}

func (scanRow) TableName() string { return "scout_scans" }

// findingRow is one finding within one scan.
type findingRow struct {
	ID          uint   `gorm:"primaryKey"`
	ScanID      string `gorm:"index"`
	Fingerprint string `gorm:"index"`
	CheckID     string `gorm:"index"`
	Severity    int    `gorm:"index"`
	Category    int    `gorm:"index"`
	Status      string `gorm:"index"`
	Data        string // full core.Finding as JSON
}

func (findingRow) TableName() string { return "scout_findings" }

// SQLite is a durable Store backed by pure-Go SQLite (no CGo).
type SQLite struct {
	db *gorm.DB
}

// OpenSQLite opens (or creates) the database at path and migrates the schema.
func OpenSQLite(path string) (*SQLite, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if err := db.AutoMigrate(&scanRow{}, &findingRow{}); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &SQLite{db: db}, nil
}

func (s *SQLite) SaveScan(ctx context.Context, sc core.ScanResult) error {
	row, err := toScanRow(sc)
	if err != nil {
		return err
	}
	findings := make([]findingRow, 0, len(sc.Findings))
	for _, f := range sc.Findings {
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		findings = append(findings, findingRow{
			ScanID: sc.ID, Fingerprint: f.Fingerprint, CheckID: f.CheckID,
			Severity: int(f.Severity), Category: int(f.Category), Status: string(f.Status), Data: string(data),
		})
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		if err := tx.Where("scan_id = ?", sc.ID).Delete(&findingRow{}).Error; err != nil {
			return err
		}
		if len(findings) == 0 {
			return nil
		}
		return tx.CreateInBatches(findings, 200).Error
	})
}

func (s *SQLite) GetScan(ctx context.Context, id string) (core.ScanResult, error) {
	var row scanRow
	if err := s.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		return core.ScanResult{}, notFound(err)
	}
	sc, err := fromScanRow(row)
	if err != nil {
		return sc, err
	}
	sc.Findings, err = s.ListFindings(ctx, FindingFilter{ScanID: id})
	return sc, err
}

func (s *SQLite) ListScans(ctx context.Context, limit int) ([]core.ScanResult, error) {
	q := s.db.WithContext(ctx).Order("started_at DESC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []scanRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]core.ScanResult, 0, len(rows))
	for _, r := range rows {
		sc, err := fromScanRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, nil
}

func (s *SQLite) LatestScan(ctx context.Context, target string) (core.ScanResult, error) {
	var row scanRow
	err := s.db.WithContext(ctx).Where("target_name = ?", target).Order("started_at DESC").First(&row).Error
	if err != nil {
		return core.ScanResult{}, notFound(err)
	}
	return s.GetScan(ctx, row.ID)
}

func (s *SQLite) ListFindings(ctx context.Context, f FindingFilter) ([]core.Finding, error) {
	q := s.db.WithContext(ctx).Model(&findingRow{}).Order("id")
	if f.ScanID != "" {
		q = q.Where("scan_id = ?", f.ScanID)
	}
	if f.Severity != nil {
		q = q.Where("severity = ?", int(*f.Severity))
	}
	if f.Category != nil {
		q = q.Where("category = ?", int(*f.Category))
	}
	if f.Status != "" {
		q = q.Where("status = ?", string(f.Status))
	}
	if f.Fingerprint != "" {
		q = q.Where("fingerprint = ?", f.Fingerprint)
	}
	if f.Limit > 0 {
		q = q.Limit(f.Limit)
	}
	var rows []findingRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]core.Finding, 0, len(rows))
	for _, r := range rows {
		var fd core.Finding
		if err := json.Unmarshal([]byte(r.Data), &fd); err != nil {
			return nil, fmt.Errorf("decode finding %d: %w", r.ID, err)
		}
		out = append(out, fd)
	}
	return out, nil
}

func (s *SQLite) Prune(ctx context.Context, before time.Time) (int, error) {
	var removed int64
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		old := tx.Model(&scanRow{}).Select("id").Where("finished_at < ?", before)
		if err := tx.Where("scan_id IN (?)", old).Delete(&findingRow{}).Error; err != nil {
			return err
		}
		res := tx.Where("finished_at < ?", before).Delete(&scanRow{})
		removed = res.RowsAffected
		return res.Error
	})
	return int(removed), err
}

func (s *SQLite) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func toScanRow(sc core.ScanResult) (scanRow, error) {
	target, err := json.Marshal(sc.Target)
	if err != nil {
		return scanRow{}, err
	}
	skipped, err := json.Marshal(sc.Skipped)
	if err != nil {
		return scanRow{}, err
	}
	errs, err := json.Marshal(sc.Errors)
	if err != nil {
		return scanRow{}, err
	}
	assessed, err := json.Marshal(sc.Assessed)
	if err != nil {
		return scanRow{}, err
	}
	return scanRow{
		ID: sc.ID, TargetName: sc.Target.Name, Mode: int(sc.Mode),
		StartedAt: sc.StartedAt, FinishedAt: sc.FinishedAt, Score: sc.Score, Grade: sc.Grade,
		TargetJSON: string(target), SkippedJSON: string(skipped), ErrorsJSON: string(errs),
		AssessedJSON: string(assessed),
	}, nil
}

func fromScanRow(r scanRow) (core.ScanResult, error) {
	sc := core.ScanResult{
		ID: r.ID, Mode: core.Mode(r.Mode), StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		Score: r.Score, Grade: r.Grade,
	}
	for _, part := range []struct {
		raw string
		dst any
	}{{r.TargetJSON, &sc.Target}, {r.SkippedJSON, &sc.Skipped}, {r.ErrorsJSON, &sc.Errors}, {r.AssessedJSON, &sc.Assessed}} {
		if part.raw == "" || part.raw == "null" {
			continue
		}
		if err := json.Unmarshal([]byte(part.raw), part.dst); err != nil {
			return sc, fmt.Errorf("decode scan %s: %w", r.ID, err)
		}
	}
	return sc, nil
}

func notFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}
