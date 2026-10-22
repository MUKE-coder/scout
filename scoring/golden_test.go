package scoring

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

var update = flag.Bool("update", false, "rewrite scoring golden files")

type fixture struct {
	Findings    []core.Finding    `json:"findings"`
	Criticality []CriticalityRule `json:"criticality,omitempty"`
	Assessed    []core.Category   `json:"assessed,omitempty"`
}

type golden struct {
	Report  Report    `json:"report"`
	FixNext []FixItem `json:"fix_next"`
}

// TestGolden pins scores for known finding sets. After an intended scoring
// change, run: go test ./scoring -run TestGolden -update
func TestGolden(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("testdata", "*.findings.json"))
	if err != nil || len(inputs) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, in := range inputs {
		name := strings.TrimSuffix(filepath.Base(in), ".findings.json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			var fx fixture
			if err := json.Unmarshal(raw, &fx); err != nil {
				t.Fatal(err)
			}
			opts := Options{Criticality: fx.Criticality, Assessed: fx.Assessed}
			got, err := json.MarshalIndent(golden{Report: Score(fx.Findings, opts), FixNext: FixNext(fx.Findings, opts)}, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')

			path := filepath.Join("testdata", name+".golden.json")
			if *update {
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden file (run with -update): %v", err)
			}
			if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
				t.Errorf("score changed for %s.\n--- want\n%s\n--- got\n%s", name, want, got)
			}
		})
	}
}
