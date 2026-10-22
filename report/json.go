package report

import (
	"encoding/json"
	"io"
)

// Document is the --json output: one entry per scanned target.
type Document struct {
	Tool    string   `json:"tool"`
	Version string   `json:"version"`
	Results []Result `json:"results"`
}

// JSON writes results as an indented JSON document.
func JSON(w io.Writer, version string, results []Result) error {
	if results == nil {
		results = []Result{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Document{Tool: "scout", Version: version, Results: results})
}
