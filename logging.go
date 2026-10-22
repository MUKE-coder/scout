package scout

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// NewLogger returns a structured logger. level is debug|info|warn|error and
// format is text|json.
func NewLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(strings.ToLower(level))); err != nil {
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lv}
	switch strings.ToLower(format) {
	case "", "text":
		return slog.New(slog.NewTextHandler(w, opts)).With("component", "scout"), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)).With("component", "scout"), nil
	}
	return nil, fmt.Errorf("invalid log format %q (want text or json)", format)
}
