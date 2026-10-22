// Package repo is a shared helper for collectors that read a target's source
// tree (Target.Repo). It walks text files while skipping version control,
// dependency and build directories, binary files, and anything too large, so
// code collectors see source without drowning in vendored or generated files.
package repo

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// MaxFileSize caps how large a file the walker will read (1 MiB).
const MaxFileSize = 1 << 20

// skipDirs are never descended into.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".next": true, "target": true, ".venv": true,
	"__pycache__": true, ".idea": true, ".vscode": true, "coverage": true,
}

// File is one text file from the tree.
type File struct {
	Abs  string // absolute path
	Rel  string // path relative to the repo root (forward slashes)
	Data []byte
}

// Walk calls fn for each eligible text file under root. A per-file read or
// callback error is returned; walking otherwise continues.
func Walk(root string, fn func(File) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, don't abort the walk
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > MaxFileSize {
			return nil
		}
		// #nosec G304 G122 -- reading a user-supplied repo tree is the point; symlink TOCTOU is not a concern for a local read-only scan
		data, err := os.ReadFile(path)
		if err != nil || isBinary(data) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		return fn(File{Abs: path, Rel: filepath.ToSlash(rel), Data: data})
	})
}

// isBinary reports whether data looks non-text (contains a NUL byte in the
// first 8 KiB).
func isBinary(data []byte) bool {
	n := len(data)
	if n > 8192 {
		n = 8192
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}

// Base returns the repo root for a target path, defaulting "." to the cwd.
func Base(repo string) string {
	if repo == "" {
		return ""
	}
	if abs, err := filepath.Abs(repo); err == nil {
		return abs
	}
	return repo
}

// Lines splits file data into lines for line-number reporting.
func Lines(data []byte) []string {
	return strings.Split(string(data), "\n")
}
