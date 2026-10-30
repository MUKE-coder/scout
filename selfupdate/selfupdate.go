// Package selfupdate lets the scout binary upgrade itself from GitHub Releases:
// it finds the latest published version, and replaces the running executable with
// the matching release asset for this OS/arch. It is used by `scout update` and
// by the throttled auto-update check on startup.
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub repository releases are published to.
const Repo = "MUKE-coder/scout"

// Release is the subset of the GitHub release API we read.
type Release struct {
	Tag   string
	URL   string // browser_download_url of the asset for this OS/arch
	Asset string // asset file name
}

// httpClient is the client used for API and downloads; short timeout so a
// startup check never hangs a command.
var httpClient = &http.Client{Timeout: 20 * time.Second}

// Latest returns the latest published release and the download URL of its asset
// for the current OS/arch.
func Latest(ctx context.Context) (Release, error) {
	url := "https://api.github.com/repos/" + Repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("github releases API returned %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return Release{}, err
	}
	want := AssetName()
	for _, a := range rel.Assets {
		if a.Name == want {
			return Release{Tag: rel.TagName, URL: a.URL, Asset: a.Name}, nil
		}
	}
	return Release{Tag: rel.TagName}, fmt.Errorf("no release asset %q for %s/%s", want, runtime.GOOS, runtime.GOARCH)
}

// AssetName is the GoReleaser asset file name for this OS/arch.
func AssetName() string {
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("scout_%s_%s%s", runtime.GOOS, runtime.GOARCH, ext)
}

// Newer reports whether released (e.g. "v0.4.16" or "0.4.16") is a higher
// semantic version than current. A dev/unparseable current is never "older" of
// its own accord — callers guard dev builds separately — but Newer returns false
// when either side cannot be parsed, so a bad read never triggers an update.
func Newer(current, released string) bool {
	c, okc := parseVer(current)
	r, okr := parseVer(released)
	if !okc || !okr {
		return false
	}
	for i := 0; i < 3; i++ {
		if r[i] != c[i] {
			return r[i] > c[i]
		}
	}
	return false
}

func parseVer(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i] // drop pre-release/build metadata
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// Apply downloads the release asset and replaces the running executable with the
// scout binary inside it. It is safe while running: on Windows the current
// executable is renamed aside first (a running .exe cannot be overwritten, but it
// can be moved), then the new binary takes its place.
func Apply(ctx context.Context, rel Release) error {
	if rel.URL == "" {
		return fmt.Errorf("no download URL for %s", rel.Tag)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	bin, err := download(ctx, rel.URL)
	if err != nil {
		return err
	}
	newBin, err := extractBinary(bin)
	if err != nil {
		return err
	}
	return replace(exe, newBin)
}

// replace swaps the executable at path for newBin, safely while running. On
// Windows the current file is renamed aside first (a running .exe cannot be
// overwritten, only moved); elsewhere the temp file is renamed over it.
func replace(exe string, newBin []byte) error {
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".scout-update-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(newBin); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	_ = tmp.Close()
	if err := os.Chmod(tmpName, 0o755); err != nil { // #nosec G302 -- an executable must be 0755
		_ = os.Remove(tmpName)
		return err
	}

	if runtime.GOOS == "windows" {
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			_ = os.Remove(tmpName)
			return err
		}
		if err := os.Rename(tmpName, exe); err != nil {
			_ = os.Rename(old, exe) // roll back
			return err
		}
		return nil
	}
	if err := os.Rename(tmpName, exe); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s returned %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 100<<20)) // 100 MiB cap
}

// extractBinary pulls the scout executable out of a .zip (Windows) or .tar.gz.
func extractBinary(archive []byte) ([]byte, error) {
	name := "scout"
	if runtime.GOOS == "windows" {
		name = "scout.exe"
	}
	if runtime.GOOS == "windows" {
		return fromZip(archive, name)
	}
	return fromTarGz(archive, name)
}

func fromZip(archive []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == name {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, 200<<20))
		}
	}
	return nil, fmt.Errorf("%s not found in archive", name)
}

func fromTarGz(archive []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(h.Name) == name {
			return io.ReadAll(io.LimitReader(tr, 200<<20))
		}
	}
	return nil, fmt.Errorf("%s not found in archive", name)
}
