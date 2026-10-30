package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, rel string
		want     bool
	}{
		{"0.4.15", "0.4.16", true},
		{"0.4.15", "v0.5.0", true},
		{"v0.4.15", "0.4.15", false},
		{"0.4.16", "0.4.15", false},
		{"1.0.0", "0.9.9", false},
		{"0.9.9", "1.0.0", true},
		{"0.0.0-dev", "0.4.16", true}, // dev parses as 0.0.0; the auto-update dev guard lives in the CLI, not here
		{"0.4.15", "garbage", false},
		{"0.4.15", "0.4.16-rc1", true}, // pre-release suffix stripped
	}
	for _, c := range cases {
		if got := Newer(c.cur, c.rel); got != c.want {
			t.Errorf("Newer(%q,%q)=%v, want %v", c.cur, c.rel, got, c.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	name := AssetName()
	if !bytes.HasPrefix([]byte(name), []byte("scout_"+runtime.GOOS+"_"+runtime.GOARCH)) {
		t.Errorf("asset name = %q", name)
	}
	if runtime.GOOS == "windows" && filepath.Ext(name) != ".zip" {
		t.Errorf("windows asset should be .zip: %q", name)
	}
}

func TestExtractBinary(t *testing.T) {
	want := []byte("#!/fake scout binary\x00\x01")
	var archive []byte
	binName := "scout"
	if runtime.GOOS == "windows" {
		binName = "scout.exe"
	}
	if runtime.GOOS == "windows" {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, _ := zw.Create(binName)
		_, _ = w.Write(want)
		// a decoy file that must be ignored
		d, _ := zw.Create("README.md")
		_, _ = d.Write([]byte("hi"))
		zw.Close()
		archive = buf.Bytes()
	} else {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		_ = tw.WriteHeader(&tar.Header{Name: "README.md", Size: 2, Mode: 0o644})
		_, _ = tw.Write([]byte("hi"))
		_ = tw.WriteHeader(&tar.Header{Name: binName, Size: int64(len(want)), Mode: 0o755})
		_, _ = tw.Write(want)
		tw.Close()
		gz.Close()
		archive = buf.Bytes()
	}
	got, err := extractBinary(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("extracted %q, want %q", got, want)
	}
}

func TestReplace(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "scout")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	if err := os.WriteFile(exe, []byte("OLD"), 0o755); err != nil { // #nosec G306
		t.Fatal(err)
	}
	newBin := []byte("NEWBINARY")
	if err := replace(exe, newBin); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(exe) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newBin) {
		t.Errorf("after replace, exe = %q, want %q", got, newBin)
	}
}
