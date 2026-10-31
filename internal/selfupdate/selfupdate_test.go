package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v0.2.0", "0.1.9", true},
		{"v1.0.0", "v1.0.0", false},
		{"v1.0.0", "v1.0.0-rc1", true},
		{"v1.0.0-rc1", "v1.0.0", false},
		{"v0.9.9", "v1.0.0", false},
		{"v1.0.0", "dev", false},
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.latest, c.current, got)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	sum := strings.Repeat("a", 64)
	m := ParseChecksums(sum + "  adarve_linux_amd64.tar.gz\nbasura\n")
	if m["adarve_linux_amd64.tar.gz"] != sum || len(m) != 1 {
		t.Errorf("checksums: %v", m)
	}
}

// TestDownloadVerifiesChecksum simula un espejo de releases.
func TestDownloadVerifiesChecksum(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("el archivo de prueba es tar.gz")
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	payload := []byte("#!/bin/sh\necho adarve\n")
	tw.WriteHeader(&tar.Header{Name: "adarve", Mode: 0o755, Size: int64(len(payload)), Typeflag: tar.TypeReg})
	tw.Write(payload)
	tw.Close()
	gz.Close()
	archive := buf.Bytes()
	sum := sha256.Sum256(archive)
	asset := AssetName(runtime.GOOS, runtime.GOARCH)

	corrupt := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/download/version.txt":
			fmt.Fprintln(w, "v9.9.9")
		case "/download/v9.9.9/checksums.txt":
			fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		case "/download/v9.9.9/" + asset:
			if corrupt {
				w.Write(append([]byte{0}, archive...))
				return
			}
			w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := Source{BaseURL: srv.URL}
	tag, err := s.Latest(context.Background())
	if err != nil || tag != "v9.9.9" {
		t.Fatalf("Latest = %q, %v", tag, err)
	}
	bin, dir, err := s.Download(context.Background(), tag)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer os.RemoveAll(dir)
	got, _ := os.ReadFile(bin)
	if !bytes.Equal(got, payload) {
		t.Error("binario extraído distinto")
	}

	corrupt = true
	if _, _, err := s.Download(context.Background(), tag); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("un archivo manipulado debe rechazarse, err = %v", err)
	}

	if err := s.Published(context.Background(), "v9.9.9"); err != nil {
		t.Errorf("v9.9.9 está publicada: %v", err)
	}
	if err := s.Published(context.Background(), "v9.9.10"); !IsNotFound(err) {
		t.Errorf("una versión sin publicar debe dar 404: %v", err)
	}
}

func TestSourceValidate(t *testing.T) {
	for _, s := range []Source{
		{Repo: "Ruby570bocadito/adarve"},
		{BaseURL: "https://mirror.interno/adarve/releases"},
		{BaseURL: "http://127.0.0.1:8765"},
		{BaseURL: "http://localhost:8765/"},
	} {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	for _, s := range []Source{
		{Repo: "nada"},
		{Repo: "a/b/c"},
		{BaseURL: "http://mirror.interno/releases"},
		{BaseURL: "http://192.168.1.5/releases"},
		{BaseURL: "ftp://mirror/releases"},
		{BaseURL: "mirror/releases"},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%+v debería rechazarse", s)
		}
	}
	if err := get(context.Background(), "http://example.com/x", &bytes.Buffer{}, 10); err == nil {
		t.Error("get no debe descargar por HTTP fuera del propio equipo")
	}
}

func TestTagsAndCompare(t *testing.T) {
	for _, tag := range []string{"v1.2.3", "1.2.3", "v1.2.3-rc.1"} {
		if !ValidTag(tag) {
			t.Errorf("%s es válida", tag)
		}
	}
	for _, tag := range []string{"", "v1.2", "../v1.2.3", "v1.2.3?x", "v1.2.3/../x", "latest"} {
		if ValidTag(tag) {
			t.Errorf("%q no es válida", tag)
		}
	}
	if IsRelease("dev") || !IsRelease("v0.3.1") {
		t.Error("IsRelease")
	}
	for _, c := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v0.3.2", "v0.3.1", 1, true},
		{"v0.3.0", "v0.3.1", -1, true},
		{"0.3.1", "v0.3.1", 0, true},
		{"v0.3.1", "dev", 0, false},
	} {
		if got, ok := Compare(c.a, c.b); got != c.want || ok != c.ok {
			t.Errorf("Compare(%s, %s) = %d, %v", c.a, c.b, got, ok)
		}
	}
}
