package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
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
	var buf bytes.Buffer
	payload := []byte("#!/bin/sh\necho adarve\n")
	if runtime.GOOS == "windows" {
		zw := zip.NewWriter(&buf)
		f, _ := zw.Create("adarve.exe")
		f.Write(payload)
		zw.Close()
	} else {
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		tw.WriteHeader(&tar.Header{Name: "adarve", Mode: 0o755, Size: int64(len(payload)), Typeflag: tar.TypeReg})
		tw.Write(payload)
		tw.Close()
		gz.Close()
	}
	archive := buf.Bytes()
	sum := sha256.Sum256(archive)
	asset := AssetName(runtime.GOOS, runtime.GOARCH)
	sums := []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), asset))
	key := useTestKey(t)
	sig := signSums(t, key, sums)

	corrupt, unsigned, badSig := false, false, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/download/version.txt":
			fmt.Fprintln(w, "v9.9.9")
		case "/download/v9.9.9/checksums.txt":
			w.Write(sums)
		case "/download/v9.9.9/checksums.txt.sig":
			switch {
			case unsigned:
				http.NotFound(w, r)
			case badSig:
				w.Write(signSums(t, key, []byte("otras sumas")))
			default:
				w.Write(sig)
			}
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
	bin, dir, signed, err := s.Download(context.Background(), tag)
	if err != nil || !signed {
		t.Fatalf("Download: %v (firmada: %v)", err, signed)
	}
	defer os.RemoveAll(dir)
	got, _ := os.ReadFile(bin)
	if !bytes.Equal(got, payload) {
		t.Error("binario extraído distinto")
	}

	corrupt = true
	if _, _, _, err := s.Download(context.Background(), tag); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("un archivo manipulado debe rechazarse, err = %v", err)
	}
	corrupt = false

	// Sin firma: se rechaza salvo con Unsigned (--insecure).
	unsigned = true
	if _, _, _, err := s.Download(context.Background(), tag); !errors.Is(err, ErrUnsigned) {
		t.Errorf("una release sin firma debe rechazarse, err = %v", err)
	}
	insecure := Source{BaseURL: srv.URL, Unsigned: true}
	if _, dir, signed, err := insecure.Download(context.Background(), tag); err != nil || signed {
		t.Errorf("con Unsigned, una release sin firma se acepta como no firmada: %v %v", signed, err)
	} else {
		os.RemoveAll(dir)
	}
	unsigned = false

	// Una firma inválida se rechaza siempre, también con Unsigned.
	badSig = true
	if _, _, _, err := insecure.Download(context.Background(), tag); err == nil || !strings.Contains(err.Error(), "firma") {
		t.Errorf("una firma inválida debe rechazarse, err = %v", err)
	}
	badSig = false

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

// useTestKey sustituye la clave de las releases por una de prueba.
func useTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	old := releaseKeysPEM
	releaseKeysPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	t.Cleanup(func() { releaseKeysPEM = old })
	return k
}

// signSums firma como lo hace el workflow de release
// (openssl dgst -sha256 -sign: ECDSA sobre SHA-256, DER).
func signSums(t *testing.T, k *ecdsa.PrivateKey, sums []byte) []byte {
	t.Helper()
	h := sha256.Sum256(sums)
	sig, err := ecdsa.SignASN1(rand.Reader, k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestVerifyChecksums(t *testing.T) {
	k := useTestKey(t)
	sums := []byte("abc  adarve_linux_amd64.tar.gz\n")
	if err := VerifyChecksums(sums, signSums(t, k, sums)); err != nil {
		t.Errorf("firma válida rechazada: %v", err)
	}
	if err := VerifyChecksums(append(sums, ' '), signSums(t, k, sums)); err == nil {
		t.Error("sumas manipuladas aceptadas")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := VerifyChecksums(sums, signSums(t, other, sums)); err == nil {
		t.Error("firma de otra clave aceptada")
	}
}

// La clave incrustada es válida y es la misma que llevan los instaladores.
func TestReleaseKeyEverywhere(t *testing.T) {
	keys, err := releaseKeys()
	if err != nil || len(keys) == 0 {
		t.Fatalf("clave incrustada: %v", err)
	}
	k := keys[0]
	sh, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sh, bytes.TrimSpace(releaseKeysPEM)) {
		t.Error("install.sh no lleva la clave pública de internal/selfupdate/release-signing.pub")
	}
	ps, err := os.ReadFile("../../scripts/install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string][]byte{"X": k.X.FillBytes(make([]byte, 32)), "Y": k.Y.FillBytes(make([]byte, 32))} {
		if !bytes.Contains(ps, []byte(base64.StdEncoding.EncodeToString(v))) {
			t.Errorf("install.ps1 no lleva la coordenada %s de la clave pública", name)
		}
	}
}

// Una firma hecha por openssl con la clave real de las releases (la que usa
// el workflow) se verifica con la clave incrustada.
func TestOpenSSLSignature(t *testing.T) {
	sums, err := os.ReadFile("testdata/checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile("testdata/checksums.txt.sig")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChecksums(sums, sig); err != nil {
		t.Errorf("firma de openssl rechazada: %v", err)
	}
	if err := VerifyChecksums(bytes.Replace(sums, []byte("abc123"), []byte("abc124"), 1), sig); err == nil {
		t.Error("sumas manipuladas aceptadas")
	}
}
