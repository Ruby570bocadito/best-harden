// Package selfupdate actualiza el binario de Adarve desde las releases de
// GitHub (o un espejo interno) verificando la firma de checksums.txt y la
// suma SHA-256 del archivo.
//
// Contrato de releases (lo cumple GitHub y cualquier espejo estático):
//
//	<base>/latest/download/version.txt         → etiqueta de la última versión
//	<base>/download/<tag>/checksums.txt        → sumas SHA-256
//	<base>/download/<tag>/checksums.txt.sig    → su firma (ver signature.go)
//	<base>/download/<tag>/adarve_<os>_<arch>.tar.gz | .zip
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/version"
)

const maxDownload = 200 << 20 // 200 MiB

// Source indica de dónde se descargan las releases.
type Source struct {
	Repo    string // owner/nombre en GitHub
	BaseURL string // espejo opcional; por defecto https://github.com/<repo>/releases
	// Unsigned acepta una release sin checksums.txt.sig (las anteriores a
	// la firma). Una firma presente e inválida se rechaza siempre.
	Unsigned bool
}

// Validate comprueba el origen antes de descargar nada: el repositorio
// debe tener la forma owner/nombre y el espejo debe usar HTTPS (HTTP solo
// hacia el propio equipo, para pruebas). Las sumas SHA-256 viajan por el
// mismo canal que los binarios: sin TLS no protegerían de nada.
func (s Source) Validate() error {
	if s.BaseURL == "" {
		if !reRepo.MatchString(s.Repo) {
			return fmt.Errorf("repositorio %q no válido (formato owner/nombre)", s.Repo)
		}
		return nil
	}
	return CheckURL(s.BaseURL)
}

var reRepo = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// CheckURL exige HTTPS, o HTTP solo hacia el propio equipo.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("dirección de releases no válida: %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if loopback(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("la dirección de releases debe usar https:// (%s): sin TLS, quien intercepte la conexión podría servir un binario y sus sumas", raw)
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Base devuelve la URL base de releases.
func (s Source) Base() string {
	if s.BaseURL != "" {
		return strings.TrimRight(s.BaseURL, "/")
	}
	return "https://github.com/" + s.Repo + "/releases"
}

// client sigue las redirecciones de GitHub (a su CDN) pero nunca hacia
// HTTP: una redirección no puede rebajar la conexión.
var client = &http.Client{
	Timeout: 5 * time.Minute,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("demasiadas redirecciones")
		}
		return CheckURL(req.URL.String())
	},
}

func get(ctx context.Context, url string, w io.Writer, limit int64) error {
	if err := CheckURL(url); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "adarve/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &statusError{url: url, status: resp.Status, code: resp.StatusCode}
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("GET %s: respuesta demasiado grande", url)
	}
	return nil
}

type statusError struct {
	url, status string
	code        int
}

func (e *statusError) Error() string { return fmt.Sprintf("GET %s: %s", e.url, e.status) }

// IsNotFound indica que el servidor de releases respondió 404.
func IsNotFound(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == http.StatusNotFound
}

// Published comprueba que la release tag está publicada (su checksums.txt
// existe). GitHub tarda unos minutos en publicarla tras crear la etiqueta.
func (s Source) Published(ctx context.Context, tag string) error {
	return get(ctx, fmt.Sprintf("%s/download/%s/checksums.txt", s.Base(), tag), io.Discard, 1<<20)
}

// Latest devuelve la etiqueta de la última versión publicada.
func (s Source) Latest(ctx context.Context) (string, error) {
	var b strings.Builder
	if err := get(ctx, s.Base()+"/latest/download/version.txt", &b, 256); err != nil {
		return "", err
	}
	tag := strings.TrimSpace(b.String())
	if !ValidTag(tag) {
		return "", fmt.Errorf("version.txt inválido: %q", tag)
	}
	return tag, nil
}

// AssetName es el nombre del archivo de release para una plataforma.
func AssetName(goos, goarch string) string {
	if goos == "windows" {
		return fmt.Sprintf("adarve_%s_%s.zip", goos, goarch)
	}
	return fmt.Sprintf("adarve_%s_%s.tar.gz", goos, goarch)
}

// Download descarga y verifica la release tag y devuelve la ruta del binario
// extraído en un directorio temporal (que el llamador debe borrar). signed
// indica si checksums.txt venía firmado (solo puede ser false con Unsigned).
func (s Source) Download(ctx context.Context, tag string) (binPath, tmpDir string, signed bool, err error) {
	if !ValidTag(tag) {
		return "", "", false, fmt.Errorf("versión %q no válida", tag)
	}
	asset := AssetName(runtime.GOOS, runtime.GOARCH)
	tmpDir, err = os.MkdirTemp("", "adarve-update-")
	if err != nil {
		return "", "", false, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(tmpDir)
			tmpDir = ""
		}
	}()

	var sums, sig bytes.Buffer
	if err = get(ctx, fmt.Sprintf("%s/download/%s/checksums.txt", s.Base(), tag), &sums, 1<<20); err != nil {
		return "", "", false, err
	}
	// La firma se comprueba antes de creer ninguna suma.
	switch serr := get(ctx, fmt.Sprintf("%s/download/%s/checksums.txt.sig", s.Base(), tag), &sig, 1<<10); {
	case IsNotFound(serr) && s.Unsigned:
	case IsNotFound(serr):
		return "", "", false, fmt.Errorf("%w: para instalar igualmente una versión sin firma, usa --insecure", ErrUnsigned)
	case serr != nil:
		return "", "", false, serr
	default:
		if err = VerifyChecksums(sums.Bytes(), sig.Bytes()); err != nil {
			return "", "", false, err
		}
		signed = true
	}
	want, ok := ParseChecksums(sums.String())[asset]
	if !ok {
		return "", "", false, fmt.Errorf("checksums.txt no contiene %s", asset)
	}

	archive := filepath.Join(tmpDir, asset)
	f, err := os.Create(archive)
	if err != nil {
		return "", "", false, err
	}
	h := sha256.New()
	err = get(ctx, fmt.Sprintf("%s/download/%s/%s", s.Base(), tag, asset), io.MultiWriter(f, h), maxDownload)
	f.Close()
	if err != nil {
		return "", "", false, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, want) {
		return "", "", false, fmt.Errorf("la suma SHA-256 no coincide (esperada %s, obtenida %s): descarga abortada", want, got)
	}

	exe := "adarve"
	if runtime.GOOS == "windows" {
		exe = "adarve.exe"
	}
	binPath = filepath.Join(tmpDir, exe+".new")
	if strings.HasSuffix(asset, ".zip") {
		err = extractZip(archive, exe, binPath)
	} else {
		err = extractTarGz(archive, exe, binPath)
	}
	return binPath, tmpDir, signed, err
}

// ParseChecksums interpreta un checksums.txt ("<sha256>  <fichero>").
func ParseChecksums(text string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && len(f[0]) == 64 {
			out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return out
}

func extractTarGz(archive, name, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("el archivo no contiene %s", name)
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == name {
			return writeExec(dst, io.LimitReader(tr, maxDownload))
		}
	}
}

func extractZip(archive, name, dst string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if filepath.Base(f.Name) == name && !f.FileInfo().IsDir() {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			return writeExec(dst, io.LimitReader(rc, maxDownload))
		}
	}
	return fmt.Errorf("el archivo no contiene %s", name)
}

func writeExec(dst string, r io.Reader) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Apply sustituye el ejecutable actual por newBin.
// En Linux el reemplazo es atómico (rename). En Windows un ejecutable en uso
// no se puede sobrescribir pero sí renombrar: se mueve a .old y se borra en
// el siguiente arranque (CleanupOld).
func Apply(newBin string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	staged := filepath.Join(dir, "."+filepath.Base(exe)+".new")
	if err := copyFile(newBin, staged); err != nil {
		return fmt.Errorf("no se pudo escribir en %s (¿permisos de administrador?): %w", dir, err)
	}
	if runtime.GOOS == "windows" {
		old := exe + ".old"
		os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			os.Remove(staged)
			return err
		}
		if err := os.Rename(staged, exe); err != nil {
			os.Rename(old, exe) // deshacer
			return err
		}
		return nil
	}
	return os.Rename(staged, exe)
}

// InstallDirWritable comprueba si se puede escribir junto al ejecutable
// actual (lo que necesita Apply). Devuelve el directorio y el error.
func InstallDirWritable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	f, err := os.CreateTemp(dir, ".adarve-write-test-*")
	if err != nil {
		return dir, err
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return dir, nil
}

// CleanupOld elimina el ejecutable anterior que deja Apply en Windows.
func CleanupOld() {
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe + ".old")
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeExec(dst, in)
}

// Newer indica si latest es una versión posterior a current. Las versiones
// de desarrollo ("dev") nunca se consideran anteriores.
func Newer(latest, current string) bool {
	l, okL := parseSemver(latest)
	c, okC := parseSemver(current)
	if !okL || !okC {
		return false
	}
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	// Misma versión: una final es posterior a una pre-release.
	return l[3] == 0 && c[3] == 1
}

// parseSemver devuelve [mayor, menor, parche, esPrerelease].
func parseSemver(v string) ([4]int, bool) {
	var out [4]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		if v[i] == '-' {
			out[3] = 1
		}
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

var reTag = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// ValidTag indica si tag es una etiqueta de versión (v1.2.3 o v1.2.3-rc.1).
// La etiqueta forma parte de las URLs de descarga: nada más se admite.
func ValidTag(tag string) bool { return reTag.MatchString(tag) }

// IsRelease indica si v es una versión publicada (semver) y no una
// compilación de desarrollo ("dev", "dev-abc1234"…).
func IsRelease(v string) bool {
	_, ok := parseSemver(v)
	return ok
}

// Compare devuelve -1, 0 o 1 según a sea anterior, igual o posterior a b
// (las pre-releases son anteriores a la final). ok es false si alguna no es
// una versión.
func Compare(a, b string) (c int, ok bool) {
	switch {
	case !IsRelease(a) || !IsRelease(b):
		return 0, false
	case Newer(a, b):
		return 1, true
	case Newer(b, a):
		return -1, true
	}
	return 0, true
}
