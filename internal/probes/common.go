package probes

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

func init() {
	Register(fileContentProbe{})
	Register(fileRegexProbe{})
	Register(fileKVProbe{})
}

const maxReadBytes = 4 << 20 // 4 MiB por fichero

// cmdResult es la salida de un comando del sistema.
type cmdResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// runCmd ejecuta un comando fijo (nunca definido por una regla) con timeout.
// Un código de salida distinto de 0 no se trata como error: muchos comandos
// (systemctl is-enabled, rpm -q) lo usan para informar de estado.
func runCmd(ctx context.Context, name string, args ...string) (cmdResult, error) {
	return runCmdEnv(ctx, nil, name, args...)
}

// PSEnviron es el entorno de este proceso sin PSModulePath, más extra.
//
// Windows PowerShell 5.1 lanzado desde PowerShell 7 (la terminal por defecto
// de Windows Terminal, o «shell: pwsh» en el CI) hereda su PSModulePath, que
// apunta primero a los módulos de PowerShell 7: entonces no puede cargar los
// suyos y Get-AuthenticodeSignature (módulo Microsoft.PowerShell.Security)
// falla. Sin la variable, la reconstruye con sus rutas por defecto.
func PSEnviron(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, "PSModulePath") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// runCmdEnv es runCmd con variables de entorno adicionales: así llegan los
// datos a un script sin formar parte de él.
func runCmdEnv(ctx context.Context, env []string, name string, args ...string) (cmdResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(PSEnviron("LC_ALL=C", "LANG=C"), env...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := cmdResult{Stdout: out.String(), Stderr: errb.String()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("%s: %w", name, err)
	}
	return res, nil
}

// readFileLimited lee un fichero con un límite de tamaño: falla solo si
// tiene MÁS de maxReadBytes (uno de exactamente ese tamaño se lee entero).
func readFileLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLimited(f, maxReadBytes)
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return b, err
	}
	if int64(len(b)) > max {
		return b[:max], errors.New("fichero demasiado grande")
	}
	return b, nil
}

// decodeText convierte el contenido de un FICHERO a string: UTF-16 con BOM
// (el INF de secedit), UTF-8 o, si no es UTF-8 válido, la página de códigos
// ANSI del sistema (Windows-1252 en español).
func decodeText(b []byte) string { return decodeWith(b, decodeLegacy) }

// decodeConsole convierte la SALIDA de una herramienta de consola (netstat,
// tasklist, auditpol /get…). No usan la página ANSI sino la de la consola,
// que por defecto es la OEM (850 en español): «Dirección» llega con 0xA2
// («ó» en CP850), que en Windows-1252 se leería «Direcci¢n».
func decodeConsole(b []byte) string { return decodeWith(b, decodeOEM) }

func decodeWith(b []byte, legacy func([]byte) string) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		return decodeUTF16(b[2:], false)
	}
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		return decodeUTF16(b[2:], true)
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(b) {
		return legacy(b)
	}
	return string(b)
}

// latin1 interpreta cada byte como un carácter Latin-1.
func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// decodeLegacy convierte el texto de 8 bits de un fichero. En Windows usa
// la página de códigos ANSI del sistema; en el resto, Latin-1.
var decodeLegacy = latin1

// decodeOEM convierte la salida de 8 bits de una herramienta de consola. En
// Windows usa la página de códigos de la consola (u OEM); en el resto,
// Latin-1.
var decodeOEM = latin1

// DecodeText convierte el contenido de un fichero a UTF-8 (UTF-16 con BOM,
// UTF-8 o la página de códigos ANSI).
func DecodeText(b []byte) string { return decodeText(b) }

// DecodeConsole convierte la salida de una herramienta de consola de
// Windows a UTF-8 (UTF-16 con BOM, UTF-8 o la página de códigos OEM).
func DecodeConsole(b []byte) string { return decodeConsole(b) }

func decodeUTF16(b []byte, bigEndian bool) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			u = append(u, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	return string(utf16.Decode(u))
}

// expandPaths expande globs y devuelve los ficheros existentes en orden.
func expandPaths(patterns []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil || len(matches) == 0 {
			matches = []string{pat}
		}
		sort.Strings(matches)
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && st.Mode().IsRegular() && !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

func isComment(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";")
}

// --- file_content: contenido completo de un fichero pequeño (/sys, /proc) ---

type fileContentProbe struct{}

func (fileContentProbe) Name() string         { return "file_content" }
func (fileContentProbe) DefaultField() string { return "value" }

func (fileContentProbe) Collect(_ context.Context, p Params) (Observation, error) {
	if err := p.Require("path"); err != nil {
		return Observation{}, err
	}
	path := p.String("path")
	b, err := readFileLimited(path)
	if errors.Is(err, os.ErrNotExist) {
		return Observation{Found: false, Source: path}, nil
	}
	if err != nil {
		return Observation{}, permissionErr(err, path)
	}
	return Observation{Found: true, Source: path, Fields: map[string]any{
		"value": strings.TrimSpace(decodeText(b)),
	}}, nil
}

// --- file_regex: cuenta líneas que coinciden con una expresión regular ---

type fileRegexProbe struct{}

func (fileRegexProbe) Name() string         { return "file_regex" }
func (fileRegexProbe) DefaultField() string { return "count" }

func (fileRegexProbe) Collect(_ context.Context, p Params) (Observation, error) {
	if err := p.Require("path", "pattern"); err != nil {
		return Observation{}, err
	}
	re, err := regexp.Compile(p.String("pattern"))
	if err != nil {
		return Observation{}, fmt.Errorf("pattern inválido: %w", err)
	}
	skipComments := p.Bool("ignore_comments", true)
	files := expandPaths(p.Strings("path"))
	src := strings.Join(p.Strings("path"), ", ")
	if len(files) == 0 {
		return Observation{Found: false, Source: src}, nil
	}
	count := 0
	var matches []string
	for _, f := range files {
		b, err := readFileLimited(f)
		if err != nil {
			return Observation{}, permissionErr(err, f)
		}
		sc := bufio.NewScanner(strings.NewReader(decodeText(b)))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		n := 0
		for sc.Scan() {
			n++
			line := sc.Text()
			if skipComments && isComment(line) {
				continue
			}
			if re.MatchString(line) {
				count++
				if len(matches) < 10 {
					matches = append(matches, fmt.Sprintf("%s:%d: %s", f, n, truncate(strings.TrimSpace(line), 160)))
				}
			}
		}
	}
	return Observation{Found: true, Source: src, Fields: map[string]any{
		"count":   count,
		"matches": matches,
		"files":   len(files),
	}}, nil
}

// --- file_kv: valor de una clave en ficheros clave/valor (login.defs, ini) ---

type fileKVProbe struct{}

func (fileKVProbe) Name() string         { return "file_kv" }
func (fileKVProbe) DefaultField() string { return "value" }

func (fileKVProbe) Collect(_ context.Context, p Params) (Observation, error) {
	if err := p.Require("path", "key"); err != nil {
		return Observation{}, err
	}
	files := expandPaths(p.Strings("path"))
	src := strings.Join(p.Strings("path"), ", ")
	if len(files) == 0 {
		return Observation{Found: false, Source: src}, nil
	}
	key := p.String("key")
	sep := p.String("separator")
	ci := p.Bool("case_insensitive", false)
	var value, from string
	found := false
	for _, f := range files {
		b, err := readFileLimited(f)
		if err != nil {
			return Observation{}, permissionErr(err, f)
		}
		if v, ok := parseKV(decodeText(b), key, sep, ci); ok {
			value, from, found = v, f, true // gana la última aparición (semántica systemd)
		}
	}
	if !found {
		return Observation{Found: false, Source: src}, nil
	}
	return Observation{Found: true, Source: from, Fields: map[string]any{"value": value, "file": from}}, nil
}

// parseKV busca key en un texto "clave valor" o "clave=valor". Devuelve la
// última aparición. Ignora comentarios y cabeceras de sección [x].
func parseKV(text, key, sep string, ci bool) (string, bool) {
	var value string
	found := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || isComment(line) || strings.HasPrefix(line, "[") {
			continue
		}
		var k, v string
		if sep == "" {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			k = fields[0]
			v = strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
		} else {
			i := strings.Index(line, sep)
			if i < 0 {
				continue
			}
			k, v = strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+len(sep):])
		}
		if k == key || (ci && strings.EqualFold(k, key)) {
			value, found = strings.Trim(v, `"'`), true
		}
	}
	return value, found
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
