// Package probes contiene los recolectores de solo lectura que obtienen el
// estado real del sistema (registro, sysctl, ficheros, servicios...).
//
// Principio de diseño: los probes NUNCA modifican el sistema y NUNCA ejecutan
// comandos definidos por una regla. Los comandos que usan están fijados en el
// código, de modo que un paquete de reglas no puede inyectar ejecución.
package probes

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Observation es lo que un probe ha observado en el sistema.
type Observation struct {
	// Found es false cuando el objeto consultado no existe (clave de registro,
	// fichero, unidad systemd...). El motor aplica entonces default/on_missing.
	Found  bool
	Fields map[string]any
	// Source describe de dónde sale el dato, para la evidencia del informe.
	Source string
}

// Probe es un recolector de solo lectura.
type Probe interface {
	Name() string
	DefaultField() string
	Collect(ctx context.Context, p Params) (Observation, error)
}

// NotApplicableError indica que el control no aplica en este equipo
// (p. ej. no hay servidor SSH instalado o no se usa systemd).
type NotApplicableError struct{ Reason string }

func (e *NotApplicableError) Error() string { return e.Reason }

// NotApplicable crea un NotApplicableError.
func NotApplicable(format string, a ...any) error {
	return &NotApplicableError{Reason: fmt.Sprintf(format, a...)}
}

// AsNotApplicable devuelve el motivo si err es un NotApplicableError.
func AsNotApplicable(err error) (string, bool) {
	var na *NotApplicableError
	if errors.As(err, &na) {
		return na.Reason, true
	}
	return "", false
}

// PrivilegeError indica que el dato solo se puede leer con privilegios de
// administrador (Windows) o root (Linux). El motor lo muestra como "sin
// evaluar" en lugar de como error: no es un fallo del control ni de Adarve.
type PrivilegeError struct{ Reason string }

func (e *PrivilegeError) Error() string { return e.Reason }

// NeedsPrivilege crea un PrivilegeError.
func NeedsPrivilege(format string, a ...any) error {
	return &PrivilegeError{Reason: fmt.Sprintf(format, a...)}
}

// AsPrivilege devuelve el motivo si err se debe a la falta de privilegios:
// un PrivilegeError o un "permiso denegado" cuando el proceso no está
// elevado. Con privilegios, un permiso denegado (p. ej. por SELinux) es un
// error real y se informa como tal.
func AsPrivilege(err error) (string, bool) {
	var pe *PrivilegeError
	if errors.As(err, &pe) {
		return pe.Reason, true
	}
	if errors.Is(err, fs.ErrPermission) && !Privileged() {
		return err.Error(), true
	}
	return "", false
}

// Privileged indica si el proceso se ejecuta como root o elevado (UAC).
// Es una variable para poder simularlo en las pruebas.
var Privileged = sync.OnceValue(isPrivileged)

// permissionErr traduce un permiso denegado a PrivilegeError cuando el
// proceso no tiene privilegios.
func permissionErr(err error, what string) error {
	if errors.Is(err, fs.ErrPermission) && !Privileged() {
		return NeedsPrivilege("sin permiso para leer %s", what)
	}
	return err
}

var (
	regMu         sync.RWMutex
	probeRegistry = map[string]Probe{}
)

// Register registra un probe disponible en la plataforma actual.
func Register(p Probe) {
	regMu.Lock()
	defer regMu.Unlock()
	probeRegistry[p.Name()] = p
}

// Get devuelve el probe registrado con ese nombre.
func Get(name string) (Probe, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	p, ok := probeRegistry[name]
	return p, ok
}

// Available lista los probes registrados en esta plataforma.
func Available() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(probeRegistry))
	for n := range probeRegistry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Known son todos los probes que existen en alguna plataforma. Lo usa el
// linter de reglas, que debe funcionar igual en Windows y en Linux.
var Known = map[string]string{
	// multiplataforma
	"file_content": "all",
	"file_regex":   "all",
	"file_kv":      "all",
	// linux
	"sysctl":  "linux",
	"file":    "linux",
	"sshd":    "linux",
	"kmod":    "linux",
	"systemd": "linux",
	"mount":   "linux",
	"package": "linux",
	// windows
	"registry": "windows",
	"secpol":   "windows",
	"auditpol": "windows",
	"service":  "windows",
	"ps":       "windows",
}

// KnownSet devuelve Known como conjunto.
func KnownSet() map[string]bool {
	out := map[string]bool{}
	for k := range Known {
		out[k] = true
	}
	return out
}

// Params son los parámetros específicos del probe declarados en la regla.
type Params map[string]any

// String devuelve un parámetro de texto.
func (p Params) String(key string) string {
	switch v := p[key].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// Strings devuelve un parámetro que puede ser texto o lista de textos.
func (p Params) Strings(key string) []string {
	switch v := p[key].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			out = append(out, fmt.Sprint(x))
		}
		return out
	case []string:
		return v
	}
	return nil
}

// Bool devuelve un parámetro booleano con valor por defecto def.
func (p Params) Bool(key string, def bool) bool {
	switch v := p[key].(type) {
	case bool:
		return v
	case string:
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

// Require devuelve error si falta algún parámetro obligatorio.
func (p Params) Require(keys ...string) error {
	var missing []string
	for _, k := range keys {
		if strings.TrimSpace(p.String(k)) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("faltan parámetros: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Session cachea resultados costosos durante un escaneo (un solo
// "secedit /export", un solo "sshd -T", etc.) aunque los pidan muchas reglas
// en paralelo.
type Session struct {
	mu      sync.Mutex
	entries map[string]*sessionEntry
}

type sessionEntry struct {
	once sync.Once
	val  any
	err  error
}

// NewSession crea una caché vacía.
func NewSession() *Session { return &Session{entries: map[string]*sessionEntry{}} }

// Do ejecuta fn una sola vez por clave y devuelve siempre el mismo resultado.
func (s *Session) Do(key string, fn func() (any, error)) (any, error) {
	s.mu.Lock()
	e, ok := s.entries[key]
	if !ok {
		e = &sessionEntry{}
		s.entries[key] = e
	}
	s.mu.Unlock()
	e.once.Do(func() { e.val, e.err = fn() })
	return e.val, e.err
}

type sessionKey struct{}

// WithSession asocia una sesión al contexto.
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFrom obtiene la sesión del contexto (o una nueva si no hay).
func SessionFrom(ctx context.Context) *Session {
	if s, ok := ctx.Value(sessionKey{}).(*Session); ok {
		return s
	}
	return NewSession()
}

// cached es un atajo tipado de Session.Do.
func cached[T any](ctx context.Context, key string, fn func() (T, error)) (T, error) {
	v, err := SessionFrom(ctx).Do(key, func() (any, error) { return fn() })
	if err != nil {
		var zero T
		return zero, err
	}
	return v.(T), nil
}
