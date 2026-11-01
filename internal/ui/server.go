// Package ui sirve la consola local de Adarve ("adarve ui"): un panel en
// el navegador con la postura, la tendencia, el plan de hardening, el
// historial y las excepciones del equipo.
//
// Seguridad (ver docs/adr/0008-consola-local.md):
//   - Solo escucha en la interfaz de loopback (127.0.0.1).
//   - Toda la API exige un token aleatorio de 256 bits que solo conoce
//     quien lanzó "adarve ui": en la cabecera X-Adarve-Token (scripts) o
//     en una cookie de sesión HttpOnly y SameSite=Strict (el navegador),
//     acompañada de la cabecera X-Adarve-Request. La dirección con el
//     token solo se muestra en la terminal; el navegador se abre con un
//     fichero local 0600 que redirige con un código de un solo uso, así que
//     el token nunca aparece en la línea de órdenes del navegador (visible
//     para otros usuarios en /proc) ni en las URLs de la consola. Otro
//     usuario del mismo equipo puede conectarse al puerto, pero no hacer
//     nada sin el token.
//   - Se rechaza cualquier cabecera Host que no sea de loopback, lo que
//     frena los ataques de DNS rebinding, y no se responde a CORS: una web
//     maliciosa no puede enviar la cabecera del token ni leer respuestas.
//   - CSP estricta con nonce, como el informe HTML: los datos del sistema
//     auditado se insertan siempre con textContent.
//   - La consola solo lee y escanea. Aplicar cambios exige la terminal,
//     donde están la confirmación, la instantánea y el dead-man switch.
package ui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/report"
	"github.com/Ruby570bocadito/adarve/internal/schedule"
	"github.com/Ruby570bocadito/adarve/internal/surface"
)

//go:embed assets/ui.html
var shell []byte

// State describe el equipo y la sesión de la consola.
type State struct {
	Version    string `json:"version"`
	Hostname   string `json:"hostname"`
	System     string `json:"system"`
	Family     string `json:"family"`
	Role       string `json:"role"`
	Profile    string `json:"profile"`
	ProfileID  string `json:"profile_id"`
	IsAdmin    bool   `json:"is_admin"`
	ReportsDir string `json:"reports_dir"`
}

// PlanItem es un control fallido y lo que "harden" haría con él.
type PlanItem struct {
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Category string   `json:"category"`
	Status   string   `json:"status"`
	Reason   string   `json:"reason,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Risk     string   `json:"risk"`
	Reboot   bool     `json:"reboot,omitempty"`
	Steps    []string `json:"steps,omitempty"`
}

// Change resume un cambio de hardening aplicado.
type Change struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Wave       int       `json:"wave"`
	Status     string    `json:"status"`
	Profile    string    `json:"profile"`
	Verified   int       `json:"verified"`
	Failed     int       `json:"failed"`
	RolledBack int       `json:"rolled_back"`
	// Nothing cuenta los controles que al aplicar ya no necesitaban cambios.
	Nothing int  `json:"nothing,omitempty"`
	Reboot  bool `json:"reboot,omitempty"`
}

// Exception es una excepción con su vigencia calculada.
type Exception struct {
	Rule     string   `json:"rule"`
	Reason   string   `json:"reason"`
	Owner    string   `json:"owner,omitempty"`
	Hosts    []string `json:"hosts,omitempty"`
	Created  string   `json:"created"`
	Expires  string   `json:"expires"`
	Expired  bool     `json:"expired"`
	DaysLeft int      `json:"days_left"`
}

// ScheduleInfo es el análisis programado y sus últimas ejecuciones.
type ScheduleInfo struct {
	Status schedule.Status `json:"status"`
	Runs   []schedule.Run  `json:"runs"`
	// Unsupported indica que el sistema no tiene un planificador conocido.
	Unsupported bool `json:"unsupported,omitempty"`
	// Notify describe dónde avisa cada ejecución (sin el secreto del
	// webhook).
	Notify string `json:"notify,omitempty"`
}

// Backend es lo que la consola necesita de Adarve. Lo implementa la CLI.
type Backend interface {
	State() State
	// Scan evalúa el perfil, guarda el informe y lo devuelve con su ID.
	Scan(ctx context.Context) (*engine.Report, string, error)
	Reports() ([]report.Meta, error)
	Report(id string) (*engine.Report, error)
	Plan(ctx context.Context, wave int) ([]PlanItem, error)
	Changes() ([]Change, error)
	Exceptions() ([]Exception, error)
	// Surface analiza la superficie de ataque (puertos, recursos, administradores).
	Surface(ctx context.Context) (*surface.Report, error)
	// Schedule describe el análisis programado (adarve schedule).
	Schedule(ctx context.Context) (*ScheduleInfo, error)
}

// Server es la consola local.
type Server struct {
	backend Backend
	token   string
	// cookie es el nombre de la cookie de sesión: lleva un resumen del
	// token porque las cookies no distinguen puertos y puede haber dos
	// consolas abiertas en 127.0.0.1.
	cookie string
	// codes son los códigos de un solo uso para abrir el navegador, con su
	// caducidad.
	mu    sync.Mutex
	codes map[string]time.Time
	// Un único escaneo, plan o análisis de superficie a la vez: todos leen
	// el sistema entero. Un segundo escaneo se rechaza; el plan y la
	// superficie esperan a que termine el que está en curso.
	busy chan struct{}
	// base es el contexto de Serve: se cancela al cerrar la consola.
	base context.Context
}

// scanTimeout limita un escaneo lanzado desde la consola.
const scanTimeout = 15 * time.Minute

func (s *Server) baseContext() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.base == nil {
		return context.Background()
	}
	return s.base
}

func (s *Server) tryAcquire() bool {
	select {
	case s.busy <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) acquire(ctx context.Context) error {
	select {
	case s.busy <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) release() { <-s.busy }

// New crea la consola con un token aleatorio.
func New(b Backend) (*Server, error) {
	t := make([]byte, 32)
	if _, err := rand.Read(t); err != nil {
		return nil, err
	}
	tok := base64.RawURLEncoding.EncodeToString(t)
	sum := sha256.Sum256([]byte(tok))
	return &Server{backend: b, token: tok, cookie: "adarve_" + hex.EncodeToString(sum[:6]),
		codes: map[string]time.Time{}, busy: make(chan struct{}, 1)}, nil
}

// Token es el secreto de la sesión. Solo se muestra en la terminal.
func (s *Server) Token() string { return s.token }

// codeTTL es lo que dura un código de apertura sin usar.
const codeTTL = 2 * time.Minute

// LaunchCode crea un código de un solo uso que, en GET /?c=<código>, abre
// una sesión en el navegador. Es lo que lleva la dirección con la que se
// abre el navegador: aunque otro usuario la viera, ya estaría gastado.
func (s *Server) LaunchCode() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	c := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, exp := range s.codes {
		if now.After(exp) {
			delete(s.codes, k)
		}
	}
	s.codes[c] = now.Add(codeTTL)
	return c, nil
}

// useCode gasta un código de apertura válido.
func (s *Server) useCode(c string) bool {
	if c == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.codes {
		if subtle.ConstantTimeCompare([]byte(k), []byte(c)) == 1 {
			delete(s.codes, k)
			return time.Now().Before(exp)
		}
	}
	return false
}

// WriteLauncher escribe en una carpeta temporal privada (0700) un fichero
// HTML (0600) que lleva al navegador a base con un código de un solo uso.
// Se abre ese fichero en lugar de la URL: la línea de órdenes del navegador
// solo contiene su ruta. cleanup lo borra.
func (s *Server) WriteLauncher(base string) (path string, cleanup func(), err error) {
	code, err := s.LaunchCode()
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "adarve-ui-")
	if err != nil {
		return "", nil, err
	}
	target := strings.TrimRight(base, "/") + "/?c=" + code
	page := `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer">` +
		`<meta http-equiv="refresh" content="0;url=` + html.EscapeString(target) + `">` +
		`<title>Adarve</title><p>Abriendo la consola de Adarve… <a href="` + html.EscapeString(target) + `">continuar</a></p>`
	path = filepath.Join(dir, "adarve-ui.html")
	if err := os.WriteFile(path, []byte(page), 0o600); err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	return path, func() { os.RemoveAll(dir) }, nil
}

// Listen abre el puerto en loopback (0 = uno libre al azar).
func Listen(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

// Serve atiende hasta que ctx se cancela.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.mu.Lock()
	s.base = ctx
	s.mu.Unlock()
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      scanTimeout + time.Minute, // la respuesta de POST /api/scan llega al terminar el escaneo
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	go func() { // #nosec G118 -- cierra el servidor al cancelar ctx; el apagado no puede depender de una petición
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Handler devuelve el enrutador con todas las protecciones aplicadas.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleShell)
	mux.Handle("GET /api/state", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		return s.backend.State(), nil
	}))
	mux.Handle("GET /api/reports", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		list, err := s.backend.Reports()
		if list == nil {
			list = []report.Meta{}
		}
		return list, err
	}))
	mux.Handle("GET /api/reports/{id}", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		id := r.PathValue("id")
		if !report.ValidReportID(id) {
			return nil, httpError{http.StatusBadRequest, "identificador de informe inválido"}
		}
		return s.backend.Report(id)
	}))
	mux.Handle("POST /api/scan", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		if !s.tryAcquire() {
			return nil, httpError{http.StatusConflict, "ya hay un escaneo en curso"}
		}
		defer s.release()
		// El escaneo no depende de la petición: si el navegador cierra la
		// pestaña o corta la conexión, termina igual y se guarda completo
		// (con el contexto de la petición se guardaría un informe a medias,
		// lleno de errores). Solo lo cancela cerrar la consola.
		ctx, cancel := context.WithTimeout(s.baseContext(), scanTimeout)
		defer cancel()
		rep, id, err := s.backend.Scan(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id, "report": rep}, nil
	}))
	mux.Handle("GET /api/plan", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		wave, err := strconv.Atoi(r.URL.Query().Get("wave"))
		if err != nil || wave < 1 || wave > 3 {
			return nil, httpError{http.StatusBadRequest, "wave debe ser 1, 2 o 3"}
		}
		if err := s.acquire(r.Context()); err != nil {
			return nil, err
		}
		defer s.release()
		items, err := s.backend.Plan(r.Context(), wave)
		if items == nil {
			items = []PlanItem{}
		}
		return items, err
	}))
	mux.Handle("GET /api/changes", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		list, err := s.backend.Changes()
		if list == nil {
			list = []Change{}
		}
		return list, err
	}))
	mux.Handle("GET /api/exceptions", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		list, err := s.backend.Exceptions()
		if list == nil {
			list = []Exception{}
		}
		return list, err
	}))
	mux.Handle("GET /api/schedule", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		info, err := s.backend.Schedule(r.Context())
		if info != nil && info.Runs == nil {
			info.Runs = []schedule.Run{}
		}
		return info, err
	}))
	mux.Handle("GET /api/surface", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		if err := s.acquire(r.Context()); err != nil {
			return nil, err
		}
		defer s.release()
		return s.backend.Surface(r.Context())
	}))
	// El informe HTML completo de un escaneo (para la pestaña Controles).
	mux.HandleFunc("GET /r/{file}", s.handleReportHTML)
	return s.guard(mux)
}

// guard aplica a todas las respuestas las cabeceras de seguridad y rechaza
// los Host que no son de loopback (DNS rebinding).
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if !loopbackHost(r.Host) {
			http.Error(w, "host no permitido", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && !loopbackOrigin(o) {
				http.Error(w, "origen no permitido", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func loopbackOrigin(o string) bool {
	rest, ok := strings.CutPrefix(o, "http://")
	return ok && loopbackHost(rest)
}

func (s *Server) validToken(t string) bool {
	return t != "" && subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
}

// session indica si la petición trae la cookie de sesión válida.
func (s *Server) session(r *http.Request) bool {
	c, err := r.Cookie(s.cookie)
	return err == nil && s.validToken(c.Value)
}

// authAPI acepta el token en la cabecera X-Adarve-Token (scripts, curl) o
// la cookie de sesión con la cabecera X-Adarve-Request: una web ajena no
// puede añadir esa cabecera sin una comprobación CORS que no se concede, así
// que la cookie sola no sirve para una petición cruzada.
func (s *Server) authAPI(r *http.Request) bool {
	if s.validToken(r.Header.Get("X-Adarve-Token")) {
		return true
	}
	return r.Header.Get("X-Adarve-Request") == "1" && s.session(r)
}

// setSession fija la cookie de sesión del navegador.
func (s *Server) setSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode}) // #nosec G124 -- consola en http://127.0.0.1: una cookie Secure no se enviaría; HttpOnly y SameSite=Strict
}

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }

// api envuelve un manejador JSON: exige el token y serializa la respuesta.
func (s *Server) api(fn func(http.ResponseWriter, *http.Request) (any, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if !s.authAPI(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sesión ausente o incorrecta: abre la dirección que muestra \"adarve ui\""})
			return
		}
		v, err := fn(w, r)
		if err != nil {
			code := http.StatusInternalServerError
			var he httpError
			if errors.As(err, &he) {
				code = he.code
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// handleShell sirve la aplicación. No contiene datos: los pide a la API con
// la sesión, así que puede servirse sin ella.
//
// La dirección de la terminal (?t=<token>) y la del fichero de apertura
// (?c=<código de un solo uso>) abren la sesión: el servidor fija la cookie y
// redirige a "/", así que el secreto no se queda en la barra de direcciones.
func (s *Server) handleShell(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Has("t") || q.Has("c") {
		if s.validToken(q.Get("t")) || s.useCode(q.Get("c")) {
			s.setSession(w)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "error interno", http.StatusInternalServerError)
		return
	}
	n := base64.RawURLEncoding.EncodeToString(nonce)
	w.Header().Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; script-src 'nonce-%s'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", n))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(bytes.ReplaceAll(shell, []byte("__NONCE__"), []byte(n)))
}

// handleReportHTML sirve el informe HTML de un escaneo guardado. Va en un
// iframe de la propia consola (o en una pestaña nueva): se autoriza con la
// cookie de sesión, nunca con el token en la URL. La cookie es SameSite=
// Strict y el informe solo se puede incrustar en la consola.
func (s *Server) handleReportHTML(w http.ResponseWriter, r *http.Request) {
	if !s.session(r) && !s.validToken(r.Header.Get("X-Adarve-Token")) {
		http.Error(w, "sesión ausente o incorrecta: abre la dirección que muestra \"adarve ui\"", http.StatusUnauthorized)
		return
	}
	id, ok := strings.CutSuffix(r.PathValue("file"), ".html")
	if !ok || !report.ValidReportID(id) {
		http.NotFound(w, r)
		return
	}
	rep, err := s.backend.Report(id)
	if err != nil {
		http.Error(w, "informe no disponible", http.StatusNotFound)
		return
	}
	// El informe trae su propia CSP con nonce; aquí solo se limita quién
	// puede incrustarlo.
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := report.HTML(&buf, rep); err != nil {
		http.Error(w, "error interno", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}
