package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/report"
	"github.com/Ruby570bocadito/adarve/internal/schedule"
	"github.com/Ruby570bocadito/adarve/internal/surface"
)

const goodID = "adarve-pc-01-20261015-100000"

type fakeBackend struct {
	scans   int
	onScan  func(context.Context)
	block   chan struct{}
	started chan struct{}
}

func (f *fakeBackend) State() State { return State{Hostname: "pc-01", Version: "test"} }
func (f *fakeBackend) Scan(ctx context.Context) (*engine.Report, string, error) {
	f.scans++
	if f.onScan != nil {
		f.onScan(ctx)
	}
	if f.block != nil {
		close(f.started)
		<-f.block
	}
	return &engine.Report{Score: engine.Score{Value: 77}}, goodID, nil
}
func (f *fakeBackend) Reports() ([]report.Meta, error) {
	return []report.Meta{{ID: goodID, FinishedAt: time.Now()}}, nil
}
func (f *fakeBackend) Report(id string) (*engine.Report, error) {
	if id != goodID {
		return nil, errors.New("no existe")
	}
	return &engine.Report{Schema: engine.SchemaVersion, Score: engine.Score{Value: 77}}, nil
}
func (f *fakeBackend) Plan(ctx context.Context, wave int) ([]PlanItem, error) {
	return []PlanItem{{RuleID: "WIN-NET-006", Status: "planned"}}, nil
}
func (f *fakeBackend) Changes() ([]Change, error)       { return nil, nil }
func (f *fakeBackend) Exceptions() ([]Exception, error) { return nil, nil }
func (f *fakeBackend) Surface(ctx context.Context) (*surface.Report, error) {
	return &surface.Report{Schema: surface.Schema, Score: 85}, nil
}
func (f *fakeBackend) Schedule(ctx context.Context) (*ScheduleInfo, error) {
	return &ScheduleInfo{Status: schedule.Status{Enabled: true, At: "09:00", Mechanism: "systemd"}}, nil
}

func newTest(t *testing.T) (*Server, http.Handler, *fakeBackend) {
	t.Helper()
	fb := &fakeBackend{}
	s, err := New(fb)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Token()) < 40 {
		t.Fatalf("token demasiado corto: %q", s.Token())
	}
	return s, s.Handler(), fb
}

func do(h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "127.0.0.1:8790"
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestShellCSP(t *testing.T) {
	_, h, _ := newTest(t)
	rec := do(h, "GET", "/", nil)
	if rec.Code != 200 {
		t.Fatalf("GET / = %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]+)'`).FindStringSubmatch(csp)
	if m == nil || !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP inesperada: %s", csp)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<script nonce="`+m[1]+`">`) || strings.Contains(body, "__NONCE__") {
		t.Error("el script debe llevar el nonce de la cabecera")
	}
	if strings.Contains(body, "innerHTML") || strings.Contains(body, "insertAdjacentHTML") {
		t.Error("la consola no debe insertar HTML")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("faltan cabeceras de seguridad")
	}
}

func TestToken(t *testing.T) {
	s, h, _ := newTest(t)
	for name, hdr := range map[string]map[string]string{
		"sin token":     nil,
		"token erróneo": {"X-Adarve-Token": "x" + s.Token()[1:]},
		"en la query":   nil, // la API no acepta el token en la URL
	} {
		target := "/api/state"
		if name == "en la query" {
			target += "?t=" + s.Token()
		}
		if rec := do(h, "GET", target, hdr); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, quiero 401", name, rec.Code)
		}
	}
	rec := do(h, "GET", "/api/state", map[string]string{"X-Adarve-Token": s.Token()})
	var st State
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.Hostname != "pc-01" {
		t.Errorf("con token: %d %s", rec.Code, rec.Body)
	}
}

func TestHostAndOrigin(t *testing.T) {
	s, h, fb := newTest(t)
	tok := map[string]string{"X-Adarve-Token": s.Token()}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{"X-Adarve-Token": s.Token()}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	// DNS rebinding: un dominio del atacante que resuelve a 127.0.0.1.
	for _, host := range []string{"evil.example:8790", "127.0.0.1.evil.example", "192.168.1.10:8790"} {
		if rec := do(h, "GET", "/", map[string]string{"Host": host}); rec.Code != http.StatusForbidden {
			t.Errorf("Host %s: %d, quiero 403", host, rec.Code)
		}
	}
	for _, host := range []string{"localhost:9000", "[::1]:8790", "127.0.0.1"} {
		if rec := do(h, "GET", "/api/state", with(map[string]string{"Host": host})); rec.Code != 200 {
			t.Errorf("Host %s: %d, quiero 200", host, rec.Code)
		}
	}
	if rec := do(h, "POST", "/api/scan", with(map[string]string{"Origin": "https://evil.example"})); rec.Code != http.StatusForbidden || fb.scans != 0 {
		t.Errorf("POST desde otro origen: %d (escaneos %d)", rec.Code, fb.scans)
	}
	if rec := do(h, "POST", "/api/scan", with(map[string]string{"Origin": "http://127.0.0.1:8790"})); rec.Code != 200 || fb.scans != 1 {
		t.Errorf("POST desde la consola: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "GET", "/api/scan", tok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/scan: %d, quiero 405", rec.Code)
	}
}

func TestReportIDs(t *testing.T) {
	s, h, _ := newTest(t)
	tok := map[string]string{"X-Adarve-Token": s.Token()}
	if rec := do(h, "GET", "/api/reports/"+goodID, tok); rec.Code != 200 {
		t.Errorf("informe válido: %d", rec.Code)
	}
	for _, id := range []string{"..%2F..%2Fetc%2Fpasswd", "adarve-x", "%2E%2E"} {
		if rec := do(h, "GET", "/api/reports/"+id, tok); rec.Code == 200 {
			t.Errorf("%s debería rechazarse", id)
		}
	}
	if rec := do(h, "GET", "/r/"+goodID+".html", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("informe HTML sin sesión: %d", rec.Code)
	}
	// El token en la URL ya no vale: solo la cookie de sesión.
	if rec := do(h, "GET", "/r/"+goodID+".html?t="+s.Token(), nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("informe HTML con el token en la URL: %d, quiero 401", rec.Code)
	}
	cookie := map[string]string{"Cookie": s.cookie + "=" + s.Token()}
	rec := do(h, "GET", "/r/"+goodID+".html", cookie)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "adarve-data") {
		t.Errorf("informe HTML: %d", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != "frame-ancestors 'self'" {
		t.Errorf("el informe solo debe poder incrustarse en la consola: %q", csp)
	}
	if rec := do(h, "GET", "/r/../x.html", cookie); rec.Code == 200 {
		t.Error("ruta fuera del directorio aceptada")
	}
}

func TestSessionCookieAndLaunchCode(t *testing.T) {
	s, h, _ := newTest(t)
	// La dirección de la terminal abre la sesión y redirige sin el token.
	rec := do(h, "GET", "/?t="+s.Token(), nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("GET /?t=: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	c := rec.Result().Cookies()
	if len(c) != 1 || c[0].Value != s.Token() || !c[0].HttpOnly || c[0].SameSite != http.SameSiteStrictMode || c[0].Name != s.cookie {
		t.Fatalf("cookie de sesión: %+v", c)
	}
	// Un token erróneo no abre sesión.
	if rec := do(h, "GET", "/?t=x"+s.Token()[1:], nil); len(rec.Result().Cookies()) != 0 {
		t.Error("un token erróneo no debe abrir sesión")
	}
	cookie := s.cookie + "=" + s.Token()
	// La cookie sola no basta para la API (CSRF): hace falta la cabecera.
	if rec := do(h, "GET", "/api/state", map[string]string{"Cookie": cookie}); rec.Code != http.StatusUnauthorized {
		t.Errorf("cookie sin X-Adarve-Request: %d, quiero 401", rec.Code)
	}
	if rec := do(h, "GET", "/api/state", map[string]string{"Cookie": cookie, "X-Adarve-Request": "1"}); rec.Code != 200 {
		t.Errorf("cookie con X-Adarve-Request: %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/state", map[string]string{"Cookie": s.cookie + "=otro", "X-Adarve-Request": "1"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("cookie errónea: %d", rec.Code)
	}

	// Código de un solo uso del fichero de apertura.
	code, err := s.LaunchCode()
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(h, "GET", "/?c="+code, nil); rec.Code != http.StatusSeeOther || len(rec.Result().Cookies()) != 1 {
		t.Errorf("primer uso del código: %d %v", rec.Code, rec.Result().Cookies())
	}
	if rec := do(h, "GET", "/?c="+code, nil); len(rec.Result().Cookies()) != 0 {
		t.Error("el código solo vale una vez")
	}

	// El fichero de apertura es privado y no contiene el token.
	path, cleanup, err := s.WriteLauncher("http://127.0.0.1:8790")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), s.Token()) || !strings.Contains(string(b), "http://127.0.0.1:8790/?c=") {
		t.Errorf("fichero de apertura:\n%s", b)
	}
	if fi, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("permisos del fichero de apertura: %v %v", fi.Mode(), err)
	}
}

// Un escaneo lanzado desde la consola no se cancela si el navegador corta
// la conexión: se guardaría a medias.
func TestScanDetachedFromRequest(t *testing.T) {
	s, h, fb := newTest(t)
	called := false
	var scanErr error
	fb.onScan = func(ctx context.Context) { called, scanErr = true, ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/api/scan", nil).WithContext(ctx)
	req.Host = "127.0.0.1:8790"
	req.Header.Set("X-Adarve-Token", s.Token())
	cancel()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || scanErr != nil {
		t.Errorf("el escaneo recibió un contexto cancelado con la petición: %v", scanErr)
	}
}

func TestPlanAndBusy(t *testing.T) {
	s, h, fb := newTest(t)
	tok := map[string]string{"X-Adarve-Token": s.Token()}
	for _, w := range []string{"0", "4", "x", ""} {
		if rec := do(h, "GET", "/api/plan?wave="+w, tok); rec.Code != http.StatusBadRequest {
			t.Errorf("wave=%q: %d, quiero 400", w, rec.Code)
		}
	}
	if rec := do(h, "GET", "/api/plan?wave=2", tok); rec.Code != 200 || !strings.Contains(rec.Body.String(), "WIN-NET-006") {
		t.Errorf("plan: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "GET", "/api/surface", tok); rec.Code != 200 || !strings.Contains(rec.Body.String(), surface.Schema) {
		t.Errorf("superficie: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "GET", "/api/surface", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("superficie sin token: %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/schedule", tok); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"at":"09:00"`) || !strings.Contains(rec.Body.String(), `"runs":[]`) {
		t.Errorf("programación: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "GET", "/api/schedule", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("programación sin token: %d", rec.Code)
	}

	// Mientras un escaneo está en curso, otro escaneo responde 409 y el plan
	// espera a que termine (no falla).
	fb.block, fb.started = make(chan struct{}), make(chan struct{})
	done := make(chan int)
	go func() { done <- do(h, "POST", "/api/scan", tok).Code }()
	<-fb.started
	if rec := do(h, "POST", "/api/scan", tok); rec.Code != http.StatusConflict {
		t.Errorf("segundo escaneo: %d, quiero 409", rec.Code)
	}
	planDone := make(chan int)
	go func() { planDone <- do(h, "GET", "/api/plan?wave=1", tok).Code }()
	select {
	case code := <-planDone:
		t.Fatalf("el plan no debe adelantarse al escaneo en curso (respondió %d)", code)
	case <-time.After(100 * time.Millisecond):
	}
	close(fb.block)
	if code := <-done; code != 200 {
		t.Errorf("primer escaneo: %d", code)
	}
	if code := <-planDone; code != 200 {
		t.Errorf("plan tras el escaneo: %d", code)
	}
}

func TestListenLoopback(t *testing.T) {
	l, err := Listen(0)
	if err != nil {
		t.Skip("sin red de loopback:", err)
	}
	defer l.Close()
	if !strings.HasPrefix(l.Addr().String(), "127.0.0.1:") {
		t.Errorf("escucha en %s, quiero solo 127.0.0.1", l.Addr())
	}
}
