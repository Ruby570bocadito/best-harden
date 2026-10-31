package schedule

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeUnix(t *testing.T, systemd bool) (*unixScheduler, *[]string) {
	t.Helper()
	root := t.TempDir()
	if systemd {
		if err := os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var calls []string
	u := &unixScheduler{root: root, run: func(_ context.Context, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch {
		case strings.HasPrefix(call, "systemctl is-enabled"):
			return "enabled\n", nil
		case strings.HasPrefix(call, "systemctl show"):
			return "Sat 2026-10-17 09:30:00 CEST\n", nil
		}
		return "", nil
	}}
	return u, &calls
}

func TestSystemdTimer(t *testing.T) {
	u, calls := fakeUnix(t, true)
	ctx := context.Background()
	st, err := u.Enable(ctx, "/opt/mis herramientas/adarve", "09:30")
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := os.ReadFile(u.path(servicePath))
	timer, _ := os.ReadFile(u.path(timerPath))
	if !strings.Contains(string(svc), `ExecStart="/opt/mis herramientas/adarve" schedule run`) || !strings.Contains(string(svc), "SuccessExitStatus=3") {
		t.Errorf("servicio:\n%s", svc)
	}
	if !strings.Contains(string(timer), "OnCalendar=*-*-* 09:30:00") || !strings.Contains(string(timer), "Persistent=true") {
		t.Errorf("temporizador:\n%s", timer)
	}
	if got := strings.Join(*calls, "\n"); !strings.Contains(got, "systemctl daemon-reload\nsystemctl enable --now adarve-scan.timer") {
		t.Errorf("órdenes:\n%s", got)
	}
	if !st.Enabled || st.At != "09:30" || !strings.HasPrefix(st.Mechanism, "systemd") || st.NextRun == "" || !strings.Contains(st.Command, "schedule run") {
		t.Errorf("estado: %+v", st)
	}
	*calls = nil
	if err := u.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{servicePath, timerPath} {
		if _, err := os.Stat(u.path(p)); !os.IsNotExist(err) {
			t.Errorf("%s debería haberse borrado", p)
		}
	}
	if got := strings.Join(*calls, "\n"); !strings.Contains(got, "systemctl disable --now adarve-scan.timer") {
		t.Errorf("órdenes al desactivar:\n%s", got)
	}
	if st, _ := u.Get(ctx); st.Enabled {
		t.Errorf("tras desactivar: %+v", st)
	}
}

func TestCronFallback(t *testing.T) {
	u, calls := fakeUnix(t, false)
	ctx := context.Background()
	st, err := u.Enable(ctx, "/usr/local/bin/adarve", "07:05")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(u.path(cronPath))
	if !strings.Contains(string(b), "5 7 * * * root /usr/local/bin/adarve schedule run") {
		t.Errorf("cron:\n%s", b)
	}
	if len(*calls) != 0 {
		t.Errorf("sin systemd no se llama a systemctl: %v", *calls)
	}
	if !st.Enabled || st.At != "07:05" || !strings.HasPrefix(st.Mechanism, "cron") {
		t.Errorf("estado: %+v", st)
	}
	if err := u.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := u.Get(ctx); st.Enabled {
		t.Errorf("tras desactivar: %+v", st)
	}
	if got := cronEntry("/opt/a b/adarve", "00:00"); !strings.Contains(got, "0 0 * * * root '/opt/a b/adarve' schedule run") {
		t.Errorf("ruta con espacios: %s", got)
	}
	if got := cronEntry("/opt/100%/adarve", "00:00"); !strings.Contains(got, `root /opt/100\%/adarve schedule run`) {
		t.Errorf("%% en la ruta: %s", got)
	}
}

func TestSystemdEscapes(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/local/bin/adarve": "/usr/local/bin/adarve",
		"/opt/100%/adarve":      "/opt/100%%/adarve",
		"/opt/$HOME/adarve":     "/opt/$$HOME/adarve",
		"/opt/a b/adarve":       `"/opt/a b/adarve"`,
		`/opt/a "b"/c%d/adarve`: `"/opt/a \"b\"/c%%d/adarve"`,
	} {
		if got := systemdQuote(in); got != want {
			t.Errorf("systemdQuote(%q) = %q, quiero %q", in, got, want)
		}
	}
	if svc := serviceUnit("/usr/local/bin/adarve"); !strings.Contains(svc, "TimeoutStartSec=") {
		t.Errorf("el servicio necesita un plazo:\n%s", svc)
	}
}

func TestValidAt(t *testing.T) {
	for _, ok := range []string{"00:00", "09:30", "23:59"} {
		if ValidAt(ok) != nil {
			t.Errorf("%s debería ser válida", ok)
		}
	}
	for _, bad := range []string{"9:30", "24:00", "12:60", "09:30; rm -rf /", ""} {
		if ValidAt(bad) == nil {
			t.Errorf("%q debería rechazarse", bad)
		}
	}
}

func TestRunLog(t *testing.T) {
	path := LogPath(t.TempDir())
	t0 := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	for i := 0; i < maxLog+5; i++ {
		if err := AppendRun(path, Run{Time: t0.Add(time.Duration(i) * time.Hour), ScanScore: 70 + i%10, SurfaceScore: 60}); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := ReadRuns(path)
	if err != nil || len(runs) != maxLog {
		t.Fatalf("ejecuciones: %d %v", len(runs), err)
	}
	if !runs[len(runs)-1].Time.Equal(t0.Add(time.Duration(maxLog+4) * time.Hour)) {
		t.Errorf("la última debe ser la más reciente: %v", runs[len(runs)-1].Time)
	}
}

func TestSafeExecutable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("comprueba propietarios root: solo como root")
	}
	if err := SafeExecutable("/bin/sh"); err != nil {
		t.Errorf("/bin/sh es de root y no se puede modificar: %v", err)
	}
	dir := t.TempDir() // bajo /tmp, con escritura para todos
	exe := filepath.Join(dir, "adarve")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SafeExecutable(exe); err == nil {
		t.Error("un ejecutable bajo /tmp no es seguro para una tarea de root")
	}
	if err := os.Chmod(exe, 0o777); err == nil {
		if err := SafeExecutable(exe); err == nil || !strings.Contains(err.Error(), "escritura") {
			t.Errorf("con permiso de escritura para todos: %v", err)
		}
	}
}
