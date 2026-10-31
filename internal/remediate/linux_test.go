//go:build linux

package remediate

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ruby570bocadito/adarve/internal/probes"
)

// sandbox redirige las rutas de los remediadores a un directorio temporal.
func sandbox(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := []string{sysctlDropIn, procSys, modprobeDir, sudoersDropIn, sysctlLegacyDropIn}
	sysctlDropIn = filepath.Join(root, "etc/sysctl.d/99-zz-bastion.conf")
	sysctlLegacyDropIn = filepath.Join(root, "etc/sysctl.d/60-bastion.conf")
	procSys = filepath.Join(root, "proc/sys")
	modprobeDir = filepath.Join(root, "etc/modprobe.d")
	sudoersDropIn = filepath.Join(root, "etc/sudoers.d/00-bastion")
	t.Cleanup(func() {
		sysctlDropIn, procSys, modprobeDir, sudoersDropIn, sysctlLegacyDropIn = old[0], old[1], old[2], old[3], old[4]
	})
	return root
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return "<no existe>"
	}
	return string(b)
}

// roundTrip simula guardar el estado previo en el manifiesto (JSON) y leerlo
// después, como hace un rollback desde otro proceso.
func roundTrip(t *testing.T, s State) State {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var out State
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func cycle(t *testing.T, r Remediator, p probes.Params) State {
	t.Helper()
	before, err := r.Capture(context.Background(), p)
	if err != nil {
		t.Fatalf("%s capture: %v", r.Type(), err)
	}
	if err := r.Apply(context.Background(), p); err != nil {
		t.Fatalf("%s apply: %v", r.Type(), err)
	}
	return roundTrip(t, before)
}

func TestSysctlSetCycle(t *testing.T) {
	root := sandbox(t)
	write(t, filepath.Join(root, "proc/sys/net/ipv4/conf/all/rp_filter"), "0\n")
	write(t, filepath.Join(root, "proc/sys/kernel/kptr_restrict"), "0\n")
	r := sysctlSet{}

	b1 := cycle(t, r, probes.Params{"key": "net.ipv4.conf.all.rp_filter", "value": 1})
	b2 := cycle(t, r, probes.Params{"key": "kernel.kptr_restrict", "value": 2})
	if got := read(t, filepath.Join(root, "proc/sys/kernel/kptr_restrict")); got != "2\n" {
		t.Errorf("runtime kptr_restrict = %q", got)
	}
	conf := read(t, sysctlDropIn)
	if !strings.Contains(conf, "net.ipv4.conf.all.rp_filter = 1") || !strings.Contains(conf, "kernel.kptr_restrict = 2") {
		t.Errorf("drop-in inesperado:\n%s", conf)
	}
	// Restaurar en orden inverso deja todo como estaba (y el drop-in no existía).
	if err := r.Restore(context.Background(), probes.Params{"key": "kernel.kptr_restrict"}, b2); err != nil {
		t.Fatal(err)
	}
	if err := r.Restore(context.Background(), probes.Params{"key": "net.ipv4.conf.all.rp_filter"}, b1); err != nil {
		t.Fatal(err)
	}
	if got := read(t, sysctlDropIn); got != "<no existe>" {
		t.Errorf("el drop-in debería eliminarse, contiene:\n%s", got)
	}
	if got := read(t, filepath.Join(root, "proc/sys/net/ipv4/conf/all/rp_filter")); got != "0\n" {
		t.Errorf("runtime rp_filter restaurado = %q", got)
	}
}

func TestSysctlOptionalMissing(t *testing.T) {
	sandbox(t)
	st, err := sysctlSet{}.Capture(context.Background(), probes.Params{"key": "net.ipv6.conf.all.forwarding", "value": 0, "optional": true})
	if err != nil || !Skipped(st) {
		t.Fatalf("un parámetro opcional inexistente debe omitirse: %v %v", st, err)
	}
	if _, err := (sysctlSet{}).Capture(context.Background(), probes.Params{"key": "net.ipv6.conf.all.forwarding", "value": 0}); err == nil {
		t.Error("un parámetro obligatorio inexistente debe dar error")
	}
}

func TestFileKVSetCycle(t *testing.T) {
	root := sandbox(t)
	path := filepath.Join(root, "login.defs")
	orig := "# comentario\nPASS_MAX_DAYS\t99999\n#UMASK 077\nUMASK\t\t022\nPASS_MAX_DAYS 88\n"
	write(t, path, orig)
	r := fileKVSet{}
	b1 := cycle(t, r, probes.Params{"path": path, "key": "PASS_MAX_DAYS", "value": "365"})
	b2 := cycle(t, r, probes.Params{"path": path, "key": "UMASK", "value": "027"})
	got := read(t, path)
	want := "# comentario\nPASS_MAX_DAYS\t365\n#UMASK 077\nUMASK\t027\n"
	if got != want {
		t.Errorf("contenido:\n%q\nquiero:\n%q", got, want)
	}
	_ = r.Restore(context.Background(), probes.Params{"path": path}, b2)
	_ = r.Restore(context.Background(), probes.Params{"path": path}, b1)
	if got := read(t, path); got != orig {
		t.Errorf("tras restaurar:\n%q\nquiero el original:\n%q", got, orig)
	}
}

func TestFileModeCycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requiere root para chown")
	}
	root := sandbox(t)
	path := filepath.Join(root, "shadow")
	write(t, path, "x")
	os.Chmod(path, 0o666)
	r := fileMode{}
	b := cycle(t, r, probes.Params{"path": path, "mode": "0640", "owner": "root", "group": []any{"grupo-que-no-existe", "root"}})
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("modo %o", st.Mode().Perm())
	}
	if err := r.Restore(context.Background(), probes.Params{"path": path}, b); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Stat(path)
	if st.Mode().Perm() != 0o666 {
		t.Errorf("modo restaurado %o, quiero 666", st.Mode().Perm())
	}
}

func TestKmodBlockCycle(t *testing.T) {
	root := sandbox(t)
	r := kmodBlock{}
	b := cycle(t, r, probes.Params{"name": "modulo-de-prueba-bastion"})
	f := filepath.Join(root, "etc/modprobe.d/bastion-modulo-de-prueba-bastion.conf")
	if got := read(t, f); !strings.Contains(got, "install modulo-de-prueba-bastion /bin/false") || !strings.Contains(got, "blacklist modulo-de-prueba-bastion") {
		t.Errorf("fichero modprobe:\n%s", got)
	}
	if err := r.Restore(context.Background(), probes.Params{"name": "modulo-de-prueba-bastion"}, b); err != nil {
		t.Fatal(err)
	}
	if got := read(t, f); got != "<no existe>" {
		t.Error("el fichero debería eliminarse al restaurar")
	}
}

func TestSudoersDefaultsCycle(t *testing.T) {
	if _, err := exec.LookPath("visudo"); err != nil {
		t.Skip("visudo no disponible")
	}
	sandbox(t)
	r := sudoersDefaults{}
	// sudo-rs (Ubuntu 25.10+) no admite logfile: LNX-AUTH-007 exige sudo-classic.
	logfile := `logfile="/var/log/sudo.log"`
	if v, _ := exec.LookPath("visudo"); v != "" {
		if real, err := filepath.EvalSymlinks(v); err == nil && strings.Contains(real, "/cargo/") {
			logfile = "env_reset"
		}
	}
	b1 := cycle(t, r, probes.Params{"option": "use_pty"})
	b2 := cycle(t, r, probes.Params{"option": logfile})
	got := read(t, sudoersDropIn)
	if !strings.Contains(got, "Defaults use_pty\n") || !strings.Contains(got, "Defaults "+logfile+"\n") {
		t.Errorf("sudoers:\n%s", got)
	}
	if st, _ := os.Stat(sudoersDropIn); st.Mode().Perm() != 0o440 {
		t.Errorf("permisos de sudoers %o, quiero 440", st.Mode().Perm())
	}
	// Idempotente: aplicar otra vez no duplica la línea.
	_ = r.Apply(context.Background(), probes.Params{"option": "use_pty"})
	if n := strings.Count(read(t, sudoersDropIn), "Defaults use_pty"); n != 1 {
		t.Errorf("use_pty aparece %d veces", n)
	}
	_ = r.Restore(context.Background(), nil, b2)
	_ = r.Restore(context.Background(), nil, b1)
	if got := read(t, sudoersDropIn); got != "<no existe>" {
		t.Errorf("el drop-in de sudoers debería eliminarse, contiene:\n%s", got)
	}
}

func TestUpsertLine(t *testing.T) {
	in := "a 1\n# b 2\nb 3\nb 4\n"
	got := upsertLine(in, "b 9", func(l string) bool { return strings.Fields(l)[0] == "b" })
	if got != "a 1\n# b 2\nb 9\n" {
		t.Errorf("upsert = %q", got)
	}
	if got := upsertLine("", "x 1", func(string) bool { return false }); got != "x 1\n" {
		t.Errorf("upsert vacío = %q", got)
	}
}

// Las instantáneas antiguas (sin "path") restauran el drop-in anterior,
// 60-bastion.conf; una ruta ajena se rechaza.
func TestSysctlLegacyDropInRestore(t *testing.T) {
	root := sandbox(t)
	write(t, filepath.Join(root, "proc/sys/kernel/kptr_restrict"), "2\n")
	write(t, sysctlLegacyDropIn, "kernel.kptr_restrict = 2\n")
	old := State{"runtime": "0", "file": map[string]any{"exists": false}}
	if err := (sysctlSet{}).Restore(context.Background(), probes.Params{"key": "kernel.kptr_restrict"}, old); err != nil {
		t.Fatal(err)
	}
	if got := read(t, sysctlLegacyDropIn); got != "<no existe>" {
		t.Errorf("el drop-in antiguo debería eliminarse:\n%s", got)
	}
	bad := State{"runtime": "0", "path": "/etc/passwd", "file": map[string]any{"exists": false}}
	if err := (sysctlSet{}).Restore(context.Background(), probes.Params{"key": "kernel.kptr_restrict"}, bad); err == nil {
		t.Error("una ruta ajena en la instantánea debe rechazarse")
	}
	if !strings.HasSuffix(sysctlDropIn, "99-zz-bastion.conf") {
		t.Errorf("el drop-in debe cargarse el último: %s", sysctlDropIn)
	}
}
