//go:build linux

package remediate

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/probes"
)

func init() {
	Register(sysctlSet{})
	Register(sshdSet{})
	Register(kmodBlock{})
	Register(systemdDisable{})
	Register(fileMode{})
	Register(fileKVSet{})
	Register(sudoersDefaults{})
}

// Rutas de los ficheros drop-in que gestiona Adarve. Son variables para
// poder redirigirlas en los tests.
//
// Conservan el nombre de Bastion (el anterior de Adarve): las instantáneas
// de los equipos ya endurecidos apuntan a ellos, y con otro nombre "rollback"
// restauraría el fichero equivocado y quedarían dos drop-ins con los mismos
// ajustes.
//
// El drop-in de sysctl se llama 99-zz-bastion.conf para cargarse el ÚLTIMO
// (systemd-sysctl y "sysctl --system" ordenan por nombre todos los
// directorios; /etc/sysctl.conf llega como 99-sysctl.conf): así un valor
// contrario en otro fichero no deshace el ajuste al reiniciar. Las versiones
// anteriores usaban 60-bastion.conf; sus instantáneas guardan esa ruta.
var (
	sysctlDropIn       = "/etc/sysctl.d/99-zz-bastion.conf"
	sysctlLegacyDropIn = "/etc/sysctl.d/60-bastion.conf"
	procSys            = "/proc/sys"
	sshdConfig         = "/etc/ssh/sshd_config"
	sshdDropIn         = "/etc/ssh/sshd_config.d/00-bastion.conf"
	modprobeDir        = "/etc/modprobe.d"
	sudoersDropIn      = "/etc/sudoers.d/00-bastion"
)

const dropInHeader = "# Gestionado por Adarve (adarve harden). Para deshacer: adarve rollback\n"

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ---- estado de ficheros -------------------------------------------------

func captureFile(path string) (State, error) {
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{"exists": false}, nil
	}
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := State{"exists": true, "content": base64.StdEncoding.EncodeToString(b), "mode": float64(st.Mode().Perm())}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		s["uid"], s["gid"] = float64(sys.Uid), float64(sys.Gid)
	}
	return s, nil
}

func restoreFile(path string, s State) error {
	if s == nil {
		return nil
	}
	if exists, _ := s["exists"].(bool); !exists {
		err := os.Remove(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	content, err := base64.StdEncoding.DecodeString(fmt.Sprint(s["content"]))
	if err != nil {
		return err
	}
	mode := fs.FileMode(num(s["mode"]))
	uid, gid := -1, -1
	if _, ok := s["uid"]; ok {
		uid, gid = int(num(s["uid"])), int(num(s["gid"]))
	}
	return writeAtomic(path, content, mode, uid, gid)
}

// writeAtomic escribe en un temporal del mismo directorio y lo renombra.
// El propietario solo se fija como root: sin privilegios chown fallaría
// siempre y el fichero queda de todos modos a nombre de quien lo escribe
// (es lo que pasa en las pruebas, que no se ejecutan como root).
func writeAtomic(path string, content []byte, mode fs.FileMode, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".adarve-tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	if err == nil {
		err = f.Sync() // a disco antes de renombrar: un corte no deja el fichero vacío
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if uid >= 0 && os.Geteuid() == 0 {
		if err := os.Chown(tmp, uid, gid); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return os.Rename(tmp, path)
}

// existingModeOwner devuelve permisos y propietario actuales (o los dados).
func existingModeOwner(path string, def fs.FileMode) (fs.FileMode, int, int) {
	st, err := os.Stat(path)
	if err != nil {
		return def, 0, 0
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return st.Mode().Perm(), int(sys.Uid), int(sys.Gid)
	}
	return st.Mode().Perm(), -1, -1
}

// upsertLine sustituye las líneas activas cuya clave coincide (match) por
// line, o la añade al final. Devuelve el contenido nuevo.
func upsertLine(content, line string, match func(string) bool) string {
	var out []string
	replaced := false
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if content == "" {
		lines = nil
	}
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") && match(t) {
			if !replaced {
				out = append(out, line)
				replaced = true
			}
			continue // duplicados activos: se eliminan
		}
		out = append(out, l)
	}
	if !replaced {
		out = append(out, line)
	}
	return strings.Join(out, "\n") + "\n"
}

func readOrHeader(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return dropInHeader
	}
	return string(b)
}

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case uint32:
		return float64(x)
	case int64:
		return float64(x)
	}
	f, _ := strconv.ParseFloat(fmt.Sprint(v), 64)
	return f
}

// ---- sysctl.set -----------------------------------------------------------

type sysctlSet struct{}

func (sysctlSet) Type() string { return "sysctl.set" }

func sysctlPath(key string) string { return filepath.Join(procSys, strings.ReplaceAll(key, ".", "/")) }

func (sysctlSet) Capture(_ context.Context, p probes.Params) (State, error) {
	key := p.String("key")
	b, err := os.ReadFile(sysctlPath(key))
	if errors.Is(err, fs.ErrNotExist) {
		if p.Bool("optional", false) {
			return skipState("el parámetro " + key + " no existe en este kernel"), nil
		}
		return nil, fmt.Errorf("el parámetro %s no existe", key)
	}
	if err != nil {
		return nil, err
	}
	file, err := captureFile(sysctlDropIn)
	if err != nil {
		return nil, err
	}
	return State{"runtime": strings.Join(strings.Fields(string(b)), " "), "file": map[string]any(file), "path": sysctlDropIn}, nil
}

// sysctlFileOf devuelve el drop-in que se capturó en before (las instantáneas
// antiguas no lo guardan: era 60-bastion.conf). Solo admite esos dos.
func sysctlFileOf(before State) (string, error) {
	p, _ := before["path"].(string)
	switch p {
	case "":
		return sysctlLegacyDropIn, nil
	case sysctlDropIn, sysctlLegacyDropIn:
		return p, nil
	}
	return "", fmt.Errorf("drop-in de sysctl desconocido en la instantánea: %q", p)
}

func (sysctlSet) Describe(p probes.Params, before State) string {
	if Skipped(before) {
		return fmt.Sprintf("sysctl %s: %s (se omite)", p.String("key"), before["reason"])
	}
	return fmt.Sprintf("sysctl %s: %s → %s  (%s)", p.String("key"), textOf(before["runtime"]), p.String("value"), sysctlDropIn)
}

func (sysctlSet) Apply(_ context.Context, p probes.Params) error {
	key, val := p.String("key"), p.String("value")
	if _, err := os.Stat(sysctlPath(key)); errors.Is(err, fs.ErrNotExist) && p.Bool("optional", false) {
		return nil
	}
	content := upsertLine(readOrHeader(sysctlDropIn), key+" = "+val, func(l string) bool {
		k, _, ok := strings.Cut(l, "=")
		return ok && strings.TrimSpace(k) == key
	})
	if err := writeAtomic(sysctlDropIn, []byte(content), 0o644, 0, 0); err != nil {
		return err
	}
	return os.WriteFile(sysctlPath(key), []byte(val+"\n"), 0o644)
}

func (sysctlSet) Restore(_ context.Context, p probes.Params, before State) error {
	if Skipped(before) {
		return nil
	}
	if f, ok := before["file"].(map[string]any); ok {
		path, err := sysctlFileOf(before)
		if err != nil {
			return err
		}
		if err := restoreFile(path, State(f)); err != nil {
			return err
		}
	}
	if rt, ok := before["runtime"].(string); ok {
		return os.WriteFile(sysctlPath(p.String("key")), []byte(rt+"\n"), 0o644)
	}
	return nil
}

// ---- sshd.set ------------------------------------------------------------------

type sshdSet struct{}

func (sshdSet) Type() string { return "sshd.set" }

var reSSHDInclude = regexp.MustCompile(`(?mi)^\s*Include\s+.*sshd_config\.d`)

func sshdBinary() string {
	for _, c := range []string{"/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func (sshdSet) Capture(_ context.Context, p probes.Params) (State, error) {
	if sshdBinary() == "" {
		return nil, errors.New("el servidor OpenSSH no está instalado")
	}
	return captureFile(sshdDropIn)
}

func (sshdSet) Describe(p probes.Params, _ State) string {
	return fmt.Sprintf("sshd %s → %s  (%s)", p.String("key"), p.String("value"), sshdDropIn)
}

func (s sshdSet) Apply(ctx context.Context, p probes.Params) error {
	main, err := os.ReadFile(sshdConfig)
	if err != nil {
		return err
	}
	if !reSSHDInclude.Match(main) {
		return fmt.Errorf("%s no incluye sshd_config.d/*.conf: añade la directiva Include o aplica el cambio a mano", sshdConfig)
	}
	before, err := captureFile(sshdDropIn)
	if err != nil {
		return err
	}
	key := p.String("key")
	content := upsertLine(readOrHeader(sshdDropIn), key+" "+p.String("value"), func(l string) bool {
		f := strings.Fields(l)
		return len(f) > 0 && strings.EqualFold(f[0], key)
	})
	if err := writeAtomic(sshdDropIn, []byte(content), 0o600, 0, 0); err != nil {
		return err
	}
	if err := reloadSSHD(ctx); err != nil {
		_ = restoreFile(sshdDropIn, before)
		return err
	}
	return nil
}

// Restore vuelve a dejar el drop-in como estaba. Lo que cuenta es el
// fichero: si después no se puede recargar sshd, el rollback no queda a
// medias (esa configuración ya era la del sistema antes del cambio, y sshd
// la leerá al arrancar).
func (sshdSet) Restore(ctx context.Context, _ probes.Params, before State) error {
	if err := restoreFile(sshdDropIn, before); err != nil {
		return err
	}
	_ = reloadSSHD(ctx)
	return nil
}

// privSepDir es el directorio de separación de privilegios de sshd. Lo crea
// la unidad de systemd al arrancar (RuntimeDirectory=sshd): con el servicio
// parado o activado por socket (Ubuntu 22.10 en adelante) no existe y
// "sshd -t" falla aunque la configuración sea correcta.
const privSepDir = "/run/sshd"

// sshdTestScript monta un /run temporal y vacío, crea en él el directorio de
// separación de privilegios y ejecuta "sshd -t". Las rutas llegan como
// argumentos ($1 mount, $2 mkdir, $3 sshd), nunca dentro del script.
const sshdTestScript = `"$1" -t tmpfs -o mode=0755 tmpfs /run && "$2" -m 0755 /run/sshd && exec "$3" -t`

// validateSSHD comprueba la configuración con "sshd -t". Si falla solo
// porque falta privSepDir, la comprueba de nuevo en un espacio de montaje
// privado (unshare) con un /run temporal: sshd encuentra su directorio y el
// sistema no cambia (crearlo de verdad dejaría un cambio fuera de la
// instantánea y haría que los escaneos leyeran sshd de otra forma).
func validateSSHD(ctx context.Context) error {
	out, err := run(ctx, sshdBinary(), "-t")
	if err != nil && strings.Contains(out, "privilege separation directory") {
		if _, serr := os.Stat(privSepDir); errors.Is(serr, fs.ErrNotExist) {
			_, err = sshdTestIsolated(ctx)
		}
	}
	if err != nil {
		return fmt.Errorf("la configuración de sshd no es válida: %w", err)
	}
	return nil
}

// sshdTestIsolated ejecuta "sshd -t" con un /run temporal en un espacio de
// montaje privado: el montaje no se propaga al sistema.
func sshdTestIsolated(ctx context.Context) (string, error) {
	unshare := firstExisting([]string{"/usr/bin/unshare", "/bin/unshare"})
	sh := firstExisting([]string{"/bin/sh", "/usr/bin/sh"})
	mount := firstExisting([]string{"/usr/bin/mount", "/bin/mount"})
	mkdir := firstExisting([]string{"/usr/bin/mkdir", "/bin/mkdir"})
	if unshare == "" || sh == "" || mount == "" || mkdir == "" {
		return "", fmt.Errorf("falta %s y no se puede comprobar sin él (se necesitan unshare, sh, mount y mkdir)", privSepDir)
	}
	return run(ctx, unshare, "--mount", "--propagation", "private", sh, "-c", sshdTestScript, "sshd-t", mount, mkdir, sshdBinary())
}

// reloadSSHD valida la configuración y recarga sshd si está en marcha. Si
// está parado (o se activa por socket), no se arranca: la configuración se
// aplicará en su próximo inicio.
func reloadSSHD(ctx context.Context) error {
	if err := validateSSHD(ctx); err != nil {
		return err
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil // sin systemd: el cambio se aplicará al reiniciar sshd
	}
	var last error
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		if _, err := run(ctx, "systemctl", "try-reload-or-restart", unit); err == nil {
			return nil
		} else {
			last = err
		}
	}
	return fmt.Errorf("no se pudo recargar sshd: %w", last)
}

// ---- kmod.block -------------------------------------------------------------

type kmodBlock struct{}

func (kmodBlock) Type() string { return "kmod.block" }

func kmodFile(name string) string { return filepath.Join(modprobeDir, "bastion-"+name+".conf") }

func moduleLoaded(name string) bool {
	b, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	want := strings.ReplaceAll(name, "-", "_")
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == want {
			return true
		}
	}
	return false
}

func (kmodBlock) Capture(_ context.Context, p probes.Params) (State, error) {
	f, err := captureFile(kmodFile(p.String("name")))
	if err != nil {
		return nil, err
	}
	return State{"file": map[string]any(f), "loaded": moduleLoaded(p.String("name"))}, nil
}

func (kmodBlock) Describe(p probes.Params, _ State) string {
	return fmt.Sprintf("módulo %s: bloquear carga  (%s)", p.String("name"), kmodFile(p.String("name")))
}

func (kmodBlock) Apply(ctx context.Context, p probes.Params) error {
	name := p.String("name")
	content := fmt.Sprintf("%sinstall %s /bin/false\nblacklist %s\n", dropInHeader, name, name)
	if err := writeAtomic(kmodFile(name), []byte(content), 0o644, 0, 0); err != nil {
		return err
	}
	if moduleLoaded(name) {
		_, _ = run(ctx, "modprobe", "-r", name) // si está en uso, quedará bloqueado tras reiniciar
	}
	return nil
}

func (kmodBlock) Restore(ctx context.Context, p probes.Params, before State) error {
	if f, ok := before["file"].(map[string]any); ok {
		if err := restoreFile(kmodFile(p.String("name")), State(f)); err != nil {
			return err
		}
	}
	if loaded, _ := before["loaded"].(bool); loaded {
		_, _ = run(ctx, "modprobe", p.String("name"))
	}
	return nil
}

// ---- systemd.disable ------------------------------------------------------------

type systemdDisable struct{}

func (systemdDisable) Type() string { return "systemd.disable" }

func unitState(ctx context.Context, unit string) (map[string]string, error) {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil, errors.New("systemd no está en ejecución")
	}
	out, err := run(ctx, "systemctl", "show", "--property=LoadState,ActiveState,UnitFileState", "--", unit)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			m[k] = v
		}
	}
	return m, nil
}

func (systemdDisable) Capture(ctx context.Context, p probes.Params) (State, error) {
	m, err := unitState(ctx, p.String("unit"))
	if err != nil {
		return nil, err
	}
	if m["LoadState"] == "not-found" {
		return skipState("la unidad " + p.String("unit") + " no existe"), nil
	}
	return State{"enabled": m["UnitFileState"], "active": m["ActiveState"]}, nil
}

func (systemdDisable) Describe(p probes.Params, before State) string {
	if Skipped(before) {
		return fmt.Sprintf("%s (se omite)", before["reason"])
	}
	verb := "deshabilitar y detener"
	if p.Bool("mask", false) {
		verb = "enmascarar y detener"
	}
	return fmt.Sprintf("systemd %s: %s/%s → %s", p.String("unit"), textOf(before["enabled"]), textOf(before["active"]), verb)
}

func (systemdDisable) Apply(ctx context.Context, p probes.Params) error {
	m, err := unitState(ctx, p.String("unit"))
	if err != nil {
		return err
	}
	if m["LoadState"] == "not-found" {
		return nil
	}
	verb := "disable"
	if p.Bool("mask", false) {
		verb = "mask"
	}
	_, err = run(ctx, "systemctl", verb, "--now", "--", p.String("unit"))
	return err
}

func (systemdDisable) Restore(ctx context.Context, p probes.Params, before State) error {
	if Skipped(before) {
		return nil
	}
	unit := p.String("unit")
	if p.Bool("mask", false) {
		if _, err := run(ctx, "systemctl", "unmask", "--", unit); err != nil {
			return err
		}
	}
	if before["enabled"] == "enabled" {
		if _, err := run(ctx, "systemctl", "enable", "--", unit); err != nil {
			return err
		}
	}
	if before["active"] == "active" {
		_, err := run(ctx, "systemctl", "start", "--", unit)
		return err
	}
	return nil
}

// ---- file.mode -------------------------------------------------------------------

type fileMode struct{}

func (fileMode) Type() string { return "file.mode" }

func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (fileMode) Capture(_ context.Context, p probes.Params) (State, error) {
	path := firstExisting(p.Strings("path"))
	if path == "" {
		return skipState("no existe " + strings.Join(p.Strings("path"), " ni ")), nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	s := State{"path": path, "mode": float64(st.Mode().Perm())}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		s["uid"], s["gid"] = float64(sys.Uid), float64(sys.Gid)
	}
	return s, nil
}

func (fileMode) Describe(p probes.Params, before State) string {
	if Skipped(before) {
		return fmt.Sprintf("%s (se omite)", before["reason"])
	}
	target := p.String("mode")
	if o := p.Strings("owner"); len(o) > 0 {
		target += " " + o[0]
		if g := p.Strings("group"); len(g) > 0 {
			target += ":" + g[0]
		}
	}
	return fmt.Sprintf("permisos %s: %04o → %s", before["path"], int(num(before["mode"])), target)
}

func lookupGroupFirst(names []string) (int, bool) {
	for _, n := range names {
		if g, err := user.LookupGroup(n); err == nil {
			id, _ := strconv.Atoi(g.Gid)
			return id, true
		}
	}
	return -1, false
}

func (fileMode) Apply(_ context.Context, p probes.Params) error {
	path := firstExisting(p.Strings("path"))
	if path == "" {
		return nil
	}
	mode, err := strconv.ParseUint(p.String("mode"), 8, 32)
	if err != nil {
		return err
	}
	uid, gid := -1, -1
	if owners := p.Strings("owner"); len(owners) > 0 {
		u, err := user.Lookup(owners[0])
		if err != nil {
			return err
		}
		uid, _ = strconv.Atoi(u.Uid)
	}
	if groups := p.Strings("group"); len(groups) > 0 {
		g, ok := lookupGroupFirst(groups)
		if !ok {
			return fmt.Errorf("no existe ninguno de los grupos %v", groups)
		}
		gid = g
	}
	if uid >= 0 || gid >= 0 {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, fs.FileMode(mode))
}

func (fileMode) Restore(_ context.Context, _ probes.Params, before State) error {
	if Skipped(before) {
		return nil
	}
	path := fmt.Sprint(before["path"])
	if _, ok := before["uid"]; ok {
		if err := os.Chown(path, int(num(before["uid"])), int(num(before["gid"]))); err != nil {
			return err
		}
	}
	return os.Chmod(path, fs.FileMode(num(before["mode"])))
}

// ---- file.kv_set ---------------------------------------------------------------------

type fileKVSet struct{}

func (fileKVSet) Type() string { return "file.kv_set" }

func (fileKVSet) Capture(_ context.Context, p probes.Params) (State, error) {
	return captureFile(p.String("path"))
}

func (fileKVSet) Describe(p probes.Params, before State) string {
	old := "(no definido)"
	if b, err := base64.StdEncoding.DecodeString(fmt.Sprint(before["content"])); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == p.String("key") {
				old = strings.Join(f[1:], " ")
			}
		}
	}
	return fmt.Sprintf("%s: %s %s → %s", p.String("path"), p.String("key"), old, p.String("value"))
}

func (fileKVSet) Apply(_ context.Context, p probes.Params) error {
	path, key, sep := p.String("path"), p.String("key"), p.String("separator")
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if sep == "" {
		sep = "\t"
	}
	content := upsertLine(string(b), key+sep+p.String("value"), func(l string) bool {
		if strings.TrimSpace(sep) == "" {
			f := strings.Fields(l)
			return len(f) > 0 && f[0] == key
		}
		k, _, ok := strings.Cut(l, strings.TrimSpace(sep))
		return ok && strings.TrimSpace(k) == key
	})
	mode, uid, gid := existingModeOwner(path, 0o644)
	return writeAtomic(path, []byte(content), mode, uid, gid)
}

func (fileKVSet) Restore(_ context.Context, p probes.Params, before State) error {
	return restoreFile(p.String("path"), before)
}

// ---- sudoers.defaults --------------------------------------------------------------------

type sudoersDefaults struct{}

func (sudoersDefaults) Type() string { return "sudoers.defaults" }

func (sudoersDefaults) Capture(_ context.Context, _ probes.Params) (State, error) {
	if _, err := exec.LookPath("visudo"); err != nil {
		return nil, errors.New("visudo no está disponible (¿sudo instalado?)")
	}
	return captureFile(sudoersDropIn)
}

func (sudoersDefaults) Describe(p probes.Params, _ State) string {
	return fmt.Sprintf("sudoers: Defaults %s  (%s)", p.String("option"), sudoersDropIn)
}

func (sudoersDefaults) Apply(ctx context.Context, p probes.Params) error {
	before, err := captureFile(sudoersDropIn)
	if err != nil {
		return err
	}
	line := "Defaults " + p.String("option")
	content := readOrHeader(sudoersDropIn)
	if !bytes.Contains([]byte(content), []byte(line+"\n")) {
		content = strings.TrimRight(content, "\n") + "\n" + line + "\n"
	}
	if err := writeAtomic(sudoersDropIn, []byte(content), 0o440, 0, 0); err != nil {
		return err
	}
	// Un sudoers inválido puede dejar el sistema sin sudo: se valida y,
	// si falla, se restaura de inmediato.
	if _, err := run(ctx, "visudo", "-c", "-q", "-f", sudoersDropIn); err != nil {
		_ = restoreFile(sudoersDropIn, before)
		return fmt.Errorf("sudoers inválido, cambio deshecho: %w", err)
	}
	return nil
}

func (sudoersDefaults) Restore(_ context.Context, _ probes.Params, before State) error {
	return restoreFile(sudoersDropIn, before)
}
