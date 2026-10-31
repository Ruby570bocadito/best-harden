//go:build linux

package probes

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Ruby570bocadito/adarve/internal/platform"
)

func init() {
	Register(sysctlProbe{})
	Register(fileProbe{})
	Register(sshdProbe{})
	Register(kmodProbe{})
	Register(systemdProbe{})
	Register(mountProbe{})
	Register(packageProbe{})
}

// inContainer detecta si Adarve se ejecuta dentro de un contenedor. En ese
// caso los controles del kernel pertenecen al host y no aplican.
var inContainer = platform.InContainer

// sysTool devuelve la ruta absoluta de una herramienta del sistema. Nunca
// se busca en el PATH, para que no se pueda suplantar.
func sysTool(name string) (string, bool) {
	for _, d := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
	}
	return "", false
}

// --- sysctl: parámetros del kernel en ejecución ----------------------------

type sysctlProbe struct{}

func (sysctlProbe) Name() string         { return "sysctl" }
func (sysctlProbe) DefaultField() string { return "value" }

func (sysctlProbe) Collect(_ context.Context, p Params) (Observation, error) {
	if err := p.Require("key"); err != nil {
		return Observation{}, err
	}
	key := p.String("key")
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	src := "sysctl " + key
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Observation{Found: false, Source: src}, nil
	}
	if err != nil {
		return Observation{}, err
	}
	return Observation{Found: true, Source: src, Fields: map[string]any{
		"value": strings.Join(strings.Fields(string(b)), " "),
	}}, nil
}

// --- file: existencia, permisos y propietario ------------------------------

type fileProbe struct{}

func (fileProbe) Name() string         { return "file" }
func (fileProbe) DefaultField() string { return "mode" }

func (fileProbe) Collect(_ context.Context, p Params) (Observation, error) {
	paths := p.Strings("path")
	if len(paths) == 0 {
		return Observation{}, errors.New("faltan parámetros: path")
	}
	// Con varias rutas se usa la primera que exista (p. ej. grub vs grub2).
	for _, path := range paths {
		st, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Observation{}, err
		}
		fields := map[string]any{
			"exists": true,
			"mode":   fmt.Sprintf("%04o", unixMode(st.Mode())),
			"type":   fileType(st.Mode()),
			"size":   st.Size(),
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			fields["uid"] = int(sys.Uid)
			fields["gid"] = int(sys.Gid)
			fields["owner"] = lookupUser(sys.Uid)
			fields["group"] = lookupGroup(sys.Gid)
		}
		return Observation{Found: true, Source: path, Fields: fields}, nil
	}
	return Observation{Found: false, Source: strings.Join(paths, " | ")}, nil
}

func unixMode(m fs.FileMode) uint32 {
	v := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		v |= 0o1000
	}
	return v
}

func fileType(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "dir"
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m.IsRegular():
		return "file"
	}
	return "other"
}

func lookupUser(uid uint32) string {
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		return u.Username
	}
	return strconv.Itoa(int(uid))
}

func lookupGroup(gid uint32) string {
	if g, err := user.LookupGroupId(strconv.Itoa(int(gid))); err == nil {
		return g.Name
	}
	return strconv.Itoa(int(gid))
}

// --- sshd: configuración EFECTIVA del servidor OpenSSH --------------------

type sshdProbe struct{}

func (sshdProbe) Name() string         { return "sshd" }
func (sshdProbe) DefaultField() string { return "value" }

type sshdConfig struct {
	values map[string]string
	source string
}

func (sshdProbe) Collect(ctx context.Context, p Params) (Observation, error) {
	if err := p.Require("key"); err != nil {
		return Observation{}, err
	}
	cfg, err := cached(ctx, "sshd", func() (sshdConfig, error) { return loadSSHD(ctx) })
	if err != nil {
		return Observation{}, err
	}
	key := strings.ToLower(p.String("key"))
	v, ok := cfg.values[key]
	src := cfg.source + " → " + key
	if !ok {
		return Observation{Found: false, Source: src}, nil
	}
	return Observation{Found: true, Source: src, Fields: map[string]any{"value": v}}, nil
}

func loadSSHD(ctx context.Context) (sshdConfig, error) {
	bin := ""
	for _, c := range []string{"/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"} {
		if _, err := os.Stat(c); err == nil {
			bin = c
			break
		}
	}
	const confPath = "/etc/ssh/sshd_config"
	_, confErr := os.Stat(confPath)
	if bin == "" && confErr != nil {
		return sshdConfig{}, NotApplicable("el servidor OpenSSH no está instalado")
	}
	// Preferimos "sshd -T": es la configuración que sshd usa de verdad,
	// incluidos los valores por defecto y los ficheros Include.
	if bin != "" {
		res, err := runCmd(ctx, bin, "-T")
		if err == nil && res.ExitCode == 0 && strings.Contains(res.Stdout, "permitrootlogin") {
			return sshdConfig{values: parseSSHDTest(res.Stdout), source: "sshd -T"}, nil
		}
	}
	read := func(path string) (string, error) {
		b, err := readFileLimited(path)
		return string(b), err
	}
	return sshdConfig{values: parseSSHDConfig(confPath, read, filepath.Glob), source: confPath}, nil
}

// --- kmod: módulos del kernel ----------------------------------------------

type kmodProbe struct{}

func (kmodProbe) Name() string         { return "kmod" }
func (kmodProbe) DefaultField() string { return "loaded" }

var modprobeDirs = []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/lib/modprobe.d", "/usr/lib/modprobe.d"}

func (kmodProbe) Collect(ctx context.Context, p Params) (Observation, error) {
	if err := p.Require("name"); err != nil {
		return Observation{}, err
	}
	if inContainer() {
		return Observation{}, NotApplicable("los módulos del kernel pertenecen al host (ejecución en contenedor)")
	}
	name := normModule(p.String("name"))

	loaded := false
	if b, err := os.ReadFile("/proc/modules"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) > 0 && normModule(f[0]) == name {
				loaded = true
				break
			}
		}
	}

	available, err := cached(ctx, "kmod-index", buildModuleIndex)
	if err != nil {
		return Observation{}, err
	}

	var texts []string
	for _, d := range modprobeDirs {
		files, _ := filepath.Glob(filepath.Join(d, "*.conf"))
		for _, f := range files {
			if b, err := readFileLimited(f); err == nil {
				texts = append(texts, string(b))
			}
		}
	}
	installDisabled, blacklisted, installCmd := modprobeDirectives(texts, name)

	return Observation{Found: true, Source: "módulo " + name, Fields: map[string]any{
		"loaded":           loaded,
		"available":        available[name],
		"install_disabled": installDisabled,
		"install_command":  installCmd,
		"blacklisted":      blacklisted,
	}}, nil
}

// buildModuleIndex recorre /lib/modules/<kernel> una vez por escaneo.
func buildModuleIndex() (map[string]bool, error) {
	idx := map[string]bool{}
	rel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return idx, nil
	}
	root := filepath.Join("/lib/modules", strings.TrimSpace(string(rel)))
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := d.Name()
		if i := strings.Index(base, ".ko"); i > 0 {
			idx[normModule(base[:i])] = true
		}
		return nil
	})
	return idx, nil
}

// --- systemd: estado de unidades -------------------------------------------

type systemdProbe struct{}

func (systemdProbe) Name() string         { return "systemd" }
func (systemdProbe) DefaultField() string { return "enabled" }

func (systemdProbe) Collect(ctx context.Context, p Params) (Observation, error) {
	if err := p.Require("unit"); err != nil {
		return Observation{}, err
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return Observation{}, NotApplicable("systemd no está en ejecución en este sistema")
	}
	unit := p.String("unit")
	systemctl, ok := sysTool("systemctl")
	if !ok {
		return Observation{}, NotApplicable("no se encontró systemctl")
	}
	res, err := runCmd(ctx, systemctl, "show", "--property=LoadState,ActiveState,UnitFileState", "--", unit)
	if err != nil {
		return Observation{}, err
	}
	props := map[string]string{}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	src := "systemctl " + unit
	if props["LoadState"] == "not-found" || props["LoadState"] == "" {
		return Observation{Found: false, Source: src}, nil
	}
	return Observation{Found: true, Source: src, Fields: map[string]any{
		"load_state": props["LoadState"],
		"active":     props["ActiveState"],
		"enabled":    props["UnitFileState"],
	}}, nil
}

// --- mount: opciones de montaje ----------------------------------------------

type mountProbe struct{}

func (mountProbe) Name() string         { return "mount" }
func (mountProbe) DefaultField() string { return "options" }

func (mountProbe) Collect(ctx context.Context, p Params) (Observation, error) {
	if err := p.Require("path"); err != nil {
		return Observation{}, err
	}
	entries, err := cached(ctx, "mountinfo", func() ([]mountEntry, error) {
		b, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			return nil, err
		}
		return parseMountinfo(string(b)), nil
	})
	if err != nil {
		return Observation{}, err
	}
	path := p.String("path")
	e, ok := findMount(entries, path)
	src := "mountinfo " + path
	if !ok {
		return Observation{Found: false, Source: src, Fields: map[string]any{"mounted": false}}, nil
	}
	opts := make([]any, len(e.Options))
	for i, o := range e.Options {
		opts[i] = o
	}
	return Observation{Found: true, Source: src, Fields: map[string]any{
		"mounted": true,
		"options": opts,
		"fstype":  e.FSType,
		"source":  e.Source,
	}}, nil
}

// --- package: paquetes instalados (dpkg / rpm) ------------------------------

type packageProbe struct{}

func (packageProbe) Name() string         { return "package" }
func (packageProbe) DefaultField() string { return "installed" }

func (packageProbe) Collect(ctx context.Context, p Params) (Observation, error) {
	if err := p.Require("name"); err != nil {
		return Observation{}, err
	}
	name := p.String("name")
	if dpkg, ok := sysTool("dpkg-query"); ok {
		res, err := runCmd(ctx, dpkg, "-W", "-f=${db:Status-Abbrev}|${Version}", "--", name)
		if err != nil {
			return Observation{}, err
		}
		status, ver, _ := strings.Cut(res.Stdout, "|")
		installed := res.ExitCode == 0 && strings.HasPrefix(status, "ii")
		return pkgObs("dpkg "+name, installed, ver), nil
	}
	if rpm, ok := sysTool("rpm"); ok {
		res, err := runCmd(ctx, rpm, "-q", "--qf", "%{VERSION}-%{RELEASE}", "--", name)
		if err != nil {
			return Observation{}, err
		}
		return pkgObs("rpm "+name, res.ExitCode == 0, strings.TrimSpace(res.Stdout)), nil
	}
	return Observation{}, NotApplicable("no se encontró dpkg ni rpm")
}

func pkgObs(src string, installed bool, ver string) Observation {
	if !installed {
		return Observation{Found: false, Source: src, Fields: map[string]any{"installed": false}}
	}
	return Observation{Found: true, Source: src, Fields: map[string]any{"installed": true, "version": ver}}
}
