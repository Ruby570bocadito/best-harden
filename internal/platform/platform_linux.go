//go:build linux

package platform

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func detect(info *Info) {
	info.Family = "linux"
	info.IsAdmin = os.Geteuid() == 0
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		m := ParseOSRelease(string(b))
		info.Distro = m["ID"]
		info.Name = m["PRETTY_NAME"]
		info.Version = m["VERSION_ID"]
		info.Tags = linuxTags(m["ID"], m["ID_LIKE"])
	} else {
		info.Name = "Linux"
		info.Tags = []string{"linux"}
	}
	if impl := SudoImplementation(); impl != "" {
		info.Tags = append(info.Tags, impl)
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(b))
	}
	info.Container = InContainer()
	info.Role = "server"
	if isGraphical() {
		info.Role = "workstation"
	}
}

// SudoImplementation devuelve TagSudoRS o TagSudoClassic según el sudo del
// sistema, o "" si no hay sudo. Lo usan la detección de la plataforma y la
// remediación de sudoers (sudo-rs no admite todas las opciones).
var SudoImplementation = sync.OnceValue(func() string {
	sudo, err := filepath.EvalSymlinks("/usr/bin/sudo")
	if err != nil {
		return ""
	}
	if impl := sudoImpl(sudo, ""); impl == TagSudoRS {
		return impl
	}
	return sudoImpl(sudo, sudoVersion(sudo))
})

// sudoVersion devuelve la primera línea de "<sudo> --version" ("" si falla).
func sudoVersion(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return ""
	}
	first, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(first)
}

// InContainer detecta si Adarve se ejecuta dentro de un contenedor (los
// controles del kernel pertenecen entonces al host). Lo usan también los
// probes.
func InContainer() bool {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	read := func(p string) string {
		b, _ := os.ReadFile(p)
		return string(b)
	}
	// /proc/1/environ solo es legible como root; sin él quedan los demás.
	return containerSignals(read("/proc/1/cgroup"), read("/proc/self/mountinfo"), read("/proc/1/environ"))
}

// isGraphical considera estación de trabajo un equipo cuyo destino por
// defecto de systemd es graphical.target: el que fija el administrador en
// /etc o, si no lo ha cambiado, el de la distribución.
func isGraphical() bool {
	return graphicalTarget(os.Readlink)
}
