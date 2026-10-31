//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"strings"
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
	if sudo, err := filepath.EvalSymlinks("/usr/bin/sudo"); err == nil && sudoClassic(sudo) {
		info.Tags = append(info.Tags, "sudo-classic")
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
