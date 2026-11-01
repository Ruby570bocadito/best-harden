// Package platform detecta el sistema operativo, su rol y las etiquetas de
// plataforma con las que se seleccionan las reglas aplicables.
package platform

import (
	"os"
	"path"
	"runtime"
	"strings"
)

// Info describe el equipo auditado.
type Info struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Family       string `json:"family"`
	Distro       string `json:"distro,omitempty"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Build        string `json:"build,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Arch         string `json:"arch"`
	Role         string `json:"role"`
	DomainJoined bool   `json:"domain_joined"`
	Domain       string `json:"domain,omitempty"`
	EntraJoined  bool   `json:"entra_joined,omitempty"`
	Container    bool   `json:"container,omitempty"`
	IsAdmin      bool   `json:"is_admin"`
	// Tags va de la etiqueta más específica a la más general.
	Tags []string `json:"tags"`
}

// DisplayName devuelve el nombre del sistema con su versión sin repetirla.
func (i Info) DisplayName() string {
	if i.Version == "" || strings.Contains(i.Name, i.Version) {
		return i.Name
	}
	return i.Name + " " + i.Version
}

// Detect obtiene la información del equipo actual.
func Detect() Info {
	info := Info{OS: runtime.GOOS, Arch: runtime.GOARCH}
	info.Hostname, _ = os.Hostname()
	detect(&info)
	return info
}

// ParseOSRelease interpreta /etc/os-release.
func ParseOSRelease(text string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		m[k] = strings.Trim(v, `"'`)
	}
	return m
}

// containerSignals busca indicios de contenedor en /proc/1/cgroup (cgroup
// v1: docker, kubepods…), /proc/1/environ (container=, que fijan podman,
// systemd-nspawn y LXC) y el montaje de / en /proc/self/mountinfo: con
// cgroup v2 y su propio espacio de cgroups, /proc/1/cgroup es solo "0::/",
// pero la raíz sigue siendo un overlay del motor de contenedores.
func containerSignals(cgroup, mountinfo, environ string) bool {
	for _, k := range []string{"docker", "kubepods", "containerd", "libpod"} {
		if strings.Contains(cgroup, k) {
			return true
		}
	}
	for _, kv := range strings.Split(environ, "\x00") {
		if strings.HasPrefix(kv, "container=") {
			return true
		}
	}
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[4] != "/" || !strings.Contains(line, " - overlay ") {
			continue
		}
		for _, k := range []string{"/docker/", "/containers/", "containerd", "/lxc/", "buildkit"} {
			if strings.Contains(line, k) {
				return true
			}
		}
	}
	return false
}

// graphicalTarget indica si el destino por defecto de systemd es
// graphical.target, mirando el enlace del administrador y luego los de la
// distribución.
func graphicalTarget(readlink func(string) (string, error)) bool {
	for _, p := range []string{"/etc/systemd/system/default.target", "/usr/lib/systemd/system/default.target", "/lib/systemd/system/default.target"} {
		if target, err := readlink(p); err == nil {
			return strings.Contains(target, "graphical")
		}
	}
	return false
}

// Etiquetas de la implementación de sudo (campo requires de las reglas).
const (
	TagSudoClassic = "sudo-classic"
	TagSudoRS      = "sudo-rs"
)

// sudoImpl clasifica el binario de sudo: TagSudoRS o TagSudoClassic.
// resolved es su ruta ya resuelta y version, la primera línea de
// "sudo --version" (vacía si no se ha podido ejecutar). En Ubuntu (25.10 en
// adelante) basta la ruta: sudo-rs vive en /usr/lib/cargo/bin y se elige con
// update-alternatives. La versión cubre las distribuciones que instalan
// sudo-rs directamente como /usr/bin/sudo.
func sudoImpl(resolved, version string) string {
	if strings.Contains(resolved, "/cargo/") || strings.Contains(path.Base(resolved), "sudo-rs") ||
		strings.Contains(strings.ToLower(version), "sudo-rs") {
		return TagSudoRS
	}
	return TagSudoClassic
}

// linuxTags calcula las etiquetas a partir de ID e ID_LIKE de os-release.

func linuxTags(id, idLike string) []string {
	var tags []string
	add := func(t string) {
		for _, x := range tags {
			if x == t {
				return
			}
		}
		tags = append(tags, t)
	}
	norm := func(s string) string {
		switch s {
		case "rocky", "almalinux", "centos", "ol", "rhel":
			return "rhel"
		case "opensuse", "opensuse-leap", "sles", "suse":
			return "suse"
		}
		return s
	}
	if id != "" {
		add("linux-" + id)
		add("linux-" + norm(id))
	}
	for _, l := range strings.Fields(idLike) {
		add("linux-" + norm(l))
	}
	add("linux")
	return tags
}
