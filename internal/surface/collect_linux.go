//go:build linux

package surface

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Collect recoge el inventario en Linux leyendo /proc y /etc; con root,
// también el firewall (nft e iptables-save, de solo lectura).
func Collect(ctx context.Context) (Inventory, error) {
	var inv Inventory
	var socks []procSocket
	for _, src := range []struct {
		file, proto string
		v6          bool
	}{{"tcp", "tcp", false}, {"tcp6", "tcp", true}, {"udp", "udp", false}, {"udp6", "udp", true}} {
		b, err := os.ReadFile("/proc/net/" + src.file)
		if err != nil {
			continue // sin IPv6, p. ej.
		}
		socks = append(socks, parseProcNet(string(b), src.proto, src.v6)...)
	}
	lo, hi := ephemeralRange()
	owners, complete := socketOwners()
	if !complete {
		inv.Notes = append(inv.Notes, "Sin root no se ven los procesos de otros usuarios: ejecuta con sudo para saber qué proceso abre cada puerto.")
	}
	for _, s := range socks {
		l := s.Listener
		l.Ephemeral = l.Proto == "udp" && ephemeralUDP(l.Port, lo, hi)
		if pid, ok := owners[s.inode]; ok {
			l.PID = pid
			l.Process = processName(pid)
		}
		inv.Listeners = append(inv.Listeners, l)
	}
	collectPackages(ctx, &inv)

	if b, err := os.ReadFile("/etc/exports"); err == nil {
		inv.Shares = append(inv.Shares, parseExports(string(b))...)
	}
	extra, _ := filepath.Glob("/etc/exports.d/*.exports")
	for _, f := range extra {
		if b, err := os.ReadFile(f); err == nil {
			inv.Shares = append(inv.Shares, parseExports(string(b))...)
		}
	}
	if b, err := os.ReadFile("/etc/samba/smb.conf"); err == nil {
		inv.Shares = append(inv.Shares, parseSmbConf(string(b))...)
	}

	passwd, err1 := os.ReadFile("/etc/passwd")
	group, err2 := os.ReadFile("/etc/group")
	if err1 == nil && err2 == nil {
		inv.Admins = parseLinuxAdmins(string(passwd), string(group))
	}

	if os.Geteuid() != 0 {
		inv.Notes = append(inv.Notes, "Sin root no se puede leer el firewall (nftables, iptables): ejecuta con sudo para saber qué puertos filtra.")
	} else if fw, err := collectNetfilter(ctx); err != nil {
		inv.Notes = append(inv.Notes, "No se pudo leer el firewall: los puertos se muestran sin filtrar. "+err.Error())
	} else {
		inv.Firewall = fw
		if u := fw.Uncovered(); len(u) > 0 {
			inv.Notes = append(inv.Notes, "Hay reglas que descartan tráfico antes de la cadena de entrada y no se evalúan ("+
				strings.Join(u, ", ")+"): algún puerto puede aparecer accesible sin estarlo.")
		}
	}
	return inv, nil
}

// collectNetfilter lee el firewall del kernel. ufw y firewalld no tienen
// reglas propias: generan las de nftables o iptables, que son las que se
// aplican. iptables-save da más detalle de las tablas de iptables-nft
// (multiport, conntrack…) que nft, que las muestra opacas.
func collectNetfilter(ctx context.Context) (*Firewall, error) {
	nft, nftErr := runTool(ctx, "nft", "-j", "list", "ruleset")
	save4, err4 := runTool(ctx, "iptables-save")
	save6, _ := runTool(ctx, "ip6tables-save")
	if nftErr != nil && err4 != nil {
		return nil, errors.New("no se encontró nft ni iptables-save, o no respondieron: " + nftErr.Error())
	}
	return newLinuxFirewall(nft, string(save4), string(save6))
}

// toolPath busca una herramienta del sistema primero en los directorios
// del sistema (sudo puede no tener /usr/sbin en el PATH, y un PATH ajeno
// podría suplantarla) y solo después en el PATH.
func toolPath(name string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if fi, e := os.Stat(filepath.Join(dir, name)); e == nil && !fi.IsDir() {
			return filepath.Join(dir, name), nil
		}
	}
	return exec.LookPath(name)
}

// runTool ejecuta una herramienta del sistema y falla si termina con error.
func runTool(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, code, err := runToolCode(ctx, name, args...)
	if err == nil && code != 0 {
		err = fmt.Errorf("%s terminó con el código %d", name, code)
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// runToolCode ejecuta una herramienta del sistema y devuelve su salida y su
// código de salida (dpkg-query y rpm terminan con 1 si algún fichero no es
// de ningún paquete, pero la salida de los demás vale).
func runToolCode(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	path, err := toolPath(name)
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	cmd.Stdout = &out
	err = cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil {
		return out.Bytes(), exitErr.ExitCode(), nil
	}
	return out.Bytes(), 0, err
}

// collectPackages anota la ruta del ejecutable de cada proceso que escucha
// en la red y el paquete que lo instala. Lo que no es de ningún paquete no
// recibe actualizaciones de seguridad con el sistema.
func collectPackages(ctx context.Context, inv *Inventory) {
	paths := map[int]string{}
	var list []string
	seen := map[string]bool{}
	for i := range inv.Listeners {
		l := &inv.Listeners[i]
		if l.Scope != ScopeNetwork || l.Ephemeral || l.PID <= 0 {
			continue
		}
		p, ok := paths[l.PID]
		if !ok {
			p = exePath(l.PID)
			paths[l.PID] = p
		}
		l.Path = p
		if p != "" && !seen[p] {
			seen[p] = true
			list = append(list, p)
		}
	}
	if len(list) == 0 {
		return
	}
	owners := packageOwners(ctx, list)
	if owners == nil {
		return // sin gestor de paquetes conocido
	}
	modified := modifiedFiles(ctx, owners)
	for i := range inv.Listeners {
		l := &inv.Listeners[i]
		if l.Path == "" {
			continue
		}
		switch pkg, ok := owners[l.Path]; {
		case ok && modified[l.Path]:
			l.Signature, l.Signer = SigModified, pkg
		case ok:
			l.Signature, l.Signer = SigPackage, pkg
		default:
			l.Signature = SigNoPackage
		}
	}
}

// modifiedFiles devuelve las rutas de owners cuyo contenido ya no coincide
// con la suma que registró su paquete (dpkg --verify o rpm -V). Ser de un
// paquete no basta: un binario sustituido sigue «perteneciendo» a él.
func modifiedFiles(ctx context.Context, owners map[string]string) map[string]bool {
	var pkgs []string
	seen := map[string]bool{}
	for _, pkg := range owners {
		if !seen[pkg] && !strings.HasPrefix(pkg, "snap ") {
			seen[pkg] = true
			pkgs = append(pkgs, pkg)
		}
	}
	if len(pkgs) == 0 {
		return nil
	}
	var out []byte
	var err error
	switch {
	case hasTool("dpkg"):
		out, _, err = runToolCode(ctx, "dpkg", append([]string{"--verify", "--"}, pkgs...)...)
	case hasTool("rpm"):
		out, _, err = runToolCode(ctx, "rpm", append([]string{"-V", "--"}, pkgs...)...)
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	changed := parseVerify(string(out))
	modified := map[string]bool{}
	for p := range owners {
		// dpkg puede tener el fichero como /bin/x con /usr fusionado.
		if changed[p] || changed[usrMergeAlt(p)] {
			modified[p] = true
		}
	}
	return modified
}

// exePath es la ruta del ejecutable de un proceso. Vacía si no se puede
// leer (sin root, los de otros usuarios) o si el proceso está en un
// contenedor o un chroot: su ruta no es la del sistema y sus paquetes no
// son los del equipo.
func exePath(pid int) string {
	proc := "/proc/" + strconv.Itoa(pid)
	self, err1 := os.Readlink("/proc/self/ns/mnt")
	ns, err2 := os.Readlink(proc + "/ns/mnt")
	root, err3 := os.Readlink(proc + "/root")
	if err1 != nil || err2 != nil || err3 != nil || ns != self || root != "/" {
		return ""
	}
	p, err := os.Readlink(proc + "/exe")
	if err != nil {
		return ""
	}
	// Un binario sustituido por una actualización sigue en memoria.
	return strings.TrimSuffix(p, " (deleted)")
}

// packageOwners devuelve el paquete de cada ruta que pertenece a alguno, o
// nil si el sistema no tiene un gestor de paquetes conocido.
func packageOwners(ctx context.Context, paths []string) map[string]string {
	owners := map[string]string{}
	var rest []string
	for _, p := range paths {
		if s := snapName(p); s != "" {
			owners[p] = "snap " + s
		} else {
			rest = append(rest, p)
		}
	}
	if len(rest) == 0 {
		return owners
	}
	switch {
	case hasTool("dpkg-query"):
		out, _, err := runToolCode(ctx, "dpkg-query", append([]string{"-S", "--"}, rest...)...)
		if err != nil {
			return nil
		}
		found := parseDpkgSearch(string(out))
		// Con /usr fusionado, dpkg puede tener el fichero como /bin/x.
		alt := map[string]string{}
		var alts []string
		for _, p := range rest {
			if a := usrMergeAlt(p); a != "" && found[p] == "" {
				alt[a] = p
				alts = append(alts, a)
			}
		}
		if len(alts) > 0 {
			if out, _, err := runToolCode(ctx, "dpkg-query", append([]string{"-S", "--"}, alts...)...); err == nil {
				for a, pkg := range parseDpkgSearch(string(out)) {
					if p, ok := alt[a]; ok {
						found[p] = pkg
					}
				}
			}
		}
		for _, p := range rest {
			if pkg := found[p]; pkg != "" {
				owners[p] = pkg
			}
		}
	case hasTool("rpm"):
		for _, p := range rest {
			out, code, err := runToolCode(ctx, "rpm", "-qf", "--qf", "%{NAME}\n", "--", p)
			if err != nil {
				return nil
			}
			if pkgs := parseRpmQuery([]string{p}, strings.SplitN(string(out), "\n", 2)[0]); code == 0 && pkgs[p] != "" {
				owners[p] = pkgs[p]
			}
		}
	case hasTool("pacman"):
		for _, p := range rest {
			out, code, err := runToolCode(ctx, "pacman", "-Qqo", "--", p)
			if err != nil {
				return nil
			}
			if name := strings.TrimSpace(string(out)); code == 0 && name != "" && !strings.Contains(name, " ") {
				owners[p] = name
			}
		}
	default:
		return nil
	}
	return owners
}

func hasTool(name string) bool {
	_, err := toolPath(name)
	return err == nil
}

// socketOwners asocia el inodo de cada socket con el PID que lo tiene
// abierto. complete es false si algún proceso no se pudo inspeccionar.
func socketOwners() (map[string]int, bool) {
	owners := map[string]int{}
	complete := true
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return owners, false
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				complete = false
			}
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, ok := owners[inode]; !ok {
				owners[inode] = pid
			}
		}
	}
	return owners, complete
}

// ephemeralRange es el rango de puertos locales que el kernel asigna a los
// clientes (net.ipv4.ip_local_port_range; por defecto 32768-60999).
func ephemeralRange() (int, int) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err == nil {
		if f := strings.Fields(string(b)); len(f) == 2 {
			lo, err1 := strconv.Atoi(f[0])
			hi, err2 := strconv.Atoi(f[1])
			if err1 == nil && err2 == nil && lo > 0 && hi >= lo {
				return lo, hi
			}
		}
	}
	return 32768, 60999
}

func processName(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
