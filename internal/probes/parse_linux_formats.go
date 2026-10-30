package probes

// Parsers puros de formatos Linux. Están separados de los probes (que llevan
// build tag) para poder probarlos en cualquier plataforma.

import (
	"bufio"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// --- sshd ---------------------------------------------------------------

// sshdTimeKeys son opciones de sshd cuyo valor es un tiempo ("1m30s").
var sshdTimeKeys = map[string]bool{"logingracetime": true, "clientaliveinterval": true}

// sshdAlgoKeys son listas de algoritmos que admiten los prefijos "+" (añadir
// a los de por defecto), "-" (quitar) y "^" (poner delante).
var sshdAlgoKeys = map[string]bool{
	"kexalgorithms": true, "ciphers": true, "macs": true, "hostkeyalgorithms": true,
	"pubkeyacceptedalgorithms": true, "pubkeyacceptedkeytypes": true,
	"hostbasedacceptedalgorithms": true, "casignaturealgorithms": true,
}

// parseSSHDTest interpreta la salida de "sshd -T" (clave valor, en minúsculas).
// Las claves repetidas (hostkey, listenaddress) se unen con comas.
func parseSSHDTest(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, _ := strings.Cut(line, " ")
		k = strings.ToLower(k)
		v = strings.TrimSpace(v)
		if prev, ok := m[k]; ok {
			m[k] = prev + "," + v
		} else {
			m[k] = v
		}
	}
	return m
}

// sshdConfigReader abstrae la lectura de ficheros para poder probar.
type sshdConfigReader func(path string) (string, error)

// parseSSHDConfig interpreta sshd_config siguiendo las reglas de OpenSSH:
// gana la PRIMERA aparición de cada clave, se siguen los Include (con globs,
// relativos a /etc/ssh) y se ignoran los bloques Match, que solo aplican a
// conexiones concretas.
func parseSSHDConfig(file string, read sshdConfigReader, glob func(string) ([]string, error)) map[string]string {
	m := map[string]string{}
	seen := map[string]bool{}
	// Ficheros de la cadena de Include en curso: un fichero que se incluye a
	// sí mismo (directa o indirectamente) se recorrería de forma exponencial.
	open := map[string]bool{}
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		if depth > 8 || open[p] {
			return
		}
		open[p] = true
		defer delete(open, p)
		text, err := read(p)
		if err != nil {
			return
		}
		sc := bufio.NewScanner(strings.NewReader(text))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v := splitSSHDLine(line)
			k = strings.ToLower(k)
			switch k {
			case "match":
				return // el resto del fichero pertenece al bloque Match
			case "include":
				for _, pat := range strings.Fields(v) {
					if !path.IsAbs(pat) { // rutas de sshd: siempre POSIX
						pat = path.Join("/etc/ssh", pat)
					}
					files, _ := glob(pat)
					for _, f := range files {
						walk(f, depth+1)
					}
				}
				continue
			}
			if seen[k] {
				continue
			}
			seen[k] = true
			if sshdTimeKeys[k] {
				if secs, ok := parseSSHDTime(v); ok {
					v = strconv.Itoa(secs)
				}
			}
			if sshdAlgoKeys[k] && v != "" {
				switch v[0] {
				case '-':
					// Quita algoritmos de los de por defecto: lo efectivo es el
					// valor por defecto de la regla sin ellos, nunca la lista.
					continue
				case '+', '^':
					// Sin "sshd -T" no se conocen los de por defecto: se
					// evalúan los que se añaden.
					v = v[1:]
				}
			}
			m[k] = v
		}
	}
	walk(file, 0)
	return m
}

func splitSSHDLine(line string) (string, string) {
	if i := strings.IndexAny(line, " \t="); i > 0 {
		return line[:i], strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
	}
	return line, ""
}

// parseSSHDTime convierte "90", "1m30s", "2h" a segundos.
func parseSSHDTime(s string) (int, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, true
	}
	total, num := 0, ""
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			num += string(r)
		default:
			n, err := strconv.Atoi(num)
			if err != nil {
				return 0, false
			}
			mult := map[rune]int{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[r]
			if mult == 0 {
				return 0, false
			}
			total += n * mult
			num = ""
		}
	}
	if num != "" {
		n, err := strconv.Atoi(num)
		if err != nil {
			return 0, false
		}
		total += n
	}
	return total, true
}

// --- /proc/self/mountinfo ---------------------------------------------------

type mountEntry struct {
	MountPoint string
	Options    []string
	FSType     string
	Source     string
}

// parseMountinfo interpreta /proc/self/mountinfo.
func parseMountinfo(text string) []mountEntry {
	var out []mountEntry
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(fields) {
			continue
		}
		opts := strings.Split(fields[5], ",")
		out = append(out, mountEntry{
			MountPoint: unescapeMount(fields[4]),
			Options:    opts,
			FSType:     fields[sep+1],
			Source:     fields[sep+2],
		})
	}
	return out
}

// unescapeMount decodifica los escapes octales (\040 = espacio).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// findMount devuelve la última entrada montada en path (la que está encima).
func findMount(entries []mountEntry, path string) (mountEntry, bool) {
	var found mountEntry
	ok := false
	for _, e := range entries {
		if e.MountPoint == path {
			found, ok = e, true
		}
	}
	return found, ok
}

// --- modprobe.d -----------------------------------------------------------

// normModule normaliza nombres de módulo: el kernel trata "-" y "_" igual.
func normModule(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "-", "_") }

// modprobeDirectives analiza ficheros de modprobe.d y devuelve si el módulo
// está bloqueado con "install <mod> /bin/false|/bin/true" y si está en
// "blacklist".
func modprobeDirectives(texts []string, module string) (installDisabled, blacklisted bool, installCmd string) {
	mod := normModule(module)
	for _, text := range texts {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 2 || normModule(f[1]) != mod {
				continue
			}
			switch f[0] {
			case "blacklist":
				blacklisted = true
			case "install":
				installCmd = strings.Join(f[2:], " ")
				base := ""
				if len(f) > 2 {
					base = filepath.Base(f[2])
				}
				installDisabled = base == "false" || base == "true"
			}
		}
	}
	return
}
