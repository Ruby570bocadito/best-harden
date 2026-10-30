package surface

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Estados de un puerto frente al firewall.
const (
	FirewallOpen     = "open"     // se puede llegar desde cualquier dirección
	FirewallLimited  = "limited"  // solo desde ciertas redes, direcciones o interfaces
	FirewallFiltered = "filtered" // lo bloquea el firewall
)

// FirewallProfile es un perfil del Firewall de Windows (Dominio, Privado o
// Público) con su estado.
type FirewallProfile struct {
	Name         string `json:"name"`
	Bit          int    `json:"-"`
	Enabled      bool   `json:"enabled"`
	BlockInbound bool   `json:"block_inbound"` // acción de entrada por defecto: bloquear
	Active       bool   `json:"active"`        // perfil de alguna red conectada ahora
}

// FirewallRule es una regla de entrada habilitada.
type FirewallRule struct {
	// ID es el nombre interno de la regla (el de Set-NetFirewallRule -Name).
	// Solo se conoce si se ha leído del almacén local del registro.
	ID         string
	Name       string
	Allow      bool
	Protocol   int    // 6 TCP, 17 UDP, 256 cualquiera
	LocalPorts string // "*", "80,443", "5000-5010", "RPC", "RPC-EPMap"…
	App        string // ruta del programa (vacía = cualquiera)
	Service    string // nombre del servicio, "*" (cualquier servicio) o vacío
	Profiles   int    // máscara de perfiles
	Local      string // direcciones locales (destino) a las que se aplica ("*" = todas)
	Remote     string // direcciones remotas permitidas ("*" = cualquiera)
	Interfaces string // interfaces concretas (vacío = todas)
	IfTypes    string // tipos de interfaz: All, Lan, Wireless, RemoteAccess
	// Package es el SID del paquete de una app de la Microsoft Store
	// (AppContainer): la regla solo se aplica a esa app, aunque no indique
	// programa. UserOwner limita la regla a los procesos de ese usuario.
	Package   string
	UserOwner string
	// Trust son las palabras clave de dispositivos de confianza (TTK en el
	// registro: WFDKmDriver, UPnP, ProxApp…): la regla solo admite tráfico
	// de dispositivos Wi-Fi Direct, UPnP o cercanos ya emparejados.
	Trust string
	// Secure indica que la regla exige autenticación IPsec.
	Secure bool
	// RemotePorts son los puertos de origen a los que se limita (vacío o
	// "*" = cualquiera) y UserAuth, que solo se aplica a los usuarios
	// autorizados (LUAuth). Con ellas la regla no cubre todo el tráfico.
	RemotePorts string
	UserAuth    bool
}

// Firewall es la política de entrada efectiva del Firewall de Windows.
type Firewall struct {
	Profiles []FirewallProfile `json:"profiles"`
	Rules    []FirewallRule    `json:"-"`
	// InboundRules es el número de reglas de entrada habilitadas.
	InboundRules int `json:"inbound_rules"`
	// Source indica de dónde se han leído las reglas: en Windows, "registry"
	// (completas) o "com" (HNetCfg.FwPolicy2, sin dispositivos de confianza
	// ni IPsec); en Linux, "nftables", "iptables" o ambos.
	Source string `json:"source,omitempty"`
	// InputPolicy es, en Linux, la acción por defecto de la entrada: drop si
	// se descarta lo que no permite una regla, accept si no.
	InputPolicy string `json:"input_policy,omitempty"`

	nf *netfilter // Linux
}

// Linux indica si es el cortafuegos del kernel de Linux.
func (fw *Firewall) Linux() bool { return fw.nf != nil }

// Uncovered devuelve las cadenas de Linux que pueden descartar tráfico antes
// de la entrada (prerouting, ingress, raw/mangle) y que no se evalúan.
func (fw *Firewall) Uncovered() []string {
	if fw == nil || fw.nf == nil {
		return nil
	}
	return fw.nf.uncovered
}

// Access es el resultado de evaluar un puerto.
type Access struct {
	State string // FirewallOpen | FirewallLimited | FirewallFiltered
	// Limit resume desde dónde se llega cuando está limitado ("Tailscale",
	// "la red local", "10.0.0.0/8"…) y Limits son sus partes por separado.
	Limit  string
	Limits []string
	// Why explica la decisión (reglas y perfil) para poder comprobarla.
	Why string
	// Rules son las reglas que lo abren a cualquiera o, si está limitado,
	// las que lo limitan.
	Rules []string
	// IDs son los nombres internos de las reglas que lo abren a cualquiera,
	// si se conocen todos (vacío si no).
	IDs []string
}

var profileNames = map[int]string{1: "Dominio", 2: "Privado", 4: "Público"}

// Active devuelve los perfiles en uso (todos si no consta ninguno).
func (fw *Firewall) Active() []FirewallProfile {
	var out []FirewallProfile
	for _, p := range fw.Profiles {
		if p.Active {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return fw.Profiles
	}
	return out
}

// Evaluate decide desde dónde se puede llegar al puerto con la política
// actual, como lo hace el Firewall de Windows: en cada perfil activo, una
// regla de bloqueo gana a una de permiso y, sin regla, manda la acción por
// defecto. Una regla de permiso puede estar limitada a ciertas direcciones
// locales (p. ej. «Tailscale-In», solo hacia la IP de Tailscale), remotas
// (LocalSubnet) o interfaces: entonces el puerto queda "limitado".
func (fw *Firewall) Evaluate(p Port) Access {
	if fw.nf != nil {
		return fw.nf.evaluate(p)
	}
	var limits, limitRules, blocked, open, openProfiles, ids []string
	allIDs := true
	for _, prof := range fw.Active() {
		if !prof.Enabled {
			return Access{State: FirewallOpen, Why: "firewall desactivado en el perfil " + prof.Name}
		}
		if r := fw.fullBlock(p, prof.Bit); r != nil {
			blocked = appendOnce(blocked, fmt.Sprintf("regla de bloqueo «%s»", r.Name))
			continue
		}
		if !prof.BlockInbound {
			return Access{State: FirewallOpen, Why: "el perfil " + prof.Name + " permite la entrada por defecto"}
		}
		for i := range fw.Rules {
			r := &fw.Rules[i]
			if !r.Allow || !r.matches(p, prof.Bit) {
				continue
			}
			parts, applies := r.limit(p)
			if !applies {
				continue
			}
			if len(parts) == 0 {
				open = appendOnce(open, "«"+r.Name+"»")
				openProfiles = appendOnce(openProfiles, prof.Name)
				if r.ID == "" {
					allIDs = false
				} else {
					ids = appendOnce(ids, r.ID)
				}
				continue
			}
			for _, x := range parts {
				limits = appendOnce(limits, x)
			}
			limitRules = appendOnce(limitRules, "«"+r.Name+"»")
		}
	}
	if len(open) > 0 {
		a := Access{State: FirewallOpen, Rules: open,
			Why: fmt.Sprintf("lo permite la regla %s (perfil %s)", open[0], joinHuman(openProfiles))}
		if len(open) > 1 {
			a.Why = fmt.Sprintf("lo permiten las reglas %s (perfil %s)", shortList(open, 4), joinHuman(openProfiles))
		}
		if allIDs {
			a.IDs = ids
		}
		return a
	}
	if len(limits) > 0 {
		sortLimits(limits)
		label := joinHuman(limits)
		return Access{State: FirewallLimited, Limit: label, Limits: limits, Rules: limitRules, Why: limitedWhy(label, limitRules)}
	}
	if len(blocked) > 0 {
		return Access{State: FirewallFiltered, Why: strings.Join(blocked, ", ")}
	}
	names := make([]string, 0, 3)
	for _, prof := range fw.Active() {
		names = append(names, prof.Name)
	}
	return Access{State: FirewallFiltered, Why: "ninguna regla lo permite en el perfil " + strings.Join(names, ", ")}
}

// limitedWhy explica un acceso limitado: "solo desde X (reglas «A» y «B»)".
func limitedWhy(label string, rules []string) string {
	word := "regla"
	if len(rules) > 1 {
		word = "reglas"
	}
	return fmt.Sprintf("solo %s (%s %s)", accessFrom(label), word, shortList(rules, 4))
}

// sortLimits ordena las partes de un límite para leerlas mejor: redes
// (la red local, Tailscale, direcciones), dispositivos, IPsec e interfaces.
func sortLimits(xs []string) {
	rank := func(s string) int {
		switch {
		case strings.HasPrefix(s, "la ") || strings.HasPrefix(s, "los "):
			return 0
		case s == "Tailscale":
			return 1
		case strings.HasPrefix(s, "hacia "):
			return 3
		case s == "Wi-Fi Direct" || strings.HasPrefix(s, "dispositivos"):
			return 4
		case strings.HasPrefix(s, "con "):
			return 5
		case strings.HasPrefix(s, "en "):
			return 6
		}
		return 2 // direcciones remotas
	}
	sort.SliceStable(xs, func(i, j int) bool { return rank(xs[i]) < rank(xs[j]) })
}

// joinHuman une una lista como en español: "A", "A y B", "A, B y C".
func joinHuman(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " y " + xs[len(xs)-1]
}

// shortList une como joinHuman, pero si hay más de max elementos resume el
// resto: "A, B, C y 5 más".
func shortList(xs []string, max int) string {
	if len(xs) <= max {
		return joinHuman(xs)
	}
	return fmt.Sprintf("%s y %d más", strings.Join(xs[:max], ", "), len(xs)-max)
}

// shortWho resume los procesos de un hallazgo para el título.
func shortWho(who []string) string {
	if len(who) <= 3 {
		return strings.Join(who, "; ")
	}
	return fmt.Sprintf("%s y %d más", strings.Join(who[:3], "; "), len(who)-3)
}

func accessFrom(label string) string {
	for _, prefix := range []string{"desde ", "hacia ", "en ", "con "} {
		if strings.HasPrefix(label, prefix) {
			return label
		}
	}
	return "desde " + label
}

// AllowAll devuelve las reglas de entrada que lo permiten todo (cualquier
// protocolo, puerto, programa y dirección) en algún perfil activo: equivalen
// a desactivar el firewall en esas redes.
func (fw *Firewall) AllowAll() []FirewallRule {
	active := 0
	for _, p := range fw.Active() {
		if p.Enabled && p.BlockInbound {
			active |= p.Bit
		}
	}
	var out []FirewallRule
	for _, r := range fw.Rules {
		if !r.Allow || r.Profiles&active == 0 || r.storeApp() || r.UserOwner != "" {
			continue
		}
		anyPort := strings.TrimSpace(r.LocalPorts) == "" || strings.TrimSpace(r.LocalPorts) == "*"
		if r.Protocol == 256 && anyPort && strings.TrimSpace(r.App) == "" && strings.TrimSpace(r.Service) == "" && r.unrestricted() {
			out = append(out, r)
		}
	}
	return out
}

// UserAllowAll devuelve las reglas que lo permiten todo pero solo para los
// procesos de un usuario (LocalUserOwner), en algún perfil activo.
func (fw *Firewall) UserAllowAll() []FirewallRule {
	active := 0
	for _, p := range fw.Active() {
		if p.Enabled && p.BlockInbound {
			active |= p.Bit
		}
	}
	var out []FirewallRule
	for _, r := range fw.Rules {
		if !r.Allow || r.UserOwner == "" || r.storeApp() || r.Profiles&active == 0 {
			continue
		}
		anyPort := strings.TrimSpace(r.LocalPorts) == "" || strings.TrimSpace(r.LocalPorts) == "*"
		if r.Protocol == 256 && anyPort && strings.TrimSpace(r.App) == "" && strings.TrimSpace(r.Service) == "" && r.unrestricted() {
			out = append(out, r)
		}
	}
	return out
}

// psList escribe una lista de cadenas de PowerShell ('a','b'), sin repetir
// las que solo cambian en mayúsculas.
func psList(xs []string) string {
	var out []string
	seen := map[string]bool{}
	for _, x := range xs {
		k := strings.ToLower(x)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, "'"+strings.ReplaceAll(x, "'", "''")+"'")
	}
	return strings.Join(out, ",")
}

// ruleSelector elige las reglas para un comando de PowerShell: por su
// nombre interno si se conocen todos (exacto) o, si no, por el visible.
func ruleSelector(rules []FirewallRule) string {
	ids := make([]string, 0, len(rules))
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.Name)
		if r.ID != "" {
			ids = append(ids, r.ID)
		}
	}
	if len(ids) == len(rules) {
		return "-Name " + psList(ids)
	}
	return "-DisplayName " + psList(names) + " -Direction Inbound"
}

// limitCmd es el comando para limitar unas reglas a la red local.
func limitCmd(ids []string) string {
	return fmt.Sprintf("Para que solo se llegue desde tu red local: bastion surface fix (con instantánea y rollback) o, a mano, "+
		"Set-NetFirewallRule -Name %s -RemoteAddress LocalSubnet (se deshace con -RemoteAddress Any).", psList(ids))
}

// ProfileNames devuelve los nombres de los perfiles de la máscara.
func ProfileNames(mask int) string {
	var out []string
	for _, b := range []int{1, 2, 4} {
		if mask&b != 0 {
			out = append(out, profileNames[b])
		}
	}
	return joinHuman(out)
}

// fullBlock devuelve una regla de bloqueo que se aplica al puerto sin
// restricciones de dirección. Las de bloqueo parcial no se tienen en cuenta
// (se peca de considerar el puerto accesible, nunca al revés).
func (fw *Firewall) fullBlock(p Port, profile int) *FirewallRule {
	for i := range fw.Rules {
		r := &fw.Rules[i]
		if r.Allow || !r.matches(p, profile) || !r.blocksProcess(p) {
			continue
		}
		if r.unrestricted() {
			return r
		}
	}
	return nil
}

// unrestricted indica si la regla se aplica desde cualquier dirección,
// interfaz y dispositivo, sin exigir IPsec.
func (r *FirewallRule) unrestricted() bool {
	return anyAddr(r.Local) && anyAddr(r.Remote) && r.Interfaces == "" && anyIfType(r.IfTypes) && r.Trust == "" && !r.Secure &&
		anyAddr(r.RemotePorts) && !r.UserAuth
}

// blocksProcess comprueba con exactitud que una regla de BLOQUEO se aplica
// al proceso del puerto. matches compara el programa solo por el nombre del
// fichero, lo que basta para un permiso (a lo sumo, se da por abierto algo
// que no lo está), pero no para un bloqueo: uno para C:\Temp\node.exe no
// cierra el node.exe de Program Files. Sin la ruta del proceso no se puede
// saber y el bloqueo no se tiene en cuenta. Lo mismo con el servicio: en un
// svchost compartido no se sabe cuál de sus servicios abre el puerto.
func (r *FirewallRule) blocksProcess(p Port) bool {
	app := strings.TrimSpace(r.App)
	switch {
	case app == "" || app == "*":
	case strings.EqualFold(app, "System"):
		if !strings.EqualFold(p.Process, "System") {
			return false
		}
	default:
		if p.Path == "" || !samePath(expandWinEnv(app, os.Getenv), p.Path) {
			return false
		}
	}
	if svc := strings.TrimSpace(r.Service); svc != "" && svc != "*" && len(p.Services) > 1 {
		return false
	}
	return true
}

// samePath compara dos rutas de Windows sin distinguir mayúsculas ni el
// tipo de barra.
func samePath(a, b string) bool {
	norm := func(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "/", `\`) }
	return strings.EqualFold(norm(a), norm(b))
}

// expandWinEnv expande las variables %VAR% de una ruta de regla. Una
// variable desconocida se deja tal cual (y la ruta no coincidirá).
func expandWinEnv(s string, getenv func(string) string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			break
		}
		name := s[i+1 : i+1+j]
		v := getenv(name)
		if v == "" && strings.EqualFold(name, "SystemRoot") {
			v = getenv("windir")
		}
		b.WriteString(s[:i])
		if v == "" {
			b.WriteString(s[i : i+2+j])
		} else {
			b.WriteString(v)
		}
		s = s[i+2+j:]
	}
	b.WriteString(s)
	return b.String()
}

// storeApp indica si es una regla de una app de la Microsoft Store. La
// interfaz COM no siempre devuelve el paquete (LocalAppPackageId), pero el
// nombre sin traducir de muchas lo delata: "@{Paquete_versión…?ms-resource://…}".
func (r *FirewallRule) storeApp() bool {
	return r.Package != "" || strings.HasPrefix(r.Name, "@{")
}

// systemProcs son procesos que nunca corren como un usuario interactivo ni
// dentro de un AppContainer.
var systemProcs = map[string]bool{"system": true, "svchost.exe": true, "lsass.exe": true, "services.exe": true,
	"wininit.exe": true, "spoolsv.exe": true}

// matches comprueba perfil, protocolo, puerto, programa y servicio.
func (r *FirewallRule) matches(p Port, profile int) bool {
	if r.Profiles&profile == 0 {
		return false
	}
	// Las reglas de apps de la Store solo afectan a su AppContainer: no
	// abren puertos de programas normales ni de servicios del sistema.
	if r.storeApp() {
		return false
	}
	if r.UserOwner != "" {
		// Solo cubre los procesos de ese usuario. Si se conoce el usuario
		// del proceso se compara el SID; si no, se excluyen los servicios.
		switch {
		case p.UserSID != "":
			if !strings.EqualFold(p.UserSID, r.UserOwner) {
				return false
			}
		case systemProcs[strings.ToLower(p.Process)] || len(p.Services) > 0:
			return false
		}
	}
	switch {
	case r.Protocol == 256:
	case r.Protocol == 6 && p.Proto == "tcp":
	case r.Protocol == 17 && p.Proto == "udp":
	default:
		return false
	}
	return matchPorts(r.LocalPorts, p) && matchApp(r.App, p.Process) && matchService(r.Service, p.Services)
}

// limit devuelve las restricciones de la regla para este puerto (ninguna
// si no las tiene) y si la regla llega a aplicarse: una regla limitada a
// direcciones locales no cubre un puerto que solo escucha en otras.
func (r *FirewallRule) limit(p Port) ([]string, bool) {
	var parts []string
	if !anyAddr(r.Local) {
		local := parseAddrs(r.Local)
		if specific := specificAddrs(p.Addresses); len(specific) > 0 && !local.containsAny(specific) {
			return nil, false
		}
		parts = append(parts, local.describe(true)...)
	}
	if !anyAddr(r.Remote) {
		parts = append(parts, parseAddrs(r.Remote).describe(false)...)
	}
	if r.Interfaces != "" {
		parts = append(parts, "en la interfaz "+r.Interfaces)
	} else if !anyIfType(r.IfTypes) {
		parts = append(parts, "en "+ifTypesLabel(r.IfTypes))
	}
	if r.Trust != "" {
		parts = append(parts, trustLabels(r.Trust)...)
	}
	if r.Secure {
		parts = append(parts, "con IPsec")
	}
	return parts, true
}

// trustLabels describe las palabras clave de dispositivos de confianza.
func trustLabels(s string) []string {
	var out []string
	for _, k := range strings.Split(s, ",") {
		k = strings.TrimSpace(k)
		low := strings.ToLower(k)
		switch {
		case k == "":
			continue
		case strings.HasPrefix(low, "wfd"):
			out = appendOnce(out, "Wi-Fi Direct")
		case strings.HasPrefix(low, "prox"):
			out = appendOnce(out, "dispositivos cercanos")
		case low == "upnp":
			out = appendOnce(out, "dispositivos UPnP")
		default:
			out = appendOnce(out, "dispositivos de confianza ("+k+")")
		}
	}
	return out
}

func anyAddr(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || s == "*"
}

func anyIfType(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	return s == "" || s == "all"
}

func ifTypesLabel(s string) string {
	names := map[string]string{"lan": "red cableada", "wireless": "wifi", "remoteaccess": "conexiones VPN o de acceso remoto"}
	var out []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if n, ok := names[strings.ToLower(t)]; ok {
			out = append(out, n)
		} else if t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, " y ")
}

// specificAddrs devuelve las direcciones de escucha que no son comodines.
// Si el puerto escucha en todas (0.0.0.0, ::), devuelve nil.
func specificAddrs(addrs []string) []net.IP {
	var out []net.IP
	for _, a := range addrs {
		a = strings.Trim(a, "[]")
		if i := strings.IndexByte(a, '%'); i >= 0 {
			a = a[:i]
		}
		ip := net.ParseIP(a)
		if ip == nil || ip.IsUnspecified() {
			return nil
		}
		out = append(out, ip)
	}
	return out
}

// addrSet es una lista de direcciones de una regla del firewall: IPs,
// subredes (CIDR o con máscara), rangos y palabras clave (LocalSubnet…).
type addrSet struct {
	nets     []*net.IPNet
	ranges   [][2]net.IP
	keywords []string
	raw      []string
	display  []string // raw en forma legible: 10.0.0.0/8 en vez de 10.0.0.0/255.0.0.0
}

func parseAddrs(s string) addrSet {
	var set addrSet
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" || tok == "*" {
			continue
		}
		if containsFold(set.raw, tok) {
			continue // LA4/LA6 o RA4/RA6 repiten LocalSubnet, DNS…
		}
		set.raw = append(set.raw, tok)
		set.display = append(set.display, tok)
		addNet := func(n *net.IPNet) {
			set.nets = append(set.nets, n)
			if ones, bits := n.Mask.Size(); ones == bits {
				set.display[len(set.display)-1] = n.IP.String()
			} else if bits != 0 {
				set.display[len(set.display)-1] = n.String()
			}
		}
		if lo, hi, ok := strings.Cut(tok, "-"); ok {
			a, b := net.ParseIP(lo), net.ParseIP(hi)
			if a != nil && b != nil {
				set.ranges = append(set.ranges, [2]net.IP{a, b})
				continue
			}
		}
		if ip, mask, ok := strings.Cut(tok, "/"); ok {
			if _, n, err := net.ParseCIDR(tok); err == nil {
				addNet(n)
				continue
			}
			if base, m := net.ParseIP(ip), net.ParseIP(mask); base != nil && m != nil && m.To4() != nil {
				mm := net.IPMask(m.To4())
				addNet(&net.IPNet{IP: base.To4().Mask(mm), Mask: mm})
				continue
			}
		}
		if ip := net.ParseIP(tok); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			addNet(&net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		set.keywords = append(set.keywords, tok)
	}
	return set
}

func (s addrSet) contains(ip net.IP) bool {
	if len(s.keywords) > 0 {
		return true // LocalSubnet, DHCP…: no se puede saber, se asume que sí
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, r := range s.ranges {
		a, b, x := r[0].To16(), r[1].To16(), ip.To16()
		if bytes.Compare(x, a) >= 0 && bytes.Compare(x, b) <= 0 {
			return true
		}
	}
	return false
}

func (s addrSet) containsAny(ips []net.IP) bool {
	for _, ip := range ips {
		if s.contains(ip) {
			return true
		}
	}
	return false
}

var (
	_, tailscale4, _ = net.ParseCIDR("100.64.0.0/10")
	_, tailscale6, _ = net.ParseCIDR("fd7a:115c:a1e0::/48")
)

// describe resume la lista para mostrarla: "Tailscale", "la red local",
// "10.0.0.0/8"… local indica si son direcciones de destino del equipo.
func (s addrSet) describe(local bool) []string {
	if len(s.raw) == 0 {
		return nil
	}
	ts := len(s.keywords) == 0 && len(s.ranges) == 0
	for _, n := range s.nets {
		if !(tailscale4.Contains(n.IP) || tailscale6.Contains(n.IP)) {
			ts = false
		}
	}
	if ts {
		return []string{"Tailscale"}
	}
	var out, other []string
	for i, tok := range s.raw {
		if label, ok := addrKeywords[strings.ToLower(tok)]; ok {
			out = append(out, label)
		} else {
			other = append(other, s.display[i])
		}
	}
	if len(other) > 0 {
		list := strings.Join(other, ", ")
		if len(other) > 3 {
			list = strings.Join(other[:3], ", ") + "…"
		}
		if local {
			list = "hacia " + list
		}
		out = append(out, list)
	}
	return out
}

// addrKeywords son las palabras clave de direcciones de las reglas.
var addrKeywords = map[string]string{
	"localsubnet": "la red local", "intranet": "la intranet", "rmtintranet": "la intranet remota",
	"dns": "los servidores DNS", "dhcp": "los servidores DHCP", "wins": "los servidores WINS",
	"defaultgateway": "la puerta de enlace", "ply2renders": "dispositivos de «Reproducir en»",
}

func containsFold(xs []string, x string) bool {
	for _, y := range xs {
		if strings.EqualFold(x, y) {
			return true
		}
	}
	return false
}

// matchPorts interpreta la lista de puertos locales de una regla.
func matchPorts(spec string, p Port) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return true
	}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		switch strings.ToLower(tok) {
		case "rpc": // extremos RPC dinámicos
			if p.Proto == "tcp" && p.Port >= 49152 {
				return true
			}
			continue
		case "rpc-epmap":
			if p.Port == 135 {
				return true
			}
			continue
		case "iphttps", "iphttpsin", "iptlsin":
			if p.Port == 443 {
				return true
			}
			continue
		case "mdns":
			if p.Port == 5353 {
				return true
			}
			continue
		}
		if lo, hi, ok := strings.Cut(tok, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && p.Port >= a && p.Port <= b {
				return true
			}
			continue
		}
		if n, err := strconv.Atoi(tok); err == nil && n == p.Port {
			return true
		}
	}
	return false
}

// matchApp compara el programa de la regla con el proceso (por nombre de
// fichero: la regla trae la ruta, a menudo con %SystemRoot%).
func matchApp(app, process string) bool {
	app = strings.TrimSpace(app)
	if app == "" || app == "*" {
		return true
	}
	if i := strings.LastIndexAny(app, `\/`); i >= 0 {
		app = app[i+1:]
	}
	return process != "" && strings.EqualFold(app, process)
}

func matchService(svc string, services []string) bool {
	svc = strings.TrimSpace(svc)
	switch svc {
	case "":
		return true
	case "*":
		return len(services) > 0
	}
	for _, s := range services {
		if strings.EqualFold(s, svc) {
			return true
		}
	}
	return false
}
