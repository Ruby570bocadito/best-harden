// Package surface analiza la superficie de ataque del equipo: qué servicios
// escuchan en la red (con su proceso), qué recursos se comparten y quién es
// administrador. Responde a "¿qué puede tocar un atacante desde la red?".
//
// Como los probes, es de SOLO LECTURA y solo ejecuta comandos fijos.
package surface

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/platform"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

// Schema es la versión del formato JSON del análisis.
const Schema = "adarve.surface/v1"

// LegacySchema es el mismo formato con el nombre anterior de Adarve
// (Bastion): los análisis guardados antes del cambio siguen valiendo.
const LegacySchema = "bastion.surface/v1"

// Alcance de un servicio a la escucha.
const (
	ScopeNetwork  = "network"  // todas las interfaces o una IP de red
	ScopeLoopback = "loopback" // solo el propio equipo
)

// Listener es un socket a la escucha.
type Listener struct {
	Proto    string   `json:"proto"` // tcp | udp
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	Scope    string   `json:"scope"`
	PID      int      `json:"pid,omitempty"`
	Process  string   `json:"process,omitempty"`
	Services []string `json:"services,omitempty"` // servicios de Windows en ese proceso
	// Known es el servicio conocido en ese puerto (vacío si no está catalogado).
	Known string `json:"known,omitempty"`
	// Ephemeral marca los sockets UDP en puertos dinámicos: son los de un
	// cliente (consultas DNS, descubrimiento…), no servicios a la escucha.
	Ephemeral bool `json:"ephemeral,omitempty"`
	// User es la cuenta con la que corre el proceso (y su SID, en Windows).
	User    string `json:"user,omitempty"`
	UserSID string `json:"user_sid,omitempty"`
	// Path es la ruta del ejecutable y Signature, de dónde viene (ver
	// SigValid…); Signer, quién lo firma (Windows) o el paquete que lo
	// instala (Linux).
	Path      string `json:"path,omitempty"`
	Signature string `json:"signature,omitempty"`
	Signer    string `json:"signer,omitempty"`
}

// Origen del ejecutable de un proceso a la escucha.
const (
	SigValid     = "valid"      // firma Authenticode válida
	SigUnsigned  = "unsigned"   // sin firma
	SigInvalid   = "invalid"    // firmado, pero modificado después
	SigUntrusted = "untrusted"  // firmado con un certificado sin confianza
	SigPackage   = "package"    // Linux: lo instala un paquete
	SigNoPackage = "unpackaged" // Linux: no es de ningún paquete
)

// Port agrupa los sockets del mismo puerto, protocolo y proceso (IPv4, IPv6
// o varias direcciones). Es lo que se muestra y lo que genera hallazgos.
type Port struct {
	Proto     string   `json:"proto"`
	Port      int      `json:"port"`
	Addresses []string `json:"addresses"`
	Scope     string   `json:"scope"`
	PID       int      `json:"pid,omitempty"`
	Process   string   `json:"process,omitempty"`
	Services  []string `json:"services,omitempty"`
	Known     string   `json:"known,omitempty"`
	Ephemeral bool     `json:"ephemeral,omitempty"`
	User      string   `json:"user,omitempty"`
	UserSID   string   `json:"user_sid,omitempty"`
	Path      string   `json:"path,omitempty"`
	Signature string   `json:"signature,omitempty"`
	Signer    string   `json:"signer,omitempty"`
	// Firewall: "open" (desde cualquier dirección), "limited" (solo desde
	// ciertas redes o interfaces, ver FirewallLimit), "filtered" (lo bloquea)
	// o vacío si no se ha podido evaluar.
	Firewall      string `json:"firewall,omitempty"`
	FirewallLimit string `json:"firewall_limit,omitempty"`
	FirewallWhy   string `json:"firewall_why,omitempty"`
	access        Access // la evaluación completa, para los hallazgos
}

// ShareAccess es un permiso de un recurso compartido.
type ShareAccess struct {
	Account string `json:"account"`
	SID     string `json:"sid,omitempty"`
	Right   string `json:"right"` // Full | Change | Read
	Deny    bool   `json:"deny,omitempty"`
}

// Share es un recurso compartido (SMB en Windows; NFS o Samba en Linux).
type Share struct {
	Kind   string        `json:"kind"` // smb | nfs | samba
	Name   string        `json:"name"`
	Path   string        `json:"path,omitempty"`
	Access []ShareAccess `json:"access,omitempty"`
	// Options resume opciones relevantes (no_root_squash, guest ok…).
	Options []string `json:"options,omitempty"`
}

// Account es un miembro con privilegios de administración.
type Account struct {
	Name   string `json:"name"`
	Kind   string `json:"kind,omitempty"`   // usuario, grupo…
	Source string `json:"source,omitempty"` // local, dominio, uid 0, grupo sudo…
}

// Inventory es lo que recogen los colectores de cada sistema.
type Inventory struct {
	Listeners []Listener `json:"listeners"`
	Shares    []Share    `json:"shares"`
	Admins    []Account  `json:"admins"`
	// Firewall es el estado del firewall del equipo, si se ha podido leer.
	Firewall *Firewall `json:"firewall,omitempty"`
	// Notes explica límites de la recogida (p. ej. sin root no se ven los
	// procesos de otros usuarios).
	Notes []string `json:"notes,omitempty"`
}

// Finding es un hallazgo de exposición.
type Finding struct {
	ID       string        `json:"id"`
	Severity rule.Severity `json:"severity"`
	Title    string        `json:"title"`
	Detail   string        `json:"detail"`
	Fix      string        `json:"fix"`
	Subject  string        `json:"subject"` // 445/tcp, \\SHARE, /etc/exports…
	// FirewallRules son los nombres internos de las reglas del Firewall de
	// Windows que lo abren a cualquiera: "adarve surface fix" las limita a
	// la red local.
	FirewallRules []string `json:"firewall_rules,omitempty"`
}

// Report es el resultado completo de "adarve surface".
type Report struct {
	Schema     string        `json:"schema"`
	Host       platform.Info `json:"host"`
	Version    string        `json:"version"`
	FinishedAt time.Time     `json:"finished_at"`
	Score      int           `json:"score"`
	Grade      string        `json:"grade"`
	// Exposed son los servicios (puertos agrupados) que escuchan en la red;
	// Reachable, los que además no bloquea el firewall (o todos, si no se
	// ha podido evaluar), y Limited, cuántos de esos solo desde ciertas
	// redes o interfaces.
	Exposed   int    `json:"exposed"`
	Reachable int    `json:"reachable"`
	Limited   int    `json:"limited"`
	Ports     []Port `json:"ports"`
	Inventory
	Findings []Finding `json:"findings"`
	// Changes compara con el último análisis guardado del equipo (si hay).
	Changes *Changes `json:"changes,omitempty"`
}

// Penalización por hallazgo en la puntuación de exposición.
var penalty = map[rule.Severity]int{rule.SevCritical: 30, rule.SevHigh: 15, rule.SevMedium: 7, rule.SevLow: 3}

// knownPort describe un servicio conocido y su riesgo si se expone.
type knownPort struct {
	service string
	proto   string // tcp | udp | "" (ambos)
	sev     rule.Severity
	why     string
	fix     string
	// group une en un solo hallazgo puertos con la misma causa (NetBIOS).
	group string
}

// groups son los hallazgos que agrupan varios puertos.
var groups = map[string]knownPort{
	"netbios": {service: "NetBIOS sobre TCP/IP", sev: rule.SevMedium,
		why: "NetBIOS (137-139) permite enumerar el equipo, envenenar resoluciones de nombres y retransmitir autenticaciones.",
		fix: "Deshabilita NetBIOS sobre TCP/IP en los adaptadores (control WIN-NET-007: adarve harden --wave 2)."},
	"sunshine": {service: "Sunshine/GameStream", sev: rule.SevMedium,
		why: "Sunshine transmite el escritorio y recibe el teclado y el ratón de los clientes emparejados; su panel web (47990/tcp) gestiona el emparejamiento y la configuración. Una contraseña débil o un fallo dan el control del equipo.",
		fix: "Si solo juegas en casa o a través de una VPN como Tailscale, limita sus reglas a la red local y no abras estos puertos en el router; protege el panel web con una contraseña robusta."},
}

// ports es el catálogo de servicios cuyo riesgo depende de estar expuestos.
// La severidad es la de tenerlos accesibles desde la red.
var ports = map[int]knownPort{
	21:    {"FTP", "tcp", rule.SevHigh, "FTP transmite usuarios, contraseñas y ficheros en claro.", "Sustitúyelo por SFTP/FTPS o desinstálalo si no se usa.", ""},
	22:    {"SSH", "tcp", rule.SevInfo, "Administración remota cifrada. Es normal en servidores; asegúrate de que el hardening de SSH pasa.", "Limítalo a la red de gestión con el firewall y usa autenticación por clave.", ""},
	23:    {"Telnet", "tcp", rule.SevCritical, "Telnet transmite la sesión y la contraseña en claro.", "Desinstala el servidor Telnet y usa SSH.", ""},
	25:    {"SMTP", "tcp", rule.SevLow, "Un servidor de correo expuesto puede usarse como relay si está mal configurado.", "Si no es un servidor de correo, desactívalo o restríngelo a localhost.", ""},
	53:    {"DNS", "", rule.SevLow, "Un DNS abierto a Internet puede usarse en ataques de amplificación.", "Si no es un servidor DNS, desactívalo; si lo es, desactiva la recursión para clientes externos.", ""},
	69:    {"TFTP", "udp", rule.SevHigh, "TFTP no tiene autenticación: cualquiera puede leer (o escribir) ficheros.", "Desinstálalo si no arrancas equipos por red.", ""},
	80:    {"HTTP", "tcp", rule.SevInfo, "Servicio web sin cifrar.", "Redirige a HTTPS y revisa qué aplicación responde.", ""},
	111:   {"rpcbind", "", rule.SevMedium, "rpcbind expone los servicios RPC del equipo y se usa en amplificación.", "Desactívalo si no usas NFS: systemctl disable --now rpcbind rpcbind.socket.", ""},
	135:   {"RPC (Windows)", "tcp", rule.SevMedium, "El mapeador RPC es base de mucho movimiento lateral en Windows.", "Bloquéalo en el firewall para redes que no sean de administración.", ""},
	137:   {"NetBIOS", "udp", rule.SevMedium, "NetBIOS permite enumerar el equipo y envenenar resoluciones de nombres.", "Deshabilita NetBIOS sobre TCP/IP en los adaptadores (control WIN-NET-007).", "netbios"},
	138:   {"NetBIOS", "udp", rule.SevMedium, "NetBIOS permite enumerar el equipo y envenenar resoluciones de nombres.", "Deshabilita NetBIOS sobre TCP/IP en los adaptadores (control WIN-NET-007).", "netbios"},
	139:   {"NetBIOS/SMB", "tcp", rule.SevMedium, "SMB sobre NetBIOS: enumeración y ataques de retransmisión.", "Deshabilita NetBIOS sobre TCP/IP en los adaptadores.", "netbios"},
	161:   {"SNMP", "udp", rule.SevHigh, "SNMP v1/v2c usa comunidades en claro (a menudo \"public\") y revela mucha información.", "Desactívalo o usa SNMPv3 con autenticación y cifrado, limitado a la red de gestión.", ""},
	389:   {"LDAP", "", rule.SevInfo, "Directorio. Normal en controladores de dominio.", "Exige firma LDAP y channel binding (controles del perfil de DC).", ""},
	445:   {"SMB", "tcp", rule.SevHigh, "SMB es vector clásico de ransomware y movimiento lateral (EternalBlue, retransmisión NTLM).", "Si no compartes recursos, bloquéalo en el firewall; si los compartes, limítalo a las redes necesarias y exige firma SMB.", ""},
	512:   {"rexec", "tcp", rule.SevCritical, "Servicio r* heredado sin cifrado.", "Desinstala rsh-server y usa SSH.", ""},
	513:   {"rlogin", "tcp", rule.SevCritical, "Servicio r* heredado sin cifrado y con confianza por host.", "Desinstala rsh-server y usa SSH.", ""},
	514:   {"rsh", "tcp", rule.SevCritical, "Servicio r* heredado sin cifrado y con confianza por host.", "Desinstala rsh-server y usa SSH.", ""},
	631:   {"IPP/CUPS", "", rule.SevMedium, "El servicio de impresión ha tenido fallos explotables remotamente (2024).", "Desactiva cups-browsed y deja CUPS solo en localhost si no compartes impresoras.", ""},
	873:   {"rsync", "tcp", rule.SevHigh, "Un demonio rsync expuesto suele permitir leer módulos sin autenticación.", "Desactívalo o exige autenticación y limita las IP de origen.", ""},
	1433:  {"SQL Server", "tcp", rule.SevMedium, "Base de datos accesible desde la red.", "Limítala a los servidores de aplicación con el firewall.", ""},
	1900:  {"SSDP/UPnP", "udp", rule.SevMedium, "UPnP anuncia el equipo y se usa en amplificación.", "Desactiva el servicio de detección SSDP si no se necesita.", ""},
	2049:  {"NFS", "", rule.SevMedium, "NFS comparte ficheros con control por IP.", "Limita los clientes en /etc/exports y no uses no_root_squash.", ""},
	2375:  {"Docker API (sin TLS)", "tcp", rule.SevCritical, "La API de Docker sin TLS da control total del equipo (root) a quien llegue al puerto.", "Desactiva el socket TCP de Docker o protégelo con TLS mutuo.", ""},
	2376:  {"Docker API (TLS)", "tcp", rule.SevMedium, "API de Docker con TLS: su compromiso equivale a root.", "Limítala a la red de gestión y verifica que exige certificado de cliente.", ""},
	2379:  {"etcd", "tcp", rule.SevHigh, "etcd guarda los secretos de Kubernetes.", "Exige TLS mutuo y limita el acceso a los nodos del plano de control.", ""},
	3306:  {"MySQL/MariaDB", "tcp", rule.SevMedium, "Base de datos accesible desde la red.", "Usa bind-address = 127.0.0.1 o limita el acceso con el firewall.", ""},
	3389:  {"RDP", "tcp", rule.SevHigh, "RDP expuesto es una de las vías de entrada más usadas por el ransomware.", "Limítalo a la red de gestión o a una VPN, exige NLA (WIN-RDP-001) y MFA.", ""},
	5353:  {"mDNS", "udp", rule.SevLow, "mDNS anuncia el equipo en la red local.", "Desactiva avahi (Linux) o mDNS si no se usa.", ""},
	5355:  {"LLMNR", "udp", rule.SevMedium, "LLMNR permite envenenar resoluciones y capturar hashes NTLM (Responder).", "Deshabilita LLMNR por directiva (control WIN-NET-006).", ""},
	5432:  {"PostgreSQL", "tcp", rule.SevMedium, "Base de datos accesible desde la red.", "Usa listen_addresses = 'localhost' o limita el acceso en pg_hba.conf y el firewall.", ""},
	5900:  {"VNC", "tcp", rule.SevHigh, "VNC suele tener autenticación débil y tráfico sin cifrar.", "Ciérralo o tunelízalo por SSH/VPN.", ""},
	5985:  {"WinRM (HTTP)", "tcp", rule.SevMedium, "Administración remota de Windows (PowerShell Remoting).", "Limítalo a la red de gestión; prefiere WinRM sobre HTTPS (5986).", ""},
	5986:  {"WinRM (HTTPS)", "tcp", rule.SevLow, "Administración remota de Windows cifrada.", "Limítalo a la red de gestión.", ""},
	6379:  {"Redis", "tcp", rule.SevCritical, "Redis no exige autenticación por defecto y permite escribir ficheros en el equipo.", "Usa bind 127.0.0.1, protected-mode yes y requirepass/ACL.", ""},
	9200:  {"Elasticsearch", "tcp", rule.SevHigh, "Elasticsearch expuesto ha causado muchas fugas de datos.", "Actívale la seguridad (usuarios y TLS) y limítalo a la red interna.", ""},
	10250: {"kubelet", "tcp", rule.SevHigh, "La API del kubelet permite ejecutar comandos en los contenedores si no exige autenticación.", "Verifica --anonymous-auth=false y authorization-mode=Webhook.", ""},
	11211: {"memcached", "", rule.SevHigh, "memcached no tiene autenticación y se usa en amplificación masiva (UDP).", "Escucha solo en 127.0.0.1 y desactiva UDP (-U 0).", ""},
	27017: {"MongoDB", "tcp", rule.SevHigh, "MongoDB expuesto sin autenticación ha causado muchas fugas de datos.", "Usa bindIp 127.0.0.1 y activa la autorización.", ""},
	// Sunshine (y Apollo): HTTPS, HTTP, panel web y RTSP en TCP; vídeo,
	// control, audio y micrófono en UDP, solo mientras se transmite.
	47984: {"Sunshine/GameStream", "tcp", rule.SevMedium, "", "", "sunshine"},
	47989: {"Sunshine/GameStream", "tcp", rule.SevMedium, "", "", "sunshine"},
	47990: {"Sunshine (panel web)", "tcp", rule.SevMedium, "", "", "sunshine"},
	47998: {"Sunshine/GameStream", "udp", rule.SevMedium, "", "", "sunshine"},
	47999: {"Sunshine/GameStream", "udp", rule.SevMedium, "", "", "sunshine"},
	48000: {"Sunshine/GameStream", "udp", rule.SevMedium, "", "", "sunshine"},
	48002: {"Sunshine/GameStream", "udp", rule.SevMedium, "", "", "sunshine"},
	48010: {"Sunshine/GameStream", "", rule.SevMedium, "", "", "sunshine"},
}

// labels nombra puertos habituales que no son un riesgo por sí mismos, para
// que el inventario no los muestre como desconocidos. No generan hallazgos.
var labels = map[string]string{
	"tcp/443":   "HTTPS",
	"udp/123":   "NTP",
	"udp/500":   "IKE (IPsec/VPN)",
	"udp/4500":  "IKE NAT-T (IPsec/VPN)",
	"tcp/2869":  "UPnP (host de dispositivos)",
	"udp/3389":  "RDP (transporte UDP)",
	"udp/5050":  "Dispositivos conectados (CDP)",
	"udp/3702":  "WS-Discovery",
	"tcp/5040":  "Dispositivos conectados (CDP)",
	"tcp/5357":  "WSD (detección de dispositivos)",
	"tcp/5358":  "WSD (detección de dispositivos)",
	"tcp/7680":  "Optimización de distribución (Windows Update)",
	"tcp/27036": "Steam (Remote Play)",
	"udp/27036": "Steam (Remote Play)",
	"udp/41641": "Tailscale (WireGuard)",
	"udp/51820": "WireGuard",
	"udp/9993":  "ZeroTier",
	"udp/6771":  "BitTorrent (descubrimiento local)",
}

// appLabels son los puertos etiquetados que abre un programa del usuario y
// no un protocolo del sistema: si el firewall los deja abiertos a
// cualquiera, cuentan como programas abiertos. Los demás (HTTPS, VPN que
// solo responden a pares autenticados…) se abren a propósito.
var appLabels = map[string]bool{"tcp/27036": true, "udp/27036": true, "udp/6771": true}

func label(proto string, port int) string {
	if port >= 47984 && port <= 48010 {
		return "Sunshine/GameStream"
	}
	return labels[proto+"/"+strconv.Itoa(port)]
}

// ephemeralUDP indica si un socket UDP en ese puerto es, casi seguro, de un
// cliente: está en el rango dinámico [lo, hi] y no es un servicio conocido
// (WireGuard, Sunshine…), que se analizan como cualquier otro.
func ephemeralUDP(port, lo, hi int) bool {
	if port < lo || port > hi {
		return false
	}
	if _, ok := lookup("udp", port); ok {
		return false
	}
	return label("udp", port) == ""
}

// wildcard indica si alguna dirección es la de todas las interfaces.
func wildcard(addrs []string) bool {
	for _, a := range addrs {
		if a == "0.0.0.0" || a == "::" || a == "*" || a == "[::]" {
			return true
		}
	}
	return false
}

// Lookup devuelve el servicio conocido de un puerto y protocolo.
func lookup(proto string, port int) (knownPort, bool) {
	k, ok := ports[port]
	if !ok || (k.proto != "" && k.proto != proto) {
		return knownPort{}, false
	}
	return k, true
}

// ScopeOf clasifica una dirección de escucha.
func ScopeOf(addr string) string {
	a := strings.Trim(addr, "[]")
	if i := strings.IndexByte(a, '%'); i >= 0 {
		a = a[:i]
	}
	if a == "*" || a == "" {
		return ScopeNetwork
	}
	ip := net.ParseIP(a)
	if ip != nil && ip.IsLoopback() {
		return ScopeLoopback
	}
	return ScopeNetwork
}

// userApp indica si el puerto es de un programa del usuario y no de
// Windows: con nombre de proceso conocido, sin servicios y fuera de los
// procesos del sistema.
func userApp(p Port) bool {
	proc := strings.ToLower(p.Process)
	return proc != "" && len(p.Services) == 0 && !systemProcs[proc] && !rpcProcs[proc]
}

// rpcProcs son los procesos de Windows que exponen extremos RPC dinámicos.
var rpcProcs = map[string]bool{"lsass.exe": true, "wininit.exe": true, "services.exe": true, "spoolsv.exe": true, "svchost.exe": true}

// Analyze genera los hallazgos y la puntuación a partir del inventario.
func Analyze(inv Inventory, host platform.Info, version string, now time.Time) *Report {
	inv.Listeners = dedupe(inv.Listeners)
	rep := &Report{Schema: Schema, Host: host, Version: version, FinishedAt: now.UTC(), Inventory: inv}
	rep.Ports = groupPorts(inv.Listeners)

	type acc struct {
		k        knownPort
		id       string
		subjects []string
		who      []string
		why      string   // la del primer puerto abierto
		open     []string // reglas que abren alguno de los puertos
		limits   []string // si todos los puertos del hallazgo están limitados
		rules    []string // las reglas que los limitan
		ids      []string // reglas que los abren, para el comando que las limita
		noIDs    bool     // algún puerto abierto sin reglas conocidas
		limited  bool
		port     int
		pids     []int
		// Programas del usuario con algún puerto abierto, y si alguno de
		// los procesos es del sistema: SSDP de Windows limitado y un
		// programa que abre el mismo puerto a cualquiera.
		openApps []string
		openSys  bool
		system   bool
	}
	// Reglas que abren cada puerto y proceso, para unir al hallazgo de un
	// puerto TCP las del mismo puerto en UDP (RDP usa los dos).
	openIDs := map[string][]string{}
	var order []string
	found := map[string]*acc{}
	// Programas (no servicios del sistema) con puertos sin catalogar que el
	// firewall deja abiertos a cualquiera.
	type app struct {
		ports, rules, ids []string
		noIDs             bool
		why               string
	}
	var appOrder []string
	apps := map[string]*app{}
	// Ejecutables sin firma (o fuera de los paquetes) o con una firma que
	// no vale, accesibles desde la red.
	var bins []*exposedBinary
	binIdx := map[string]*exposedBinary{}
	var ephApps []string // programas con UDP en puertos dinámicos de todas las interfaces
	for i := range rep.Ports {
		p := &rep.Ports[i]
		k, ok := lookup(p.Proto, p.Port)
		if ok && p.Port == 22 && host.Role == "workstation" {
			// En un servidor, SSH es lo normal; en un equipo de usuario rara
			// vez se necesita y conviene saber que está abierto.
			k.sev = rule.SevLow
			k.why = "Un servidor SSH en un equipo de usuario amplía la superficie de ataque y rara vez es necesario."
			k.fix = "Si no lo usas, deshabilítalo (Windows: Stop-Service sshd; Set-Service sshd -StartupType Disabled · Linux: systemctl disable --now ssh). Si lo usas, limítalo a tu red y exige claves."
		}
		switch {
		case ok:
			p.Known = k.service
		case p.Proto == "tcp" && p.Port >= 49152 && rpcProcs[strings.ToLower(p.Process)]:
			p.Known = "RPC dinámico (Windows)"
		case p.Proto == "tcp" && p.Port == 443 && containsFold(p.Services, "iphlpsvc"):
			p.Known = "IP-HTTPS (túnel IPv6 de Windows)"
		default:
			p.Known = label(p.Proto, p.Port)
		}
		if p.Scope == ScopeNetwork && p.Ephemeral && userApp(*p) && wildcard(p.Addresses) {
			// No se analiza (suele ser un cliente: QUIC, descubrimiento…),
			// pero un programa que no es del sistema podría ser un servidor.
			ephApps = appendOnce(ephApps, p.Process)
		}
		if p.Scope != ScopeNetwork || p.Ephemeral {
			continue
		}
		rep.Exposed++
		if inv.Firewall != nil {
			a := inv.Firewall.Evaluate(*p)
			p.Firewall, p.FirewallLimit, p.FirewallWhy, p.access = a.State, a.Limit, a.Why, a
		}
		if p.Firewall == FirewallFiltered {
			continue
		}
		rep.Reachable++
		if p.Firewall == FirewallLimited {
			rep.Limited++
		}
		if p.Firewall == FirewallOpen && len(p.access.IDs) > 0 {
			openIDs[fmt.Sprintf("%d/%d", p.Port, p.PID)] = append(openIDs[fmt.Sprintf("%d/%d", p.Port, p.PID)], p.access.IDs...)
		}
		switch p.Signature {
		case SigUnsigned, SigNoPackage, SigInvalid, SigUntrusted:
			key := strings.ToLower(p.Path)
			b := binIdx[key]
			if b == nil {
				b = &exposedBinary{name: p.Process, path: p.Path, signer: p.Signer, status: p.Signature}
				if b.name == "" {
					b.name = baseName(p.Path)
				}
				binIdx[key] = b
				bins = append(bins, b)
			}
			b.ports = appendOnce(b.ports, fmt.Sprintf("%d/%s", p.Port, p.Proto))
		}
		if p.Firewall == FirewallOpen && (p.Known == "" || appLabels[p.Proto+"/"+strconv.Itoa(p.Port)]) && userApp(*p) {
			ap := apps[p.Process]
			if ap == nil {
				ap = &app{why: p.FirewallWhy}
				apps[p.Process] = ap
				appOrder = append(appOrder, p.Process)
			}
			ap.ports = appendOnce(ap.ports, fmt.Sprintf("%d/%s", p.Port, p.Proto))
			for _, r := range p.access.Rules {
				ap.rules = appendOnce(ap.rules, r)
			}
			for _, id := range p.access.IDs {
				ap.ids = appendOnce(ap.ids, id)
			}
			ap.noIDs = ap.noIDs || len(p.access.IDs) == 0
		}
		if !ok || k.sev == rule.SevInfo {
			continue
		}
		subject := fmt.Sprintf("%d/%s", p.Port, p.Proto)
		key, kk, id := subject, k, "SURF-PORT-"+strconv.Itoa(p.Port)
		if k.group != "" {
			key, kk, id = k.group, groups[k.group], "SURF-"+strings.ToUpper(k.group)
		}
		a := found[key]
		if a == nil {
			a = &acc{k: kk, id: id, limited: true, port: p.Port}
			found[key] = a
			order = append(order, key)
		}
		a.pids = append(a.pids, p.PID)
		app := userApp(*p)
		a.system = a.system || !app
		if p.Firewall == FirewallOpen {
			if app {
				a.openApps = appendOnce(a.openApps, p.Process)
			} else {
				a.openSys = true
			}
		}
		if p.Firewall == FirewallLimited {
			for _, x := range p.access.Limits {
				a.limits = appendOnce(a.limits, x)
			}
			for _, r := range p.access.Rules {
				a.rules = appendOnce(a.rules, r)
			}
		} else {
			if a.limited || a.why == "" {
				a.why = p.FirewallWhy
			}
			a.limited = false
			for _, r := range p.access.Rules {
				a.open = appendOnce(a.open, r)
			}
			for _, id := range p.access.IDs {
				a.ids = appendOnce(a.ids, id)
			}
			a.noIDs = a.noIDs || len(p.access.IDs) == 0
		}
		a.subjects = appendOnce(a.subjects, subject)
		who := p.Process
		if who == "" {
			who = "proceso desconocido"
		}
		if len(p.Services) > 0 {
			who += " · " + strings.Join(p.Services, ", ")
		}
		a.who = appendOnce(a.who, who)
	}
	for _, key := range order {
		a := found[key]
		why := a.why
		switch {
		case a.limited:
			sortLimits(a.limits)
			why = limitedWhy(joinHuman(a.limits), a.rules)
		case len(a.open) > 1:
			// Varios puertos abiertos por reglas distintas (mDNS de Chrome y
			// de Steam): se nombran todas, como en el comando.
			why = "lo permiten las reglas " + shortList(a.open, 4)
		}
		detail := a.k.why
		if why != "" {
			detail += " Firewall: " + why + "."
		}
		f := Finding{
			ID: a.id, Severity: a.k.sev, Subject: strings.Join(a.subjects, ", "),
			Title:  fmt.Sprintf("%s accesible desde la red (%s)", a.k.service, shortWho(a.who)),
			Detail: detail, Fix: a.k.fix,
		}
		if a.limited {
			// Solo se llega desde ciertas redes (VPN, red local…): el riesgo
			// es menor y depende de quién esté en ellas.
			f.Severity = lower(a.k.sev)
			if f.Severity == rule.SevInfo {
				continue
			}
			limit := joinHuman(a.limits)
			f.Title = fmt.Sprintf("%s accesible solo %s (%s)", a.k.service, accessFrom(limit), shortWho(a.who))
			f.Fix = "Ya solo se llega " + accessFrom(limit) + ": revisa quién tiene acceso a esa red. Además: " + a.k.fix
		} else if a.system && !a.openSys && len(a.openApps) > 0 {
			// Lo que queda abierto no es el servicio del catálogo, sino un
			// programa que usa el mismo puerto.
			f.Fix = fmt.Sprintf("Lo deja abierto a cualquiera %s, no el servicio de Windows: si no necesitas que acepte conexiones "+
				"de otros equipos, limita su regla a la red local o desactívala. Sobre el servicio: %s", joinHuman(a.openApps), a.k.fix)
		}
		if !a.limited && len(a.ids) > 0 && !a.noIDs {
			if a.k.group == "" {
				for _, pid := range a.pids {
					for _, id := range openIDs[fmt.Sprintf("%d/%d", a.port, pid)] {
						a.ids = appendOnce(a.ids, id)
					}
				}
			}
			f.Fix += " " + limitCmd(a.ids)
			f.FirewallRules = a.ids
		}
		rep.Findings = append(rep.Findings, f)
	}
	if len(appOrder) > 0 {
		var names, rules, ids []string
		noIDs := false
		for _, name := range appOrder {
			ap := apps[name]
			names = append(names, fmt.Sprintf("%s (%s)", name, strings.Join(ap.ports, ", ")))
			for _, r := range ap.rules {
				rules = appendOnce(rules, r)
			}
			ids = append(ids, ap.ids...)
			noIDs = noIDs || ap.noIDs
		}
		// Sin reglas, está abierto porque el firewall no filtra en ese perfil.
		fwWhy := apps[appOrder[0]].why
		if len(rules) == 1 {
			fwWhy = "regla " + rules[0]
		} else if len(rules) > 1 {
			fwWhy = "reglas " + shortList(rules, 4)
		}
		var ports []string
		for _, name := range appOrder {
			ports = append(ports, apps[name].ports...)
		}
		subject := strings.Join(ports, ", ")
		if len(ports) > 4 {
			subject = strings.Join(ports[:4], ", ") + "…"
		}
		f := Finding{ID: "SURF-APPS-OPEN", Severity: rule.SevLow, Subject: subject,
			Title: names[0] + " acepta conexiones desde cualquier dirección",
			Detail: "El firewall deja sus puertos abiertos a cualquiera que llegue al equipo: si el programa tiene un fallo o una contraseña débil, " +
				"se puede atacar desde la red y, si la regla incluye el perfil Público, también en redes que no controlas (la wifi de un hotel o una cafetería). " +
				"Firewall: " + fwWhy + ".",
			Fix: "Si solo lo usas en este equipo o desde tu red, limita sus reglas a la red local; si no lo necesitas desde otros equipos, desactívalas.",
		}
		if inv.Firewall.Linux() {
			// Sin perfiles de red; la solución, con ufw (lo más habitual).
			f.Detail = strings.Replace(f.Detail, " y, si la regla incluye el perfil Público, también en redes que no controlas (la wifi de un hotel o una cafetería)", "", 1)
			port, proto, _ := strings.Cut(apps[appOrder[0]].ports[0], "/")
			f.Fix = fmt.Sprintf("Si solo lo usas desde tu red, limita la regla a esa red y borra la abierta; con ufw, por ejemplo: "+
				"ufw allow from 192.168.1.0/24 to any port %s proto %s (y ufw status numbered y ufw delete N para la abierta).", port, proto)
		}
		if len(appOrder) > 1 {
			f.Title = fmt.Sprintf("%d programas aceptan conexiones desde cualquier dirección: %s", len(appOrder), shortList(names, 3))
			f.Detail = strings.Replace(f.Detail, "si el programa tiene un fallo", "si alguno tiene un fallo", 1)
			if !inv.Firewall.Linux() {
				f.Fix = "Si solo los usas en este equipo o desde tu red, limita sus reglas a la red local; si no los necesitas desde otros equipos, desactívalas."
			}
		}
		if len(ids) > 0 && !noIDs {
			f.Fix += " " + limitCmd(ids)
			f.FirewallRules = ids
		}
		rep.Findings = append(rep.Findings, f)
	}
	if len(ephApps) > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("Sin analizar: %s tiene(n) sockets UDP en puertos dinámicos de todas las interfaces. "+
			"Suelen ser de clientes (QUIC, descubrimiento de red), pero si no reconoces el programa, revisa si acepta datos de la red.",
			shortList(ephApps, 4)))
	}
	rep.Findings = append(rep.Findings, binaryFindings(bins)...)
	rep.Findings = append(rep.Findings, shareFindings(inv.Shares)...)
	if inv.Firewall != nil {
		if rules := inv.Firewall.UserAllowAll(); len(rules) > 0 {
			var names []string
			profiles := 0
			for _, r := range rules {
				names = appendOnce(names, "«"+r.Name+"»")
				profiles |= r.Profiles
			}
			verb := "permite"
			if len(names) > 1 {
				verb = "permiten"
			}
			rep.Findings = append(rep.Findings, Finding{
				ID: "SURF-FW-USERALLOWALL", Severity: rule.SevMedium, Subject: "firewall", // las reglas van en el título
				Title: fmt.Sprintf("%s %s toda la entrada a los programas de un usuario (perfil %s)", shortList(names, 3), verb, ProfileNames(profiles&7)),
				Detail: "Cualquier programa que ejecute ese usuario, incluido uno malicioso, puede aceptar conexiones de cualquier puerto desde esas redes. " +
					"Los servicios del sistema no quedan cubiertos. Estas reglas suelen crearlas apps como la de Xbox para el juego en red.",
				Fix: fmt.Sprintf("Si no las necesitas, desactívalas: Get-NetFirewallRule %s | Disable-NetFirewallRule "+
					"(se pueden volver a activar con Enable-NetFirewallRule).", ruleSelector(rules)),
			})
		}
		for _, r := range inv.Firewall.AllowAll() {
			rep.Findings = append(rep.Findings, Finding{
				ID: "SURF-FW-ALLOWALL", Severity: rule.SevHigh, Subject: "firewall",
				Title: fmt.Sprintf("La regla de firewall «%s» permite toda la entrada (perfil %s)", r.Name, ProfileNames(r.Profiles)),
				Detail: "Admite cualquier protocolo y puerto, para cualquier programa y desde cualquier dirección: en esas redes " +
					"equivale a tener el firewall desactivado, y cualquier servicio que escuche queda accesible.",
				Fix: fmt.Sprintf("Si no sabes de dónde viene, desactívala y comprueba que todo sigue funcionando: "+
					"Get-NetFirewallRule %s | Disable-NetFirewallRule. Si un programa la necesita, "+
					"sustitúyela por una regla limitada a ese programa y sus puertos.", ruleSelector([]FirewallRule{r})),
			})
		}
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		if rep.Findings[i].Severity.Rank() != rep.Findings[j].Severity.Rank() {
			return rep.Findings[i].Severity.Rank() < rep.Findings[j].Severity.Rank()
		}
		return rep.Findings[i].Subject < rep.Findings[j].Subject
	})
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	if rep.Listeners == nil {
		rep.Listeners = []Listener{}
	}
	if rep.Ports == nil {
		rep.Ports = []Port{}
	}
	if rep.Shares == nil {
		rep.Shares = []Share{}
	}
	if rep.Admins == nil {
		rep.Admins = []Account{}
	}
	score := 100
	for _, f := range rep.Findings {
		score -= penalty[f.Severity]
	}
	if score < 0 {
		score = 0
	}
	rep.Score = score
	rep.Grade = grade(score)
	return rep
}

// lower baja un nivel la severidad.
func lower(s rule.Severity) rule.Severity {
	switch s {
	case rule.SevCritical:
		return rule.SevHigh
	case rule.SevHigh:
		return rule.SevMedium
	case rule.SevMedium:
		return rule.SevLow
	}
	return rule.SevInfo
}

// groupPorts une los sockets del mismo protocolo, puerto y proceso.
func groupPorts(ls []Listener) []Port {
	var out []Port
	idx := map[string]int{}
	for _, l := range ls {
		key := fmt.Sprintf("%s|%d|%d|%s", l.Proto, l.Port, l.PID, l.Process)
		i, ok := idx[key]
		if !ok {
			i = len(out)
			idx[key] = i
			out = append(out, Port{Proto: l.Proto, Port: l.Port, Scope: l.Scope, PID: l.PID, Process: l.Process,
				Services: l.Services, Ephemeral: l.Ephemeral, User: l.User, UserSID: l.UserSID,
				Path: l.Path, Signature: l.Signature, Signer: l.Signer})
		}
		p := &out[i]
		p.Addresses = appendOnce(p.Addresses, l.Address)
		if l.Scope == ScopeNetwork {
			p.Scope = ScopeNetwork
		}
		p.Ephemeral = p.Ephemeral && l.Ephemeral
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Scope == ScopeNetwork) != (out[j].Scope == ScopeNetwork) {
			return out[i].Scope == ScopeNetwork
		}
		if out[i].Ephemeral != out[j].Ephemeral {
			return !out[i].Ephemeral
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

// SIDs de grupos amplios: compartir con ellos es compartir con casi todos.
var broadSIDs = map[string]string{
	"S-1-1-0":      "Todos (Everyone)",
	"S-1-5-7":      "Anónimo",
	"S-1-5-11":     "Usuarios autenticados",
	"S-1-5-32-545": "Usuarios",
	"S-1-5-32-546": "Invitados",
}

func shareFindings(shares []Share) []Finding {
	var out []Finding
	for _, s := range shares {
		switch s.Kind {
		case "smb":
			for _, a := range s.Access {
				who, broad := broadSIDs[a.SID]
				if !broad || a.Deny {
					continue
				}
				sev, what := rule.SevMedium, "lectura"
				if a.Right == "Full" || a.Right == "Change" {
					sev, what = rule.SevHigh, "escritura"
				}
				out = append(out, Finding{
					ID: "SURF-SHARE-SMB", Severity: sev, Subject: `\\` + s.Name,
					Title:  fmt.Sprintf("Recurso compartido %s con %s para %s", s.Name, what, who),
					Detail: fmt.Sprintf("%s (%s) permite %s a %s: cualquier cuenta (o sesión anónima) puede acceder, y el ransomware cifra lo que puede escribir.", s.Name, s.Path, what, who),
					Fix:    "Concede el permiso solo a los grupos que lo necesitan (Grant-SmbShareAccess / Revoke-SmbShareAccess) y revisa también los permisos NTFS.",
				})
			}
		case "nfs":
			for _, o := range s.Options {
				switch o {
				case "no_root_squash":
					out = append(out, Finding{ID: "SURF-SHARE-NFS-ROOT", Severity: rule.SevHigh, Subject: s.Path,
						Title:  "Exportación NFS con no_root_squash: " + s.Path,
						Detail: "Un root remoto actúa como root en " + s.Path + ": puede dejar binarios setuid y escalar privilegios en este equipo.",
						Fix:    "Quita no_root_squash de /etc/exports y aplica con exportfs -ra."})
				case "*":
					out = append(out, Finding{ID: "SURF-SHARE-NFS-ALL", Severity: rule.SevMedium, Subject: s.Path,
						Title:  "Exportación NFS para cualquier cliente: " + s.Path,
						Detail: s.Path + " se exporta a cualquier dirección (*).",
						Fix:    "Limita los clientes a las redes o equipos que lo necesitan en /etc/exports."})
				}
			}
		case "samba":
			guest, writable := false, false
			for _, o := range s.Options {
				guest = guest || o == "guest ok"
				writable = writable || o == "writable"
			}
			if guest {
				sev, what := rule.SevMedium, "lectura"
				if writable {
					sev, what = rule.SevHigh, "escritura"
				}
				out = append(out, Finding{ID: "SURF-SHARE-SAMBA-GUEST", Severity: sev, Subject: "[" + s.Name + "]",
					Title:  fmt.Sprintf("Recurso Samba [%s] con acceso de invitado (%s)", s.Name, what),
					Detail: "guest ok = yes permite acceder sin contraseña a " + s.Path + ".",
					Fix:    "Pon guest ok = no y concede acceso con valid users."})
			}
		}
	}
	return out
}

// dedupe elimina sockets repetidos (mismo proto, dirección y puerto).
func dedupe(ls []Listener) []Listener {
	seen := map[string]bool{}
	out := ls[:0]
	for _, l := range ls {
		k := l.Proto + "|" + l.Address + "|" + strconv.Itoa(l.Port)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, l)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope == ScopeNetwork
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

func grade(v int) string {
	switch {
	case v >= 90:
		return "A"
	case v >= 80:
		return "B"
	case v >= 70:
		return "C"
	case v >= 60:
		return "D"
	}
	return "F"
}
