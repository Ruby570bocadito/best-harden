package surface

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/platform"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

// Los ficheros de testdata son salida real de nft 1.0.9 e iptables-nft
// 1.8.10, generada cargando nftables.conf, firewalld.nft y ufw.rules en un
// espacio de red aislado (unshare -n).

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fwCase struct {
	name  string
	p     Port
	state string
	limit string
	why   string // fragmento de la explicación
}

func checkCases(t *testing.T, fw *Firewall, cases []fwCase) {
	t.Helper()
	for _, c := range cases {
		a := fw.Evaluate(c.p)
		if a.State != c.state || a.Limit != c.limit || !strings.Contains(a.Why, c.why) {
			t.Errorf("%s: %s %q (%s), quiero %s %q (…%s…)", c.name, a.State, a.Limit, a.Why, c.state, c.limit, c.why)
		}
	}
}

var anyAddr4and6 = []string{"0.0.0.0", "::"}

func TestNftablesConf(t *testing.T) {
	fw, err := newLinuxFirewall(readTestdata(t, "nft-nftables-conf.json"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if fw.Source != "nftables" || fw.InputPolicy != "drop" || fw.InboundRules != 18 || !fw.Linux() {
		t.Errorf("firewall: %+v", fw)
	}
	checkCases(t, fw, []fwCase{
		{"SSH", Port{Proto: "tcp", Port: 22, Addresses: anyAddr4and6}, FirewallOpen, "", "«input #6»"},
		{"HTTPS por su comentario", Port{Proto: "tcp", Port: 443, Addresses: anyAddr4and6}, FirewallOpen, "", "«web»"},
		{"node_exporter desde un conjunto", Port{Proto: "tcp", Port: 9100, Addresses: []string{"0.0.0.0"}}, FirewallLimited, "10.8.0.0/24, 192.168.50.0/24", "«input #8»"},
		{"PostgreSQL por WireGuard", Port{Proto: "tcp", Port: 5432, Addresses: []string{"0.0.0.0"}}, FirewallLimited, "en la interfaz wg0", ""},
		{"WireGuard", Port{Proto: "udp", Port: 51820, Addresses: anyAddr4and6}, FirewallOpen, "", ""},
		{"rango desde la LAN", Port{Proto: "tcp", Port: 8005, Addresses: []string{"0.0.0.0"}}, FirewallLimited, "192.168.1.0/24", ""},
		{"SMTP bloqueado", Port{Proto: "tcp", Port: 25, Addresses: anyAddr4and6}, FirewallFiltered, "", "lo bloquea la regla «input #12»"},
		{"marca: no se evalúa", Port{Proto: "tcp", Port: 6379, Addresses: []string{"0.0.0.0"}}, FirewallLimited, "con condiciones que Adarve no evalúa", ""},
		{"subcadena solo IPv6", Port{Proto: "tcp", Port: 3000, Addresses: anyAddr4and6}, FirewallLimited, "fd00::/8", "«services #1»"},
		{"subcadena", Port{Proto: "udp", Port: 53, Addresses: anyAddr4and6}, FirewallOpen, "", "«services #2»"},
		{"sin regla", Port{Proto: "tcp", Port: 3306, Addresses: anyAddr4and6}, FirewallFiltered, "", "«input #15»"},
		{"Docker publica con DNAT", Port{Proto: "tcp", Port: 8080, Addresses: []string{"0.0.0.0"}, Process: "docker-proxy"}, FirewallOpen, "", "DNAT"},
	})
}

func TestFirewalld(t *testing.T) {
	fw, err := newLinuxFirewall(readTestdata(t, "nft-firewalld.json"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if fw.InputPolicy != "accept" {
		t.Errorf("la cadena de firewalld acepta por defecto y rechaza con una regla: %q", fw.InputPolicy)
	}
	checkCases(t, fw, []fwCase{
		{"SSH en la zona public", Port{Proto: "tcp", Port: 22, Addresses: anyAddr4and6}, FirewallOpen, "", "«filter_IN_public_allow #1»"},
		{"Cockpit", Port{Proto: "tcp", Port: 9090, Addresses: anyAddr4and6}, FirewallOpen, "", ""},
		{"regla enriquecida y zona trusted", Port{Proto: "tcp", Port: 5432, Addresses: []string{"0.0.0.0"}}, FirewallLimited, "10.0.0.0/8 y en la interfaz wg0", ""},
		{"solo por la zona trusted", Port{Proto: "tcp", Port: 3306, Addresses: anyAddr4and6}, FirewallLimited, "en la interfaz wg0", ""},
		{"mDNS solo multidifusión", Port{Proto: "udp", Port: 5353, Addresses: []string{"0.0.0.0"}}, FirewallLimited, "en la interfaz wg0", ""},
	})
	// Sin la zona trusted, lo que no permite public queda rechazado.
	nf := fw.nf
	for _, c := range nf.chains {
		if c.name == "filter_INPUT_POLICIES" {
			c.rules = c.rules[2:]
		}
	}
	checkCases(t, fw, []fwCase{
		{"rechazado", Port{Proto: "tcp", Port: 3306, Addresses: anyAddr4and6}, FirewallFiltered, "", "lo bloquea la regla «filter_INPUT_POLICIES"},
		{"solo desde 10.0.0.0/8", Port{Proto: "tcp", Port: 5432, Addresses: []string{"0.0.0.0"}}, FirewallLimited, "10.0.0.0/8", ""},
	})
}

func TestUfwIptablesSave(t *testing.T) {
	save := string(readTestdata(t, "ufw-iptables-save.txt"))
	fw, err := newLinuxFirewall(readTestdata(t, "nft-ufw-iptables.json"), save, "")
	if err != nil {
		t.Fatal(err)
	}
	// Las tablas de iptables-nft se leen de iptables-save, con todo el detalle.
	if fw.Source != "iptables" || fw.InputPolicy != "drop" {
		t.Errorf("firewall: %+v", fw)
	}
	v4 := []string{"0.0.0.0"}
	checkCases(t, fw, []fwCase{
		{"SSH por su comentario de ufw", Port{Proto: "tcp", Port: 22, Addresses: v4}, FirewallOpen, "", "«dapp_OpenSSH»"},
		{"MySQL desde la LAN y Tailscale", Port{Proto: "tcp", Port: 3306, Addresses: v4}, FirewallLimited, "Tailscale y 192.168.1.0/24", ""},
		{"multiport: rango", Port{Proto: "tcp", Port: 8005, Addresses: v4}, FirewallOpen, "", ""},
		{"multiport: suelto", Port{Proto: "tcp", Port: 9000, Addresses: v4}, FirewallOpen, "", ""},
		{"ufw limit", Port{Proto: "tcp", Port: 2222, Addresses: v4}, FirewallOpen, "", "«ufw-user-limit-accept #1»"},
		{"deny 25: solo por Tailscale", Port{Proto: "tcp", Port: 25, Addresses: v4}, FirewallLimited, "Tailscale", ""},
		{"mDNS a la multidifusión", Port{Proto: "udp", Port: 5353, Addresses: v4}, FirewallLimited, "Tailscale y hacia 224.0.0.251", ""},
		{"SMB de la política", Port{Proto: "tcp", Port: 445, Addresses: v4}, FirewallLimited, "Tailscale", ""},
	})
	// Sin la regla de Tailscale, lo no permitido queda filtrado.
	for _, c := range fw.nf.chains {
		if c.name == "ufw-user-input" {
			c.rules = append(c.rules[:2:2], c.rules[3:]...)
		}
	}
	checkCases(t, fw, []fwCase{
		{"política drop", Port{Proto: "tcp", Port: 8080, Addresses: v4}, FirewallFiltered, "", "descarta por defecto"},
		{"deny explícito", Port{Proto: "tcp", Port: 25, Addresses: v4}, FirewallFiltered, "", "«ufw-user-input"},
	})
}

func TestUfwOnlyNftJSON(t *testing.T) {
	// Sin iptables-save, nft no traduce multiport, conntrack ni addrtype:
	// no debe darse nada por bloqueado sin motivo.
	fw, err := newLinuxFirewall(readTestdata(t, "nft-ufw-iptables.json"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	v4 := []string{"0.0.0.0"}
	checkCases(t, fw, []fwCase{
		{"SSH", Port{Proto: "tcp", Port: 22, Addresses: v4}, FirewallOpen, "", ""},
		{"multiport sin detalle", Port{Proto: "tcp", Port: 8005, Addresses: v4}, FirewallLimited, "Tailscale y con condiciones que Adarve no evalúa", ""},
	})
}

func TestLinuxFirewallEmptyAndAnalyze(t *testing.T) {
	fw, err := newLinuxFirewall(nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if a := fw.Evaluate(Port{Proto: "tcp", Port: 22, Addresses: []string{"0.0.0.0"}}); a.State != FirewallOpen || !strings.Contains(a.Why, "no tiene reglas") {
		t.Errorf("sin reglas: %+v", a)
	}
	fw, _ = newLinuxFirewall(readTestdata(t, "nft-nftables-conf.json"), "", "")
	inv := Inventory{Firewall: fw, Listeners: []Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 22, Scope: ScopeNetwork, Process: "sshd"},
		{Proto: "tcp", Address: "0.0.0.0", Port: 3306, Scope: ScopeNetwork, Process: "mysqld"},
		{Proto: "tcp", Address: "0.0.0.0", Port: 5432, Scope: ScopeNetwork, Process: "postgres"},
	}}
	rep := Analyze(inv, platform.Info{}, "test", time.Now())
	if rep.Exposed != 3 || rep.Reachable != 2 || rep.Limited != 1 {
		t.Errorf("expuestos %d, accesibles %d, limitados %d", rep.Exposed, rep.Reachable, rep.Limited)
	}
	// MySQL filtrado no es hallazgo; PostgreSQL por WireGuard baja a bajo.
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "SURF-PORT-5432" || rep.Findings[0].Severity != rule.SevLow {
		t.Errorf("hallazgos: %+v", rep.Findings)
	}

	// WireGuard solo responde a pares autenticados: abierto a propósito,
	// no es un programa abierto.
	inv.Listeners = append(inv.Listeners, Listener{Proto: "udp", Address: "0.0.0.0", Port: 51820, Scope: ScopeNetwork, Process: "wg-quick"})
	rep = Analyze(inv, platform.Info{}, "test", time.Now())
	if len(rep.Findings) != 1 {
		t.Errorf("WireGuard abierto no es un hallazgo: %+v", rep.Findings)
	}

	// Un programa abierto a cualquiera: la solución habla de ufw, no de
	// perfiles de Windows.
	fw, err = newLinuxFirewall(nil, "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -m tcp --dport 8766 -j ACCEPT\nCOMMIT\n", "")
	if err != nil {
		t.Fatal(err)
	}
	inv = Inventory{Firewall: fw, Listeners: []Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 8766, Scope: ScopeNetwork, Process: "autoclaw"}}}
	rep = Analyze(inv, platform.Info{}, "test", time.Now())
	var apps *Finding
	for i := range rep.Findings {
		if rep.Findings[i].ID == "SURF-APPS-OPEN" {
			apps = &rep.Findings[i]
		}
	}
	if apps == nil || !strings.Contains(apps.Fix, "ufw allow from 192.168.1.0/24 to any port 8766 proto tcp") ||
		strings.Contains(apps.Detail, "perfil") || !strings.Contains(apps.Detail, "«INPUT #1»") {
		t.Errorf("programa abierto en Linux: %+v", apps)
	}
}

func TestIptablesArgs(t *testing.T) {
	got := splitArgs(`ufw-user-input -p tcp --dport 22 -m comment --comment "\'dapp_OpenSSH\'" -j ACCEPT`)
	if len(got) != 11 || got[9] != "-j" || got[8] != "'dapp_OpenSSH'" {
		t.Errorf("splitArgs: %q", got)
	}
	r := iptRule(strings.Fields("-s 10.0.0.0/8 ! -i lo -p udp -m multiport --dports 53,5000:5010 -m conntrack --ctstate NEW -j ACCEPT"), "ip")
	if r.proto != "udp" || len(r.ports) != 2 || r.ports[1] != (portRange{5000, 5010}) || r.skip || r.unknown || joinHuman(r.limits) != "10.0.0.0/8" || r.verdict != "accept" {
		t.Errorf("iptRule: %+v", r)
	}
	if r := iptRule(strings.Fields("-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"), "ip"); !r.skip {
		t.Error("ESTABLISHED no se aplica a conexiones nuevas")
	}
	if r := iptRule(strings.Fields("-m addrtype --dst-type BROADCAST -j ufw-skip-to-policy-input"), "ip"); !r.skip || r.verdict != "jump" {
		t.Errorf("difusión: %+v", r)
	}
	if r := iptRule(strings.Fields("-m recent --update --seconds 30 -j DROP"), "ip"); !r.unknown {
		t.Error("recent no se evalúa")
	}
}
