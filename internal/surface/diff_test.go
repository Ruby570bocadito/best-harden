package surface

import (
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

func TestDiff(t *testing.T) {
	ayer := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	port := func(p int, proto, proc, fw, limit string) Port {
		return Port{Proto: proto, Port: p, Addresses: []string{"0.0.0.0"}, Scope: ScopeNetwork, Process: proc, Firewall: fw, FirewallLimit: limit}
	}
	prev := &Report{FinishedAt: ayer, Score: 70, Ports: []Port{
		port(22, "tcp", "sshd.exe", FirewallOpen, ""),
		port(445, "tcp", "System", FirewallLimited, "la red local"),
		port(3389, "tcp", "svchost.exe", FirewallOpen, ""),
		port(8080, "tcp", "app.exe", FirewallOpen, ""),
		port(5353, "udp", "chrome.exe", FirewallOpen, ""),
		{Proto: "udp", Port: 60000, Scope: ScopeNetwork, Ephemeral: true, Process: "svchost.exe"},
	}, Findings: []Finding{
		{ID: "SURF-PORT-445", Severity: rule.SevLow, Subject: "445/tcp", Title: "SMB accesible solo desde la red local (System)"},
		{ID: "SURF-PORT-3389", Severity: rule.SevHigh, Subject: "3389/tcp", Title: "RDP accesible desde la red (svchost.exe)"},
	}}
	cur := &Report{Score: 55, Ports: []Port{
		port(22, "tcp", "sshd.exe", FirewallOpen, ""),
		port(445, "tcp", "System", FirewallOpen, ""),
		port(3389, "tcp", "svchost.exe", FirewallLimited, "la red local"),
		port(8766, "tcp", "AutoClaw.exe", FirewallOpen, ""),
		port(5353, "udp", "chrome.exe", FirewallOpen, ""),
		{Proto: "udp", Port: 61000, Scope: ScopeNetwork, Ephemeral: true, Process: "svchost.exe"},
	}, Findings: []Finding{
		{ID: "SURF-PORT-445", Severity: rule.SevHigh, Subject: "445/tcp", Title: "SMB accesible desde la red (System)"},
		{ID: "SURF-APPS-OPEN", Severity: rule.SevLow, Subject: "8766/tcp", Title: "AutoClaw.exe (8766/tcp) acepta conexiones desde cualquier dirección"},
	}}
	ch := Diff(prev, cur)
	if !ch.Since.Equal(ayer) || ch.ScoreBefore != 70 {
		t.Errorf("cabecera: %+v", ch)
	}
	var got []string
	for _, c := range ch.Items {
		got = append(got, c.Kind+" "+c.Title)
	}
	want := []string{
		"worse 445/tcp (System): limitado: la red local → abierto a cualquiera",
		"new 8766/tcp (AutoClaw.exe) escucha en la red: abierto a cualquiera",
		"finding AutoClaw.exe (8766/tcp) acepta conexiones desde cualquier dirección",
		"better 3389/tcp (svchost.exe): abierto a cualquiera → limitado: la red local",
		"gone 8080/tcp (app.exe) ya no escucha en la red",
		"resolved RDP accesible desde la red (svchost.exe)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("cambios:\n%s\n\nquiero:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	bad := 0
	for _, c := range ch.Items {
		if c.Bad() {
			bad++
		}
	}
	if bad != 3 {
		t.Errorf("cambios que aumentan la exposición: %d, quiero 3", bad)
	}
	// Sin cambios: lista vacía, no nil (el JSON dice "items": []).
	if same := Diff(cur, cur); same.Items == nil || len(same.Items) != 0 {
		t.Errorf("sin cambios: %+v", same.Items)
	}
}

func TestDiffGroupedFindings(t *testing.T) {
	f := func(id, subject, title string) Finding {
		return Finding{ID: id, Severity: rule.SevLow, Subject: subject, Title: title}
	}
	prev := &Report{Findings: []Finding{
		f("SURF-NETBIOS", "137/udp, 138/udp, 139/tcp", "NetBIOS…"),
		f("SURF-APPS-OPEN", "4530/tcp, 8766/tcp, 57621/tcp", "3 programas…"),
		f("SURF-FW-ALLOWALL", "firewall", "La regla de firewall «Vieja» permite toda la entrada (perfil Privado)"),
		f("SURF-SUNSHINE", "47984/tcp, 47989/tcp, 47990/tcp, 48010/tcp", "Sunshine/GameStream…"),
	}}
	cur := &Report{Findings: []Finding{
		f("SURF-SUNSHINE", "47984/tcp, 47989/tcp, 47990/tcp, 47998/udp, 48010/tcp", "Sunshine/GameStream…"), // transmitiendo: no es nuevo
		f("SURF-NETBIOS", "137/udp, 138/udp", "NetBIOS…"),                                                   // se ha filtrado 139: no es nuevo
		f("SURF-APPS-OPEN", "4530/tcp, 8766/tcp", "2 programas…"),                                           // se ha cerrado Spotify: no es nuevo
		f("SURF-FW-ALLOWALL", "firewall", "La regla de firewall «Vieja» permite toda la entrada (perfil Privado)"),
		f("SURF-FW-ALLOWALL", "firewall", "La regla de firewall «Nueva» permite toda la entrada (perfil Público)"),
	}}
	ch := Diff(prev, cur)
	if len(ch.Items) != 1 || ch.Items[0].Kind != ChangeFinding || !strings.Contains(ch.Items[0].Title, "«Nueva»") {
		t.Errorf("solo la nueva regla que lo permite todo es un hallazgo nuevo: %+v", ch.Items)
	}
}
