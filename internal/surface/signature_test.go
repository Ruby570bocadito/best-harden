package surface

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

func TestParsePSSignatures(t *testing.T) {
	data := map[string]any{"files": map[string]any{
		`C:\Windows\System32\svchost.exe`:                                  map[string]any{"status": "Valid", "signer": "CN=Microsoft Windows Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"},
		`C:\Program Files (x86)\Steam\steam.exe`:                           map[string]any{"status": "Valid", "signer": `CN="Valve Corp.", O="Valve Corp.", C=US`},
		`C:\Users\rafag\AppData\Local\Programs\hydra\hydra-python-rpc.exe`: map[string]any{"status": "NotSigned", "signer": ""},
		`C:\Tools\patched.exe`:                                             map[string]any{"status": "HashMismatch", "signer": "CN=Contoso Ltd, O=Contoso"},
		`C:\Tools\selfsigned.exe`:                                          map[string]any{"status": "NotTrusted", "signer": "CN=Mi Empresa"},
		`C:\Tools\weird.bin`:                                               map[string]any{"status": "NotSupportedFileFormat", "signer": ""},
	}}
	got := parsePSSignatures(data)
	want := map[string]sigInfo{
		`c:\windows\system32\svchost.exe`:                                  {SigValid, "Microsoft Windows Publisher"},
		`c:\program files (x86)\steam\steam.exe`:                           {SigValid, "Valve Corp."},
		`c:\users\rafag\appdata\local\programs\hydra\hydra-python-rpc.exe`: {SigUnsigned, ""},
		`c:\tools\patched.exe`:                                             {SigInvalid, "Contoso Ltd"},
		`c:\tools\selfsigned.exe`:                                          {SigUntrusted, "Mi Empresa"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("firmas:\n%v\nquiero\n%v", got, want)
	}
	if got := certCN("O=Sin Nombre Común, C=ES"); got != "O=Sin Nombre Común, C=ES" {
		t.Errorf("sin CN: %q", got)
	}
}

func TestParsePackageQueries(t *testing.T) {
	dpkg := "openssh-server: /usr/sbin/sshd\n" +
		"libc-bin, libc6:amd64: /usr/sbin/ldconfig\n" +
		"docker.io:amd64: /usr/bin/docker-proxy\n" +
		"diversion by dash from: /bin/sh\n"
	got := parseDpkgSearch(dpkg)
	want := map[string]string{"/usr/sbin/sshd": "openssh-server", "/usr/sbin/ldconfig": "libc-bin", "/usr/bin/docker-proxy": "docker.io"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dpkg: %v", got)
	}
	paths := []string{"/usr/sbin/sshd", "/opt/app/server"}
	rpm := "openssh-server\nfile /opt/app/server is not owned by any package\n"
	if got := parseRpmQuery(paths, rpm); !reflect.DeepEqual(got, map[string]string{"/usr/sbin/sshd": "openssh-server"}) {
		t.Errorf("rpm: %v", got)
	}
	if got := parseRpmQuery(paths, "openssh-server\n"); len(got) != 0 {
		t.Errorf("salida incompleta de rpm: %v", got)
	}
	for in, want := range map[string]string{"/usr/sbin/sshd": "/sbin/sshd", "/bin/foo": "/usr/bin/foo", "/opt/x": "", "/usr/local/bin/x": ""} {
		if got := usrMergeAlt(in); got != want {
			t.Errorf("usrMergeAlt(%s) = %q", in, got)
		}
	}
	if snapName("/snap/syncthing/123/syncthing") != "syncthing" || snapName("/snapx/a/b") != "" {
		t.Error("snapName")
	}
}

func TestBinaryFindings(t *testing.T) {
	fw := &Firewall{Source: "registry", Profiles: []FirewallProfile{
		{Name: "Privado", Bit: 2, Enabled: true, BlockInbound: true, Active: true},
	}, Rules: []FirewallRule{
		{ID: "{HYDRA}", Name: "hydra", Allow: true, Protocol: 256, App: `C:\Users\rafag\AppData\Local\Programs\hydra\hydra-python-rpc.exe`, Profiles: 2},
		{ID: "{CLAW}", Name: "AutoClaw", Allow: true, Protocol: 6, App: `C:\AutoClaw\AutoClaw.exe`, Profiles: 2, Remote: "LocalSubnet"},
		{ID: "{PATCHED}", Name: "Tool", Allow: true, Protocol: 6, App: `C:\Tools\tool.exe`, Profiles: 2},
		{ID: "{STEAM}", Name: "Steam", Allow: true, Protocol: 256, App: `C:\Steam\steam.exe`, Profiles: 2},
	}}
	hydra := `C:\Users\rafag\AppData\Local\Programs\hydra\hydra-python-rpc.exe`
	inv := Inventory{Firewall: fw, Listeners: []Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 5881, Scope: ScopeNetwork, PID: 10, Process: "hydra-python-rpc.exe", Path: hydra, Signature: SigUnsigned},
		{Proto: "udp", Address: "0.0.0.0", Port: 5881, Scope: ScopeNetwork, PID: 10, Process: "hydra-python-rpc.exe", Path: hydra, Signature: SigUnsigned},
		{Proto: "tcp", Address: "0.0.0.0", Port: 8766, Scope: ScopeNetwork, PID: 11, Process: "AutoClaw.exe", Path: `C:\AutoClaw\AutoClaw.exe`, Signature: SigUnsigned},
		{Proto: "tcp", Address: "0.0.0.0", Port: 9000, Scope: ScopeNetwork, PID: 12, Process: "tool.exe", Path: `C:\Tools\tool.exe`, Signature: SigInvalid, Signer: "Contoso Ltd"},
		{Proto: "tcp", Address: "0.0.0.0", Port: 27036, Scope: ScopeNetwork, PID: 13, Process: "steam.exe", Path: `C:\Steam\steam.exe`, Signature: SigValid, Signer: "Valve Corp."},
		// Filtrado por el firewall: sin firma, pero nadie llega.
		{Proto: "tcp", Address: "0.0.0.0", Port: 9999, Scope: ScopeNetwork, PID: 14, Process: "nadie.exe", Path: `C:\x\nadie.exe`, Signature: SigUnsigned},
		// Solo local: no cuenta.
		{Proto: "tcp", Address: "127.0.0.1", Port: 9998, Scope: ScopeLoopback, PID: 15, Process: "local.exe", Path: `C:\x\local.exe`, Signature: SigUnsigned},
	}}
	rep := Analyze(inv, platform.Info{Role: "workstation"}, "test", time.Now())
	byID := map[string]Finding{}
	for _, f := range rep.Findings {
		byID[f.ID] = f
	}
	u := byID["SURF-UNSIGNED"]
	if u.Severity != rule.SevLow || u.Title != "2 programas sin firma digital aceptan conexiones desde la red: hydra-python-rpc.exe (5881/tcp, 5881/udp) y AutoClaw.exe (8766/tcp)" ||
		!strings.Contains(u.Detail, hydra) || strings.Contains(u.Detail, "nadie.exe") || strings.Contains(u.Detail, "local.exe") {
		t.Errorf("sin firma: %+v", u)
	}
	b := byID["SURF-BADSIG"]
	if b.Severity != rule.SevHigh || !strings.HasPrefix(b.Title, "La firma de tool.exe no es válida") || !strings.Contains(b.Detail, "Contoso Ltd") ||
		!strings.Contains(b.Fix, `-ScanPath 'C:\Tools\tool.exe'`) || b.Subject != "9000/tcp" {
		t.Errorf("firma no válida: %+v", b)
	}
	for _, p := range rep.Ports {
		if p.Port == 27036 && (p.Signature != SigValid || p.Signer != "Valve Corp." || p.Path != `C:\Steam\steam.exe`) {
			t.Errorf("Steam: %+v", p)
		}
	}

	// Linux: fuera de los paquetes.
	inv = Inventory{Listeners: []Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 18081, Scope: ScopeNetwork, PID: 20, Process: "mi-servidor", Path: "/opt/mi/servidor", Signature: SigNoPackage},
		{Proto: "tcp", Address: "0.0.0.0", Port: 22, Scope: ScopeNetwork, PID: 21, Process: "sshd", Path: "/usr/sbin/sshd", Signature: SigPackage, Signer: "openssh-server"},
	}}
	rep = Analyze(inv, platform.Info{Role: "server"}, "test", time.Now())
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "SURF-UNPACKAGED" ||
		rep.Findings[0].Title != "mi-servidor (18081/tcp) no es de ningún paquete y acepta conexiones desde la red" {
		t.Fatalf("Linux: %+v", rep.Findings)
	}
}

func TestParseVerify(t *testing.T) {
	out := `??5??????   /usr/sbin/sshd
??5?????? c /etc/ssh/sshd_config
?????????   /usr/bin/a
S.5....T.    /usr/bin/b
missing     /usr/bin/c
.M.......    /usr/bin/d
`
	got := parseVerify(out)
	for p, want := range map[string]bool{"/usr/sbin/sshd": true, "/etc/ssh/sshd_config": true, "/usr/bin/b": true,
		"/usr/bin/a": false, "/usr/bin/c": false, "/usr/bin/d": false} {
		if got[p] != want {
			t.Errorf("%s: %v, quiero %v", p, got[p], want)
		}
	}
}

func TestModifiedPackageFinding(t *testing.T) {
	inv := Inventory{Listeners: []Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 22, Scope: ScopeNetwork, PID: 21, Process: "sshd", Path: "/usr/sbin/sshd", Signature: SigModified, Signer: "openssh-server"},
	}}
	rep := Analyze(inv, platform.Info{Role: "server"}, "test", time.Now())
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "SURF-BADSIG" || rep.Findings[0].Severity != rule.SevHigh {
		t.Fatalf("binario modificado: %+v", rep.Findings)
	}
	if o, warn := rep.Ports[0].Origin(); !warn || o != "modificado respecto al paquete openssh-server" {
		t.Errorf("origen: %q %v", o, warn)
	}
}
