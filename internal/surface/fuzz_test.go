package surface

import (
	"os"
	"testing"
)

// Los parsers leen la salida de herramientas del sistema y ficheros que
// pueden contener cualquier cosa: no deben entrar en pánico con ninguna
// entrada. go test los ejecuta con el corpus semilla; para buscar fallos:
//   go test -fuzz=FuzzNetfilter ./internal/surface

// fuzzPorts son los puertos con los que se evalúa cada política.
var fuzzPorts = []Port{
	{Proto: "tcp", Port: 22, Addresses: []string{"0.0.0.0"}, Scope: ScopeNetwork},
	{Proto: "udp", Port: 53, Addresses: []string{"::"}, Scope: ScopeNetwork},
	{Proto: "tcp", Port: 8080, Addresses: []string{"192.168.1.10", "fe80::1%2"}, Scope: ScopeNetwork, Process: "node.exe", Path: `C:\Program Files\nodejs\node.exe`},
}

func seedFile(f *testing.F, name string) {
	if b, err := os.ReadFile("testdata/" + name); err == nil {
		f.Add(b)
	}
}

func FuzzNetfilter(f *testing.F) {
	seedFile(f, "ufw-iptables-save.txt")
	seedFile(f, "ufw.rules")
	f.Add([]byte("*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK NONE -j DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"))
	f.Add([]byte("*filter\n-A INPUT -s 10.0.0.0/8 -p udp -m multiport --dports 53,67:68 -j ACCEPT\n-A INPUT -j ufw-user\n-N ufw-user\n-A ufw-user -j RETURN\nCOMMIT\n"))
	f.Fuzz(func(t *testing.T, save []byte) {
		fw, err := newLinuxFirewall(nil, string(save), string(save))
		if err != nil || fw == nil {
			return
		}
		for _, p := range fuzzPorts {
			fw.Evaluate(p)
		}
	})
}

func FuzzNftJSON(f *testing.F) {
	seedFile(f, "nft-firewalld.json")
	seedFile(f, "nft-nftables-conf.json")
	seedFile(f, "nft-ufw-iptables.json")
	f.Add([]byte(`{"nftables":[{"chain":{"family":"inet","table":"t","name":"in","hook":"input","policy":"drop"}},{"rule":{"family":"inet","table":"t","chain":"in","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"prefix":{"len":8}}}},{"accept":null}]}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		fw, err := newLinuxFirewall(data, "", "")
		if err != nil || fw == nil {
			return
		}
		for _, p := range fuzzPorts {
			fw.Evaluate(p)
		}
	})
}

func FuzzWindowsFirewallRule(f *testing.F) {
	f.Add(`v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|App=%ProgramFiles%\nodejs\node.exe|Name=node|`)
	f.Add(`v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|RPort=53|RPort2_10=Ply2Disc|RA4=LocalSubnet|Name=x|`)
	f.Add(`v2.33|Action=Block|Active=TRUE|Dir=In|LUAuth=O:LSD:(A;;CC;;;S-1-5-21-1)|Svc=Dnscache|Profile=Public|Name=y|`)
	f.Fuzz(func(t *testing.T, s string) {
		r, ok := parseRegRule(s)
		if !ok {
			return
		}
		fw := &Firewall{
			Profiles: []FirewallProfile{{Name: "Público", Bit: 4, Enabled: true, BlockInbound: true, Active: true}},
			Rules:    []FirewallRule{r},
		}
		for _, p := range fuzzPorts {
			fw.Evaluate(p)
		}
	})
}

func FuzzParsers(f *testing.F) {
	f.Add("  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234\n  UDP    [::]:5353              *:*                                    4321\n")
	f.Add("/srv/a\n/srv/b *(rw,no_root_squash) 10.0.0.0/8(ro)\n/srv/c \\\n  0.0.0.0/0(rw)\n")
	f.Add("[global]\n   guest ok = yes\n[datos]\n   path = /srv/datos\n   guest ok = yes\n")
	f.Add("  0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n")
	f.Add(`"svchost.exe","1760","RpcSs, RpcEptMapper"` + "\n" + `"bad "quote","x"` + "\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseNetstat(s)
		parseExports(s)
		parseSmbConf(s)
		parseTasklist(s)
		parseProcNet(s, "tcp", false)
		parseProcNet(s, "udp", true)
		parseLinuxAdmins(s, s)
		parseDpkgSearch(s)
		parseAddrs(s)
	})
}
