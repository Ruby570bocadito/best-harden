package surface

import (
	"os"
	"path/filepath"
	"testing"
)

// Los parsers leen la salida de herramientas del sistema auditado, que puede
// estar manipulada o ser de una versión que no conocemos: ninguna entrada
// debe hacer caer a Adarve. Se ejecutan como tests normales con las semillas
// y, en el CI, con "go test -fuzz" (ver .github/workflows/fuzz.yml).

func seed(f *testing.F, names ...string) {
	f.Helper()
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("testdata", n))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
}

// Un firewall de Linux (nftables + iptables-save) evaluado contra puertos.
func FuzzLinuxFirewall(f *testing.F) {
	seed(f, "nft-firewalld.json", "nft-nftables-conf.json", "nft-ufw-iptables.json", "ufw-iptables-save.txt")
	f.Add([]byte(`{"nftables":[{"chain":{"family":"inet","table":"t","name":"input","hook":"input","policy":"drop"}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ports := []Port{
			{Proto: "tcp", Port: 22, Addresses: []string{"0.0.0.0"}, Scope: "network"},
			{Proto: "udp", Port: 53, Addresses: []string{"::"}, Scope: "network"},
		}
		// La misma entrada como JSON de nftables y como iptables-save.
		for _, fw := range []func() (*Firewall, error){
			func() (*Firewall, error) { return newLinuxFirewall(data, "", "") },
			func() (*Firewall, error) { return newLinuxFirewall(nil, string(data), string(data)) },
		} {
			w, err := fw()
			if err != nil || w == nil {
				continue
			}
			for _, p := range ports {
				w.Evaluate(p)
			}
			w.AllowAll()
			w.Uncovered()
		}
	})
}

func FuzzParseNetstat(f *testing.F) {
	f.Add("  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234\r\n  UDP    [::]:5353              *:*                                    5678\r\n")
	f.Fuzz(func(t *testing.T, s string) { parseNetstat(s) })
}

func FuzzParseTasklist(f *testing.F) {
	f.Add(`"svchost.exe","1234","Services","0","10,000 K","Running","NT AUTHORITY\SYSTEM","0:00:01","N/A"` + "\r\n")
	f.Fuzz(func(t *testing.T, s string) { parseTasklist(s) })
}

func FuzzParseProcNet(f *testing.F) {
	f.Add("  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n", false)
	f.Add("   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 0 0 0 0 0 1\n", true)
	f.Fuzz(func(t *testing.T, s string, v6 bool) {
		parseProcNet(s, "tcp", v6)
		parseProcNet(s, "udp", v6)
	})
}

func FuzzParseShares(f *testing.F) {
	f.Add("/srv *(rw,no_root_squash)\n/home 192.168.1.0/24(ro)\n")
	f.Add("[global]\nworkgroup = X\n[pub]\npath = /srv\nguest ok = yes\nwritable = yes\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseExports(s)
		parseSmbConf(s)
	})
}

func FuzzParseLinuxAdmins(f *testing.F) {
	f.Add("root:x:0:0:root:/root:/bin/bash\nana:x:1000:1000::/home/ana:/bin/bash\n", "sudo:x:27:ana\nwheel:x:10:\n")
	f.Fuzz(func(t *testing.T, passwd, group string) { parseLinuxAdmins(passwd, group) })
}

// Reglas del firewall de Windows tal como están en el registro.
func FuzzParseRegRule(f *testing.F) {
	f.Add("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|RA4=LocalSubnet|Profile=Private|App=%SystemRoot%\\system32\\svchost.exe|Svc=TermService|Name=RDP|")
	f.Fuzz(func(t *testing.T, s string) { parseRegRule(s) })
}
