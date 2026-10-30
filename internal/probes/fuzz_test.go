package probes

import (
	"errors"
	"testing"
)

// Los parsers de ficheros y salidas del sistema no deben entrar en pánico
// con ninguna entrada. Para buscar fallos: go test -fuzz=FuzzSSHDConfig ./internal/probes

func FuzzSSHDConfig(f *testing.F) {
	f.Add("PermitRootLogin no\nInclude sshd_config.d/*.conf\nLoginGraceTime 1m30s\nKexAlgorithms -diffie-hellman-group1-sha1\nMatch User x\n  X11Forwarding yes\n")
	f.Add("MaxAuthTries=6\nCiphers +aes128-cbc\nClientAliveInterval 1h1m1s\nInclude /etc/ssh/a /etc/ssh/b\n")
	f.Fuzz(func(t *testing.T, s string) {
		read := func(p string) (string, error) {
			if p == "/etc/ssh/sshd_config" {
				return s, nil
			}
			return "", errors.New("no existe")
		}
		// El Include apunta otra vez al mismo fichero: el límite de
		// profundidad debe cortar la recursión.
		glob := func(string) ([]string, error) { return []string{"/etc/ssh/sshd_config"}, nil }
		parseSSHDConfig("/etc/ssh/sshd_config", read, glob)
		parseSSHDTest(s)
		parseSSHDTime(s)
		parseMountinfo(s)
		parseKV(s, "key", "=", true)
	})
}

func FuzzWindowsFormats(f *testing.F) {
	f.Add("[Unicode]\nUnicode=yes\n[System Access]\nMinimumPasswordLength = 14\n[Privilege Rights]\nSeDebugPrivilege = *S-1-5-32-544\n")
	f.Add("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\nPC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseSecpolINF(s)
		_, _ = parseAuditpolBackup(s)
	})
}
