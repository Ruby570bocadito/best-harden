package probes

import "testing"

// Los parsers leen la salida de herramientas del sistema auditado (sshd -T,
// /proc/self/mountinfo, secedit, auditpol…): ninguna entrada debe hacer
// caer a Adarve. Ver también internal/surface/fuzz_test.go.

func FuzzParseSSHD(f *testing.F) {
	f.Add("permitrootlogin no\nmaxauthtries 4\nlogingracetime 60\nciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n")
	f.Add("ClientAliveInterval 1h30m\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseSSHDTest(s)
		k, v := splitSSHDLine(s)
		_, _ = k, v
		parseSSHDTime(s)
	})
}

func FuzzParseMountinfo(f *testing.F) {
	f.Add("36 35 98:0 /mnt1 /mnt\\040con\\040espacio rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n")
	f.Fuzz(func(t *testing.T, s string) {
		entries := parseMountinfo(s)
		findMount(entries, "/tmp")
		unescapeMount(s)
	})
}

func FuzzModprobe(f *testing.F) {
	f.Add("install cramfs /bin/false\nblacklist cramfs\n# comentario\n", "cramfs")
	f.Fuzz(func(t *testing.T, text, module string) {
		modprobeDirectives([]string{text, text}, module)
	})
}

func FuzzParseSecpol(f *testing.F) {
	f.Add("[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nMinimumPasswordLength = 14\r\nNewAdministratorName = \"Admin\"\r\n[Privilege Rights]\r\nSeDebugPrivilege = *S-1-5-32-544\r\n")
	f.Fuzz(func(t *testing.T, s string) {
		for section, kv := range parseSecpolINF(s) {
			for _, v := range kv {
				secpolValue(section, v)
			}
		}
	})
}

func FuzzParseAuditpol(f *testing.F) {
	f.Add("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\nPC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3\r\n")
	f.Fuzz(func(t *testing.T, s string) { _, _ = parseAuditpolBackup(s) })
}

func FuzzSplitRegistryPath(f *testing.F) {
	f.Add(`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`)
	f.Add(`HKEY_CURRENT_USER\Software`)
	f.Fuzz(func(t *testing.T, s string) { _, _, _ = splitRegistryPath(s) })
}

// Texto de herramientas en UTF-16, UTF-8 o la página de códigos del sistema.
func FuzzDecodeText(f *testing.F) {
	f.Add([]byte{0xff, 0xfe, 'a', 0, 'b', 0})
	f.Add([]byte("año"))
	f.Fuzz(func(t *testing.T, b []byte) { decodeText(b) })
}
