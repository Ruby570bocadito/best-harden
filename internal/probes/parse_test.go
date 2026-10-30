package probes

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseSSHDConfig(t *testing.T) {
	files := map[string]string{
		"/etc/ssh/sshd_config": `
# comentario
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin yes
LoginGraceTime 1m30s
MaxAuthTries=6
Match User backup
	PermitRootLogin no
	X11Forwarding yes
`,
		"/etc/ssh/sshd_config.d/00-bastion.conf": "PermitRootLogin no\nX11Forwarding no\n",
	}
	read := func(p string) (string, error) {
		if s, ok := files[p]; ok {
			return s, nil
		}
		return "", errors.New("no existe")
	}
	glob := func(p string) ([]string, error) {
		if p == "/etc/ssh/sshd_config.d/*.conf" {
			return []string{"/etc/ssh/sshd_config.d/00-bastion.conf"}, nil
		}
		return nil, nil
	}
	m := parseSSHDConfig("/etc/ssh/sshd_config", read, glob)
	want := map[string]string{
		"permitrootlogin": "no", // gana el Include (primera aparición)
		"x11forwarding":   "no", // el bloque Match se ignora
		"logingracetime":  "90",
		"maxauthtries":    "6",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, quiero %q", k, m[k], v)
		}
	}
}

func TestParseSSHDConfigAlgoPrefixes(t *testing.T) {
	files := map[string]string{"/c": "KexAlgorithms -diffie-hellman-group1-sha1\nKexAlgorithms curve25519-sha256\nCiphers +aes128-cbc\n"}
	read := func(p string) (string, error) { return files[p], nil }
	m := parseSSHDConfig("/c", read, func(string) ([]string, error) { return nil, nil })
	if _, ok := m["kexalgorithms"]; ok {
		t.Errorf("con \"-\" debe usarse el valor por defecto, no %q (ni la segunda línea)", m["kexalgorithms"])
	}
	if m["ciphers"] != "aes128-cbc" {
		t.Errorf("ciphers = %q", m["ciphers"])
	}
}

func TestParseSSHDTest(t *testing.T) {
	m := parseSSHDTest("port 22\npermitrootlogin without-password\nhostkey /a\nhostkey /b\n")
	if m["permitrootlogin"] != "without-password" || m["hostkey"] != "/a,/b" {
		t.Errorf("parse inesperado: %v", m)
	}
}

func TestParseSSHDTime(t *testing.T) {
	for in, want := range map[string]int{"60": 60, "1m": 60, "1m30s": 90, "2h": 7200, "1h1m1s": 3661} {
		got, ok := parseSSHDTime(in)
		if !ok || got != want {
			t.Errorf("parseSSHDTime(%q) = %d, %v", in, got, ok)
		}
	}
	if _, ok := parseSSHDTime("1x"); ok {
		t.Error("unidad inválida aceptada")
	}
}

func TestParseMountinfo(t *testing.T) {
	text := `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
35 22 0:31 / /tmp rw,nosuid,nodev,noexec shared:15 - tmpfs tmpfs rw,size=1024k
36 22 0:32 / /mnt/my\040disk rw - ext4 /dev/sdb1 rw
37 22 0:33 / /tmp rw,nosuid shared:16 - tmpfs tmpfs rw
`
	es := parseMountinfo(text)
	if len(es) != 4 {
		t.Fatalf("entradas = %d", len(es))
	}
	e, ok := findMount(es, "/tmp")
	if !ok || !reflect.DeepEqual(e.Options, []string{"rw", "nosuid"}) {
		t.Errorf("/tmp debería ser el último montaje: %+v", e)
	}
	if _, ok := findMount(es, "/mnt/my disk"); !ok {
		t.Error("escape \\040 no decodificado")
	}
}

func TestModprobeDirectives(t *testing.T) {
	texts := []string{"# x\ninstall cramfs /bin/false\nblacklist cramfs\n", "install usb-storage /usr/bin/true\n"}
	dis, bl, _ := modprobeDirectives(texts, "cramfs")
	if !dis || !bl {
		t.Errorf("cramfs: disabled=%v blacklisted=%v", dis, bl)
	}
	dis, bl, _ = modprobeDirectives(texts, "usb_storage")
	if !dis || bl {
		t.Errorf("usb_storage: disabled=%v blacklisted=%v", dis, bl)
	}
}

func TestParseKV(t *testing.T) {
	v, ok := parseKV("PASS_MAX_DAYS\t99999\n#PASS_MAX_DAYS 1\nPASS_MAX_DAYS 365\n", "PASS_MAX_DAYS", "", false)
	if !ok || v != "365" {
		t.Errorf("login.defs: %q %v", v, ok)
	}
	v, ok = parseKV("[Journal]\nstorage = persistent\n", "Storage", "=", true)
	if !ok || v != "persistent" {
		t.Errorf("ini: %q %v", v, ok)
	}
}

func TestParseSecpolINF(t *testing.T) {
	text := "[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nMinimumPasswordLength = 14\r\nNewGuestName = \"Invitado\"\r\n" +
		"[Privilege Rights]\r\nSeDebugPrivilege = *S-1-5-32-544\r\nSeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551\r\n" +
		"[Registry Values]\r\nMACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,1\r\n"
	m := parseSecpolINF(text)
	if v := secpolValue("system access", m["system access"]["minimumpasswordlength"]); v != int64(14) {
		t.Errorf("MinimumPasswordLength = %#v", v)
	}
	if v := secpolValue("system access", m["system access"]["newguestname"]); v != "Invitado" {
		t.Errorf("NewGuestName = %#v", v)
	}
	if v := secpolValue("privilege rights", m["privilege rights"]["sebackupprivilege"]); !reflect.DeepEqual(v, []any{"S-1-5-32-544", "S-1-5-32-551"}) {
		t.Errorf("SeBackupPrivilege = %#v", v)
	}
	if v := secpolValue("registry values", m["registry values"][`machine\system\currentcontrolset\control\lsa\nolmhash`]); v != int64(1) {
		t.Errorf("NoLMHash = %#v", v)
	}
}

func TestParseAuditpolBackup(t *testing.T) {
	text := "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\n" +
		"PC,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,,1\n" +
		"PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3\n" +
		"PC,System,Option:CrashOnAuditFail,,Disabled,,0\n"
	m, err := parseAuditpolBackup(text)
	if err != nil {
		t.Fatal(err)
	}
	if m["0cce922b-69ae-11d9-bed3-505054503030"].Value != 1 || m["0cce9215-69ae-11d9-bed3-505054503030"].Value != 3 {
		t.Errorf("auditpol: %+v", m)
	}
	if len(m) != 2 {
		t.Errorf("filas = %d, quiero 2", len(m))
	}
}

func TestDecodeTextUTF16(t *testing.T) {
	b := []byte{0xFF, 0xFE, 'h', 0, 'o', 0, 'l', 0, 'a', 0}
	if s := decodeText(b); s != "hola" {
		t.Errorf("UTF-16LE = %q", s)
	}
	if s := decodeText([]byte("\xef\xbb\xbfhola")); s != "hola" {
		t.Errorf("UTF-8 BOM = %q", s)
	}
}

func TestSplitRegistryPath(t *testing.T) {
	root, sub, err := splitRegistryPath(`HKEY_LOCAL_MACHINE\SOFTWARE\Policies`)
	if err != nil || root != "HKLM" || sub != `SOFTWARE\Policies` {
		t.Errorf("%s %s %v", root, sub, err)
	}
	if _, _, err := splitRegistryPath(`HKCU\x`); err == nil {
		t.Error("HKCU debería rechazarse (Bastion audita el equipo, no un usuario)")
	}
}

func TestDecodeLegacy(t *testing.T) {
	// "Creación del proceso" en Windows-1252/Latin-1 (como lo escribe auditpol).
	if got := decodeText([]byte("Creaci\xf3n del proceso")); got != "Creación del proceso" {
		t.Errorf("legacy = %q", got)
	}
	if got := decodeText([]byte("\xef\xbb\xbfCreación")); got != "Creación" {
		t.Errorf("UTF-8 con BOM = %q", got)
	}
}

func TestParseSSHDConfigIncludeCycle(t *testing.T) {
	files := map[string]string{
		"/etc/ssh/sshd_config": strings.Repeat("Include /etc/ssh/a.conf\n", 8),
		"/etc/ssh/a.conf":      strings.Repeat("Include /etc/ssh/sshd_config\n", 8) + "Port 2222\n",
	}
	read := func(p string) (string, error) { return files[p], nil }
	glob := func(p string) ([]string, error) { return []string{p}, nil }
	done := make(chan map[string]string, 1)
	go func() { done <- parseSSHDConfig("/etc/ssh/sshd_config", read, glob) }()
	select {
	case m := <-done:
		if m["port"] != "2222" {
			t.Errorf("port = %q", m["port"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("un Include circular no debe recorrerse de forma exponencial")
	}
}
