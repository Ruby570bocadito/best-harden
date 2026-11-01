package platform

import (
	"reflect"
	"testing"
)

func TestLinuxTags(t *testing.T) {
	cases := []struct {
		id, like string
		want     []string
	}{
		{"ubuntu", "debian", []string{"linux-ubuntu", "linux-debian", "linux"}},
		{"debian", "", []string{"linux-debian", "linux"}},
		{"rocky", "rhel centos fedora", []string{"linux-rocky", "linux-rhel", "linux-fedora", "linux"}},
		{"rhel", "fedora", []string{"linux-rhel", "linux-fedora", "linux"}},
		{"almalinux", "rhel centos fedora", []string{"linux-almalinux", "linux-rhel", "linux-fedora", "linux"}},
	}
	for _, c := range cases {
		if got := linuxTags(c.id, c.like); !reflect.DeepEqual(got, c.want) {
			t.Errorf("linuxTags(%q, %q) = %v, quiero %v", c.id, c.like, got, c.want)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	m := ParseOSRelease("NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n# comentario\nVERSION_ID='9.4'\n")
	if m["ID"] != "rocky" || m["ID_LIKE"] != "rhel centos fedora" || m["VERSION_ID"] != "9.4" {
		t.Errorf("os-release: %v", m)
	}
}

func TestDisplayName(t *testing.T) {
	if n := (Info{Name: "Ubuntu 24.04.1 LTS", Version: "24.04"}).DisplayName(); n != "Ubuntu 24.04.1 LTS" {
		t.Errorf("no debe repetir la versión: %q", n)
	}
	if n := (Info{Name: "Windows 11 Pro", Version: "24H2"}).DisplayName(); n != "Windows 11 Pro 24H2" {
		t.Errorf("Windows: %q", n)
	}
}

func TestSudoImpl(t *testing.T) {
	for _, c := range []struct{ path, version, want string }{
		{"/usr/bin/sudo", "Sudo version 1.9.15p5", TagSudoClassic},
		{"/usr/bin/sudo.ws", "Sudo version 1.9.16p2", TagSudoClassic}, // el clásico en Ubuntu 25.10+
		{"/usr/lib/cargo/bin/sudo", "", TagSudoRS},                    // sudo-rs en Ubuntu 25.10+
		{"/usr/bin/sudo-rs", "", TagSudoRS},
		{"/usr/bin/sudo", "sudo-rs 0.2.8", TagSudoRS}, // sudo-rs instalado como /usr/bin/sudo
		{"/usr/bin/sudo", "", TagSudoClassic},
	} {
		if got := sudoImpl(c.path, c.version); got != c.want {
			t.Errorf("sudoImpl(%q, %q) = %s, quiero %s", c.path, c.version, got, c.want)
		}
	}
}
