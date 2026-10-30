package platform

import (
	"errors"
	"testing"
)

func TestContainerSignals(t *testing.T) {
	host := "29 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n"
	docker := "523 470 0:51 / / rw,relatime master:1 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/X,upperdir=/var/lib/docker/overlay2/abc/diff,workdir=/var/lib/docker/overlay2/abc/work\n"
	podman := "600 500 0:60 / / rw - overlay overlay rw,upperdir=/home/u/.local/share/containers/storage/overlay/x/diff\n"
	cases := []struct {
		name               string
		cgroup, mount, env string
		want               bool
	}{
		{"host cgroup v2", "0::/init.scope\n", host, "", false},
		{"docker cgroup v1", "12:pids:/docker/abc\n", host, "", true},
		{"docker cgroup v2 con cgroupns", "0::/\n", docker, "", true},
		{"podman sin root", "0::/\n", podman, "", true},
		{"nspawn por environ", "0::/\n", host, "PATH=/bin\x00container=systemd-nspawn\x00", true},
		{"overlay del host (live)", "0::/\n", "1 0 0:1 / / rw - overlay overlay rw,upperdir=/run/live/rw\n", "", false},
	}
	for _, c := range cases {
		if got := containerSignals(c.cgroup, c.mount, c.env); got != c.want {
			t.Errorf("%s: %v, quiero %v", c.name, got, c.want)
		}
	}
}

func TestGraphicalTarget(t *testing.T) {
	links := func(m map[string]string) func(string) (string, error) {
		return func(p string) (string, error) {
			if v, ok := m[p]; ok {
				return v, nil
			}
			return "", errors.New("no existe")
		}
	}
	if !graphicalTarget(links(map[string]string{"/usr/lib/systemd/system/default.target": "graphical.target"})) {
		t.Error("sin enlace en /etc vale el de la distribución")
	}
	if graphicalTarget(links(map[string]string{
		"/etc/systemd/system/default.target":     "/lib/systemd/system/multi-user.target",
		"/usr/lib/systemd/system/default.target": "graphical.target",
	})) {
		t.Error("el de /etc manda")
	}
	if !graphicalTarget(links(map[string]string{"/lib/systemd/system/default.target": "graphical.target"})) {
		t.Error("/lib")
	}
	if graphicalTarget(links(nil)) {
		t.Error("sin enlaces")
	}
}
