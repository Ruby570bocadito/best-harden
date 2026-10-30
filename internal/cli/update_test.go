package cli

import (
	"strings"
	"testing"
)

func TestPlanUpdate(t *testing.T) {
	cases := []struct {
		current, target string
		explicit, force bool
		install         bool
		msg             string
	}{
		{"v0.3.1", "v0.3.2", false, false, true, "nueva"},
		{"v0.3.2", "v0.3.2", false, false, false, "actualizado"},
		{"v0.3.2", "v0.3.2", true, false, false, "Ya tienes"},
		{"v0.3.2", "v0.3.2", false, true, true, "reinstala"},
		// --check --version con una versión anterior: no es «nueva».
		{"v0.3.2", "v0.3.0", true, false, true, "anterior"},
		{"v0.4.0-rc.1", "v0.3.2", false, false, false, "posterior"},
		// Compilación de desarrollo: no se compara.
		{"dev", "v0.3.2", false, false, false, "desarrollo"},
		{"dev", "v0.3.2", false, true, true, "desarrollo"},
	}
	for _, c := range cases {
		install, msg := planUpdate(c.current, c.target, c.explicit, c.force)
		if install != c.install || !strings.Contains(msg, c.msg) {
			t.Errorf("planUpdate(%s, %s, explicit=%v, force=%v) = %v %q", c.current, c.target, c.explicit, c.force, install, msg)
		}
	}
}

func TestHardenCmdLine(t *testing.T) {
	old := gf.rulesDir
	defer func() { gf.rulesDir = old }()
	gf.rulesDir = []string{"/opt/mis reglas"}
	got := hardenCmdLine(hardenFlags{wave: 2, forceLocal: true, includeRemote: true}, true)
	for _, want := range []string{"--wave 2", "--include-remote", "--force-local", "--rules-dir ", "mis reglas", "--apply"} {
		if !strings.Contains(got, want) {
			t.Errorf("falta %q en %q", want, got)
		}
	}
	if quoteArg("simple") != "simple" || quoteArg("con espacio") == "con espacio" {
		t.Error("quoteArg")
	}
}
