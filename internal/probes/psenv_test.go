package probes

import (
	"strings"
	"testing"
)

// Windows PowerShell 5.1 no debe heredar el PSModulePath de PowerShell 7.
func TestPSEnvironDropsPSModulePath(t *testing.T) {
	t.Setenv("PSModulePath", `C:\Program Files\PowerShell\7\Modules`)
	t.Setenv("ADARVE_PRUEBA", "1")
	env := PSEnviron("EXTRA=si")
	var sawOther, sawExtra bool
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if strings.EqualFold(k, "PSModulePath") {
			t.Errorf("PSModulePath sigue en el entorno: %s", kv)
		}
		sawOther = sawOther || kv == "ADARVE_PRUEBA=1"
		sawExtra = sawExtra || kv == "EXTRA=si"
	}
	if !sawOther || !sawExtra {
		t.Errorf("faltan variables: resto %v, extra %v", sawOther, sawExtra)
	}
}
