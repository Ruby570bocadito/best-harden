//go:build windows

package probes

import "testing"

// netstat en un Windows en español escribe «Dirección» en CP850 (0xA2),
// no en Windows-1252 (0xF3).
func TestDecodeCodePage(t *testing.T) {
	if got := decodeCodePage(850, []byte("Direcci\xa2n")); got != "Dirección" {
		t.Errorf("CP850 = %q", got)
	}
	if got := decodeCodePage(1252, []byte("Direcci\xf3n")); got != "Dirección" {
		t.Errorf("CP1252 = %q", got)
	}
	if consoleCP() == 0 {
		t.Error("página de la consola desconocida")
	}
}
