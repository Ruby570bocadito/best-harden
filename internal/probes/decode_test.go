package probes

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadLimited(t *testing.T) {
	exact := bytes.Repeat([]byte("a"), 10)
	if b, err := readLimited(bytes.NewReader(exact), 10); err != nil || len(b) != 10 {
		t.Errorf("exactamente el límite: %d %v", len(b), err)
	}
	if b, err := readLimited(bytes.NewReader(append(exact, 'b')), 10); err == nil || len(b) != 10 {
		t.Errorf("por encima del límite: %d %v", len(b), err)
	}
}

func TestDecodeConsole(t *testing.T) {
	// UTF-16 y UTF-8 se respetan igual que en los ficheros.
	if s := decodeConsole([]byte{0xFF, 0xFE, 'o', 0, 'k', 0}); s != "ok" {
		t.Errorf("UTF-16LE = %q", s)
	}
	if s := decodeConsole([]byte("Dirección")); s != "Dirección" {
		t.Errorf("UTF-8 = %q", s)
	}
	// El texto de 8 bits pasa por la página de la consola (no la ANSI).
	old := decodeOEM
	defer func() { decodeOEM = old }()
	decodeOEM = func(b []byte) string { return "oem:" + string(rune(b[len(b)-1])) }
	if s := decodeConsole([]byte("x\xa2")); !strings.HasPrefix(s, "oem:") {
		t.Errorf("consola = %q", s)
	}
	if s := decodeText([]byte("x\xa2")); strings.HasPrefix(s, "oem:") {
		t.Errorf("un fichero no usa la página de la consola: %q", s)
	}
}
