//go:build windows

package probes

import (
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

var procGetOEMCP = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetOEMCP")

func init() {
	// Los ficheros (auditpol /backup, secedit) usan la página ANSI.
	decodeLegacy = func(b []byte) string { return decodeCodePage(windows.GetACP(), b) }
	// La salida de las herramientas de consola usa la página de la consola:
	// la heredada si Bastion tiene una o, si no (tarea programada), la OEM,
	// que es la que recibe la consola nueva del proceso hijo.
	decodeOEM = func(b []byte) string { return decodeCodePage(consoleCP(), b) }
}

func consoleCP() uint32 {
	if cp, err := windows.GetConsoleOutputCP(); err == nil && cp != 0 {
		return cp
	}
	if procGetOEMCP.Find() == nil {
		if cp, _, _ := procGetOEMCP.Call(); cp != 0 {
			return uint32(cp)
		}
	}
	return windows.GetACP()
}

// decodeCodePage convierte texto de 8 bits en la página de códigos cp.
func decodeCodePage(cp uint32, b []byte) string {
	if len(b) == 0 {
		return ""
	}
	n, err := windows.MultiByteToWideChar(cp, 0, &b[0], int32(len(b)), nil, 0)
	if err != nil || n <= 0 {
		return latin1(b)
	}
	u := make([]uint16, n)
	if _, err := windows.MultiByteToWideChar(cp, 0, &b[0], int32(len(b)), &u[0], n); err != nil {
		return latin1(b)
	}
	return string(utf16.Decode(u))
}
