package report

import (
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Los informes de consola muestran texto que procede del sistema auditado:
// nombres de procesos, recursos compartidos, cuentas, líneas de ficheros de
// configuración… Un usuario sin privilegios puede poner secuencias de
// escape en el nombre de un proceso que escucha en la red; impresas tal
// cual en la terminal de root podrían ocultar líneas, reescribir el texto o
// escribir en el portapapeles (OSC 52).

// ownSGR son los únicos códigos de escape que emite Style.
var ownSGR = regexp.MustCompile(`^\x1b\[(?:0|1|2|31|32|33|34|35|36|1;31)m`)

// sanitize quita los caracteres de control (C0, DEL y C1) salvo el salto de
// línea y el tabulador. Si keepSGR es true conserva los códigos de color de
// Style; cualquier otra secuencia de escape pierde su ESC y queda como texto
// inofensivo.
func sanitize(s string, keepSGR bool) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f || c == 0xc2 {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == 0x1b && keepSGR {
			if m := ownSGR.FindString(s[i:]); m != "" {
				b.WriteString(m)
				i += len(m)
				continue
			}
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			// fuera
		case r == utf8.RuneError && size == 1:
			b.WriteByte('?')
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// Clean quita los caracteres de control de un texto procedente del sistema
// auditado antes de mostrarlo en la terminal (los saltos de línea pasan a
// espacios: cada dato ocupa una línea).
func Clean(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(sanitize(s, false), "\n", " "), "\t", " ")
}

// SafeWriter filtra lo que se escribe en w: conserva los colores de Style y
// quita cualquier otro carácter de control o secuencia de escape.
func SafeWriter(w io.Writer) io.Writer {
	if _, ok := w.(safeWriter); ok {
		return w
	}
	return safeWriter{w}
}

type safeWriter struct{ w io.Writer }

func (s safeWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(s.w, sanitize(string(p), true)); err != nil {
		return 0, err
	}
	return len(p), nil
}
