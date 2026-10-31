package report

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/surface"
)

//go:embed assets/report.html
var htmlTemplate []byte

// HTML genera un informe autocontenido (un único fichero, sin dependencias
// externas) que funciona sin conexión y se puede enviar por correo.
//
// Seguridad: los datos del escaneo proceden del sistema auditado y podrían
// contener texto malicioso (p. ej. una línea de sudoers manipulada). Por eso
//   - se serializan con encoding/json, que escapa <, > y & (no puede cerrar
//     la etiqueta <script>);
//   - el JavaScript los inserta siempre con textContent, nunca como HTML;
//   - la página declara una CSP que solo ejecuta el script con el nonce
//     aleatorio de este informe y bloquea cualquier carga externa.
func HTML(w io.Writer, rep *engine.Report) error {
	data, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	out := bytes.ReplaceAll(htmlTemplate, []byte("__NONCE__"), []byte(base64.RawURLEncoding.EncodeToString(nonce)))
	out = bytes.Replace(out, []byte("__ADARVE_DATA__"), data, 1)
	_, err = w.Write(out)
	return err
}

//go:embed assets/surface.html
var surfaceTemplate []byte

// SurfaceHTML genera el informe autocontenido de "adarve surface", con las
// mismas garantías que HTML: datos como JSON escapado, insertados con
// textContent y una CSP con nonce. Comparte los estilos del informe de
// escaneo (se toman de su plantilla), así que los dos se ven igual.
func SurfaceHTML(w io.Writer, rep *surface.Report) error {
	data, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	out := bytes.Replace(surfaceTemplate, []byte("__STYLE__"), sharedStyle(), 1)
	out = bytes.ReplaceAll(out, []byte("__NONCE__"), []byte(base64.RawURLEncoding.EncodeToString(nonce)))
	out = bytes.Replace(out, []byte("__ADARVE_DATA__"), data, 1)
	_, err = w.Write(out)
	return err
}

// sharedStyle devuelve el CSS del informe de escaneo.
func sharedStyle() []byte {
	start := bytes.Index(htmlTemplate, []byte("<style>"))
	end := bytes.Index(htmlTemplate, []byte("</style>"))
	if start < 0 || end < start {
		return nil
	}
	return bytes.TrimSpace(htmlTemplate[start+len("<style>") : end])
}
