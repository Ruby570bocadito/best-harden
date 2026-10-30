// Package exceptions gestiona las excepciones: controles fallidos que se
// aceptan de forma documentada (riesgo asumido o control compensatorio).
//
// Una excepción siempre lleva un motivo, un responsable y una fecha de
// caducidad de como mucho un año: es una decisión que se revisa, no una
// forma de esconder un fallo. Al caducar, el control vuelve a contar como
// fallido y Bastion avisa.
//
// Se guardan en <config>/exceptions.yaml (bastion.exceptions/v1), con los
// mismos permisos que config.yaml: solo un administrador puede modificarlas.
package exceptions

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Schema es la versión del formato del fichero.
const Schema = "bastion.exceptions/v1"

// DateLayout es el formato de las fechas (AAAA-MM-DD).
const DateLayout = "2006-01-02"

// MaxDuration es la vigencia máxima de una excepción.
const MaxDuration = 366 * 24 * time.Hour

// MinReason es la longitud mínima del motivo.
const MinReason = 10

// Entry es una excepción.
type Entry struct {
	Rule    string   `yaml:"rule" json:"rule"`
	Reason  string   `yaml:"reason" json:"reason"`
	Owner   string   `yaml:"owner,omitempty" json:"owner,omitempty"`
	Hosts   []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Created string   `yaml:"created" json:"created"`
	Expires string   `yaml:"expires" json:"expires"`
}

// File es el contenido de exceptions.yaml.
type File struct {
	Schema     string  `yaml:"schema"`
	Exceptions []Entry `yaml:"exceptions"`
}

// ExpiresAt devuelve el final de la vigencia: el día de caducidad incluido.
func (e Entry) ExpiresAt() time.Time {
	t, err := time.ParseInLocation(DateLayout, e.Expires, time.Local)
	if err != nil {
		return time.Time{}
	}
	return t.AddDate(0, 0, 1)
}

// Expired indica si la excepción ha caducado en now.
func (e Entry) Expired(now time.Time) bool { return !now.Before(e.ExpiresAt()) }

// DaysLeft son los días de vigencia que quedan (0 si ha caducado).
func (e Entry) DaysLeft(now time.Time) int {
	d := e.ExpiresAt().Sub(now)
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Hours() / 24))
}

// AppliesTo indica si la excepción cubre a este equipo.
func (e Entry) AppliesTo(host string) bool {
	if len(e.Hosts) == 0 {
		return true
	}
	for _, h := range e.Hosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

// reRuleID sigue el mismo formato que los IDs de regla (rule.ValidID y el
// esquema): al menos tres partes de mayúsculas y dígitos (LNX-SSH-001,
// ACME-WIN-NET-0001...).
var reRuleID = regexp.MustCompile(`^[A-Z0-9]+(-[A-Z0-9]+){2,}$`)

// Validate comprueba una excepción respecto a la fecha actual.
func (e Entry) Validate() error { return e.ValidateAt(time.Now()) }

// ValidateAt comprueba una excepción en la fecha now. La vigencia máxima se
// cuenta desde la creación y también desde hoy: una fecha de creación futura
// no puede alargarla.
func (e Entry) ValidateAt(now time.Time) error {
	if !reRuleID.MatchString(e.Rule) {
		return fmt.Errorf("ID de regla inválido %q", e.Rule)
	}
	if len([]rune(strings.TrimSpace(e.Reason))) < MinReason {
		return fmt.Errorf("%s: el motivo debe explicar la decisión (al menos %d caracteres)", e.Rule, MinReason)
	}
	if strings.ContainsAny(e.Reason+e.Owner, "\r\n") {
		return fmt.Errorf("%s: el motivo y el responsable deben ocupar una sola línea", e.Rule)
	}
	created, err := time.ParseInLocation(DateLayout, e.Created, time.Local)
	if err != nil {
		return fmt.Errorf("%s: fecha de creación inválida %q (AAAA-MM-DD)", e.Rule, e.Created)
	}
	expires, err := time.ParseInLocation(DateLayout, e.Expires, time.Local)
	if err != nil {
		return fmt.Errorf("%s: fecha de caducidad inválida %q (AAAA-MM-DD)", e.Rule, e.Expires)
	}
	if expires.Before(created) {
		return fmt.Errorf("%s: caduca antes de crearse", e.Rule)
	}
	if expires.Sub(created) > MaxDuration {
		return fmt.Errorf("%s: la vigencia máxima es de un año (creada %s, caduca %s)", e.Rule, e.Created, e.Expires)
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	if created.After(today.AddDate(0, 0, 1)) { // un día de margen por zonas horarias
		return fmt.Errorf("%s: la fecha de creación %s está en el futuro", e.Rule, e.Created)
	}
	if expires.Sub(today) > MaxDuration {
		return fmt.Errorf("%s: la vigencia máxima es de un año desde hoy (caduca %s)", e.Rule, e.Expires)
	}
	return nil
}

// Path es la ruta de exceptions.yaml dentro del directorio de configuración.
func Path(configDir string) string { return filepath.Join(configDir, "exceptions.yaml") }

// Load lee el fichero. Si no existe devuelve un fichero vacío.
func Load(path string) (*File, error) {
	f := &File{Schema: Schema}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := yaml.Unmarshal(b, f); err != nil {
		return &File{Schema: Schema}, fmt.Errorf("%s: %w", path, err)
	}
	if f.Schema != "" && f.Schema != Schema {
		return &File{Schema: Schema}, fmt.Errorf("%s: formato %q no soportado (se esperaba %s)", path, f.Schema, Schema)
	}
	f.Schema = Schema
	var errs []string
	valid := f.Exceptions[:0]
	for _, e := range f.Exceptions {
		if err := e.Validate(); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		valid = append(valid, e)
	}
	f.Exceptions = valid
	if len(errs) > 0 {
		return f, fmt.Errorf("%s: excepciones ignoradas por inválidas: %s", path, strings.Join(errs, "; "))
	}
	return f, nil
}

const header = `# Excepciones de Bastion (bastion.exceptions/v1)
# Controles fallidos aceptados de forma documentada. Gestiónalas con
#   bastion exceptions add|list|remove
# Cada excepción caduca (como mucho al año): entonces el control vuelve a
# contar como fallido. Este fichero solo debe poder modificarlo un administrador.
`

// Save escribe el fichero de forma atómica.
func (f *File) Save(path string) error {
	f.Schema = Schema
	sort.SliceStable(f.Exceptions, func(i, j int) bool { return f.Exceptions[i].Rule < f.Exceptions[j].Rule })
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return err
	}
	b := buf.Bytes()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// Temporal único y sincronizado a disco antes de renombrar: dos
	// "bastion exceptions add" a la vez no comparten temporal y un corte de
	// luz no deja el fichero vacío.
	tf, err := os.CreateTemp(filepath.Dir(path), ".exceptions-*.tmp")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	_, err = tf.Write(append([]byte(header), b...))
	if err == nil {
		err = tf.Sync()
	}
	if cerr := tf.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o640)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// Find devuelve la excepción de una regla que se aplica a host. Si hay
// varias, gana la vigente que caduca más tarde; expired indica que todas
// las que había han caducado (y devuelve la más reciente).
func (f *File) Find(ruleID, host string, now time.Time) (e *Entry, expired bool) {
	var best, lastExpired *Entry
	for i := range f.Exceptions {
		x := &f.Exceptions[i]
		if !strings.EqualFold(x.Rule, ruleID) || !x.AppliesTo(host) {
			continue
		}
		if x.Expired(now) {
			if lastExpired == nil || x.ExpiresAt().After(lastExpired.ExpiresAt()) {
				lastExpired = x
			}
			continue
		}
		if best == nil || x.ExpiresAt().After(best.ExpiresAt()) {
			best = x
		}
	}
	if best != nil {
		return best, false
	}
	return lastExpired, lastExpired != nil
}

// Upsert añade la excepción o sustituye la de la misma regla y equipos.
func (f *File) Upsert(e Entry) (replaced bool) {
	for i, x := range f.Exceptions {
		if strings.EqualFold(x.Rule, e.Rule) && sameHosts(x.Hosts, e.Hosts) {
			f.Exceptions[i] = e
			return true
		}
	}
	f.Exceptions = append(f.Exceptions, e)
	return false
}

// Remove elimina las excepciones de una regla (todas, o solo las del
// equipo indicado). Devuelve cuántas se han eliminado.
func (f *File) Remove(ruleID, host string) int {
	n := 0
	out := f.Exceptions[:0]
	for _, x := range f.Exceptions {
		if strings.EqualFold(x.Rule, ruleID) && (host == "" || sameHosts(x.Hosts, []string{host})) {
			n++
			continue
		}
		out = append(out, x)
	}
	f.Exceptions = out
	return n
}

func sameHosts(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	norm := func(xs []string) []string {
		out := make([]string, len(xs))
		for i, x := range xs {
			out[i] = strings.ToLower(x)
		}
		sort.Strings(out)
		return out
	}
	na, nb := norm(a), norm(b)
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}

// ParseExpiry interpreta una caducidad absoluta (AAAA-MM-DD) o relativa
// (90d, 12w, 6m) a partir de now.
func ParseExpiry(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if t, err := time.ParseInLocation(DateLayout, s, time.Local); err == nil {
		return t, nil
	}
	if len(s) >= 2 {
		n, err := strconv.Atoi(s[:len(s)-1])
		if err == nil && n > 0 {
			day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
			switch s[len(s)-1] {
			case 'd':
				return day.AddDate(0, 0, n), nil
			case 'w':
				return day.AddDate(0, 0, 7*n), nil
			case 'm':
				return day.AddDate(0, n, 0), nil
			case 'y':
				return day.AddDate(n, 0, 0), nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("caducidad %q no válida: usa una fecha (2027-03-31) o un plazo (90d, 12w, 6m)", s)
}
