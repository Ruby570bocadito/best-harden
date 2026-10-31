// Package config gestiona las rutas de Adarve y el fichero config.yaml.
//
// Rutas por defecto:
//
//	Linux:   /etc/adarve (configuración)  ·  /var/lib/adarve (datos)
//	Windows: %ProgramData%\Adarve (ambos)
//
// ADARVE_HOME sustituye ambas rutas (útil para desarrollo y pruebas).
//
// Adarve se llamaba antes Bastion: las carpetas de Bastion se trasladan a
// las nuevas la primera vez que se usan (ver migrated) y las variables
// BASTION_* se siguen aceptando (ver Env).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config es el contenido de config.yaml.
type Config struct {
	// Profile es el perfil por defecto: "auto" lo elige según la plataforma.
	Profile string `yaml:"profile"`
	Reports struct {
		Dir  string `yaml:"dir"`
		Keep int    `yaml:"keep"`
	} `yaml:"reports"`
	Rules struct {
		ExtraDirs []string `yaml:"extra_dirs"`
	} `yaml:"rules"`
	Update struct {
		Repo        string `yaml:"repo"`
		ReleasesURL string `yaml:"releases_url"`
	} `yaml:"update"`
	Notify Notify `yaml:"notify"`
}

// Notify configura los avisos del análisis programado.
type Notify struct {
	// Webhook recibe el aviso (ntfy, Slack, Discord, Teams o JSON). Su
	// dirección suele llevar un secreto: el fichero solo lo leen los
	// administradores.
	Webhook string `yaml:"webhook,omitempty"`
	// Format fuerza el formato; vacío, se deduce de la dirección.
	Format string `yaml:"format,omitempty"`
	// When es "changes" (por defecto: solo si algo empeora o falla) o
	// "always" (también las ejecuciones sin cambios a peor).
	When string `yaml:"when,omitempty"`
}

// ConfigDir es el directorio de configuración.
func ConfigDir() string {
	if h := Env("HOME"); h != "" {
		return h
	}
	if runtime.GOOS == "windows" {
		return programData()
	}
	return migrated("/etc/adarve", "/etc/bastion")
}

// DataDir es el directorio de datos (informes, instantáneas).
func DataDir() string {
	if h := Env("HOME"); h != "" {
		return h
	}
	if runtime.GOOS == "windows" {
		return programData()
	}
	return migrated("/var/lib/adarve", "/var/lib/bastion")
}

func programData() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return migrated(filepath.Join(pd, "Adarve"), filepath.Join(pd, "Bastion"))
}

// Env lee la variable ADARVE_<name> o, si no está definida, la antigua
// BASTION_<name>.
func Env(name string) string {
	if v := os.Getenv("ADARVE_" + name); v != "" {
		return v
	}
	return os.Getenv("BASTION_" + name)
}

// migrated devuelve dir. Si no existe y sí existe legacy (la carpeta de
// Bastion), la traslada a dir conservando sus permisos; si no se puede
// (sin privilegios, ficheros en uso), sigue usando legacy para no perder
// el historial, las excepciones ni las instantáneas de rollback.
func migrated(dir, legacy string) string {
	if _, err := os.Lstat(dir); err == nil {
		return dir
	}
	fi, err := os.Lstat(legacy)
	if err != nil || !fi.IsDir() {
		return dir
	}
	if err := os.Rename(legacy, dir); err != nil {
		return legacy
	}
	return dir
}

// UserReportsDir es el directorio de informes del usuario actual. Se usa
// cuando Adarve se ejecuta sin privilegios y no puede escribir en DataDir:
//
//	Windows: %LOCALAPPDATA%\Adarve\reports
//	Linux:   $XDG_DATA_HOME/adarve/reports (~/.local/share/adarve/reports)
func UserReportsDir() (string, error) {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(migrated(filepath.Join(d, "Adarve"), filepath.Join(d, "Bastion")), "reports"), nil
		}
		return "", errors.New("LOCALAPPDATA no está definido")
	}
	d := os.Getenv("XDG_DATA_HOME")
	if d == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		d = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(migrated(filepath.Join(d, "adarve"), filepath.Join(d, "bastion")), "reports"), nil
}

// File es la ruta de config.yaml.
func File() string { return filepath.Join(ConfigDir(), "config.yaml") }

// Default devuelve la configuración por defecto.
func Default() Config {
	var c Config
	c.Profile = "auto"
	c.Reports.Dir = filepath.Join(DataDir(), "reports")
	c.Reports.Keep = 30
	c.Rules.ExtraDirs = []string{filepath.Join(ConfigDir(), "rules.d")}
	return c
}

// Load lee config.yaml; si no existe devuelve la configuración por defecto.
func Load() (Config, error) {
	c := Default()
	b, err := os.ReadFile(File())
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Default(), fmt.Errorf("%s: %w", File(), err)
	}
	if c.Reports.Dir == "" {
		c.Reports.Dir = Default().Reports.Dir
	}
	if c.Profile == "" {
		c.Profile = "auto"
	}
	return c, nil
}

const defaultFile = `# Configuración de Adarve · https://github.com/Ruby570bocadito/adarve
# Este fichero solo debe poder modificarlo un administrador.

# Perfil por defecto para "adarve scan". "auto" lo elige según la plataforma
# (win-workstation-l1, win-server-l1, win-dc-l1, linux-server-l1...).
profile: auto

reports:
  # Dónde se guardan los informes HTML y JSON de "adarve scan --save".
  dir: %q
  # Número de escaneos que se conservan (los más antiguos se borran).
  keep: 30

rules:
  # Directorios con reglas propias (*.yaml) que se suman al paquete oficial.
  extra_dirs:
    - %q

update:
  # Repositorio de GitHub del que se descargan las actualizaciones.
  # repo: Ruby570bocadito/adarve
  # Espejo interno de releases (redes corporativas o aisladas).
  # Debe servir <url>/latest/download/version.txt y <url>/download/<tag>/<fichero>.
  # releases_url: https://mirror.interno/adarve/releases

# Avisos del análisis programado ("adarve schedule"). Cada ejecución queda en
# el Visor de eventos (Windows) o en syslog (Linux); además, un webhook
# opcional. Se configura con: adarve schedule notify --set <url>
# notify:
#   webhook: https://ntfy.sh/<tema-secreto>
#   format: ntfy      # ntfy, slack, discord, teams o json (se deduce de la url)
#   when: changes     # changes (solo si algo empeora o falla) o always
`

// InitResult resume lo que hizo Init.
type InitResult struct {
	Created []string
	Config  string
}

// Init crea los directorios y un config.yaml por defecto si no existe.
// No sobrescribe nunca una configuración existente.
func Init() (InitResult, error) {
	var res InitResult
	d := Default()
	dirs := []string{ConfigDir(), DataDir(), d.Reports.Dir, d.Rules.ExtraDirs[0], filepath.Join(DataDir(), "snapshots")}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return res, err
			}
			res.Created = append(res.Created, dir)
		}
	}
	res.Config = File()
	if _, err := os.Stat(res.Config); errors.Is(err, fs.ErrNotExist) {
		content := fmt.Sprintf(defaultFile, d.Reports.Dir, d.Rules.ExtraDirs[0])
		if err := os.WriteFile(res.Config, []byte(content), 0o640); err != nil {
			return res, err
		}
		res.Created = append(res.Created, res.Config)
	}
	if err := restrictPermissions(DataDir()); err != nil {
		return res, err
	}
	if ConfigDir() != DataDir() {
		if err := restrictPermissions(ConfigDir()); err != nil {
			return res, err
		}
	}
	if err := GrantUserRead(d.Reports.Dir); err != nil {
		return res, err
	}
	return res, nil
}

// SetNotify guarda la configuración de avisos en config.yaml. Solo cambia
// la sección notify (la quita y la añade al final): el resto del fichero y
// sus comentarios quedan igual. Con webhook vacío la quita.
func SetNotify(n Notify) error {
	path := File()
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		d := Default()
		b = []byte(fmt.Sprintf(defaultFile, d.Reports.Dir, d.Rules.ExtraDirs[0]))
	} else if err != nil {
		return err
	}
	var cur Config
	if err := yaml.Unmarshal(b, &cur); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var out []string
	in := false
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "notify:"):
			in = true
			continue
		case in && (l == "" || l[0] == ' ' || l[0] == '\t'):
			continue
		}
		in = false
		out = append(out, l)
	}
	text := strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
	if n.Webhook != "" {
		text += "\nnotify:\n"
		for _, kv := range [][2]string{{"webhook", n.Webhook}, {"format", n.Format}, {"when", n.When}} {
			if kv[1] != "" {
				// Una cadena JSON es una cadena YAML válida entre comillas.
				q, _ := json.Marshal(kv[1])
				text += "  " + kv[0] + ": " + string(q) + "\n"
			}
		}
	}
	var check Config
	if err := yaml.Unmarshal([]byte(text), &check); err != nil || check.Notify != n {
		return fmt.Errorf("no se pudo actualizar %s sin estropearlo: edítalo a mano", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
