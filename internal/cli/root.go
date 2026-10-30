// Package cli implementa la línea de comandos de Bastion.
package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/bastion/internal/config"
	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/internal/remediate"
	"github.com/Ruby570bocadito/bastion/internal/report"
	"github.com/Ruby570bocadito/bastion/internal/version"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
	"github.com/Ruby570bocadito/bastion/rules"
)

// ExitError permite devolver un código de salida concreto.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

type globalFlags struct {
	noColor  bool
	rulesDir []string
	// trustEnv permite, con privilegios, las variables BASTION_HOME,
	// BASTION_RELEASES_URL y BASTION_REPO.
	trustEnv bool
}

var gf globalFlags

// Execute ejecuta la CLI y devuelve el código de salida.
func Execute() int {
	root := newRoot()
	if err := root.Execute(); err != nil {
		var ee *ExitError
		if errors.As(err, &ee) {
			if ee.Msg != "" {
				fmt.Fprintln(os.Stderr, ee.Msg)
			}
			return ee.Code
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "bastion",
		Short: "Bastion · auditoría y hardening para Windows, Windows Server y Linux",
		Long: `Bastion evalúa la configuración de seguridad del equipo frente a perfiles de
hardening (CIS, STIG, baselines de Microsoft), calcula una puntuación de postura
y genera informes con evidencias y pasos de remediación.

Bastion solo LEE la configuración del sistema: "scan" nunca modifica nada.

Primeros pasos:
  bastion info                      qué plataforma y perfil se han detectado
  bastion scan                      auditar con el perfil por defecto
  bastion scan --save --open        guardar el informe HTML y abrirlo
  bastion rules show LNX-SSH-001    detalle de un control`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
	}
	root.SetVersionTemplate(version.String() + "\n")
	root.PersistentFlags().BoolVar(&gf.noColor, "no-color", false, "desactivar colores")
	root.PersistentFlags().StringSliceVar(&gf.rulesDir, "rules-dir", nil, "directorios adicionales de reglas (*.yaml)")
	root.PersistentFlags().BoolVar(&gf.trustEnv, "trust-env", false, "con privilegios, usar igualmente BASTION_HOME, BASTION_RELEASES_URL y BASTION_REPO (desarrollo y laboratorios)")
	root.PersistentPreRun = func(cmd *cobra.Command, _ []string) { dropUntrustedEnv(cmd) }
	root.AddCommand(newScanCmd(), newHardenCmd(), newRollbackCmd(), newHistoryCmd(), newDeadmanCmd(), newExceptionsCmd(), newSurfaceCmd(), newScheduleCmd(), newUICmd(), newInfoCmd(), newRulesCmd(), newProfilesCmd(), newUpdateCmd(), newInitCmd(), newVersionCmd())
	root.CompletionOptions.HiddenDefaultCmd = true
	return root
}

// loadConfig lee config.yaml y avisa de los problemas reales. Sin
// privilegios el fichero no se puede leer (en Windows la carpeta es solo
// para administradores): se usan los valores por defecto sin avisar.
//
// Con privilegios, si otro usuario puede modificar la carpeta de
// configuración o config.yaml, no se usa: podría apuntar las
// actualizaciones a un espejo suyo o añadir reglas. Se avisa y se usan los
// valores por defecto ("bastion init" restablece los permisos).
func loadConfig() config.Config {
	if !configTrusted() {
		c := config.Default()
		c.Rules.ExtraDirs = nil // rules.d tampoco es fiable
		return c
	}
	cfg, err := config.Load()
	if err != nil && !(errors.Is(err, fs.ErrPermission) && !probes.Privileged()) {
		fmt.Fprintln(os.Stderr, "aviso:", err)
	}
	return cfg
}

var (
	trustOnce sync.Once
	trusted   = true
)

// configTrusted indica si la configuración (config.yaml, exceptions.yaml,
// rules.d) es fiable. Solo se comprueba con privilegios: sin ellos Bastion
// no aplica cambios y la carpeta de un usuario es suya. Con --trust-env y
// BASTION_HOME (desarrollo) no se comprueba.
func configTrusted() bool {
	trustOnce.Do(func() {
		if !probes.Privileged() || (gf.trustEnv && os.Getenv("BASTION_HOME") != "") {
			return
		}
		probs := config.TrustProblems()
		if len(probs) == 0 {
			return
		}
		trusted = false
		fmt.Fprintln(os.Stderr, "aviso: se ignoran config.yaml, exceptions.yaml y las reglas propias porque un usuario sin privilegios podría haberlos modificado:")
		for _, p := range probs {
			fmt.Fprintln(os.Stderr, "  ·", p.Err)
		}
		fmt.Fprintln(os.Stderr, "  Revisa su contenido y ejecuta \"bastion init\" para restablecer los permisos.")
	})
	return trusted
}

// reportsDir es donde "scan --save" guarda los informes: el directorio de
// la configuración o, sin privilegios, la carpeta del usuario (en Windows
// solo los administradores pueden escribir en %ProgramData%\Bastion).
func reportsDir(cfg config.Config) (dir string, user bool) {
	if probes.Privileged() || os.Getenv("BASTION_HOME") != "" {
		return cfg.Reports.Dir, false
	}
	if d, err := config.UserReportsDir(); err == nil {
		return d, true
	}
	return cfg.Reports.Dir, false
}

// ensureDataDirs prepara las carpetas de Bastion con sus permisos
// restringidos antes de que un comando con privilegios escriba en ellas.
//
//   - Si no existen (nadie ejecutó "bastion init"), las crea con "init": así
//     no heredan los permisos de %ProgramData%, donde cualquier usuario
//     puede crear ficheros.
//   - Si existen pero otro usuario puede modificarlas (las creó él antes,
//     o las creó una versión anterior sin restringirlas), aparta los
//     ficheros de configuración no fiables (*.no-confiable-<fecha>) y
//     restablece los permisos.
func ensureDataDirs() error {
	for _, d := range []string{config.ConfigDir(), config.DataDir()} {
		if _, err := os.Stat(d); errors.Is(err, fs.ErrNotExist) {
			if _, err := config.Init(); err != nil {
				return fmt.Errorf("no se pudieron preparar las carpetas de Bastion: %w", err)
			}
			return nil
		}
	}
	return secureDataDirs()
}

// secureDataDirs aparta los ficheros de configuración no fiables y
// restablece los permisos si otro usuario puede modificar las carpetas de
// Bastion (ver ensureDataDirs).
func secureDataDirs() error {
	if !probes.Privileged() || (gf.trustEnv && os.Getenv("BASTION_HOME") != "") {
		return nil
	}
	probs := config.TrustProblems()
	if len(probs) == 0 {
		return nil
	}
	fmt.Fprintln(os.Stderr, "aviso: las carpetas de Bastion tenían permisos inseguros:")
	for _, p := range probs {
		fmt.Fprintln(os.Stderr, "  ·", p.Err)
		if p.Path == config.ConfigDir() || p.Path == config.DataDir() {
			continue // se restringen abajo; su contenido no fiable se aparta aparte
		}
		if dst, err := config.Quarantine(p.Path); err != nil {
			return err
		} else {
			fmt.Fprintf(os.Stderr, "    apartado en %s: revísalo antes de recuperarlo\n", dst)
		}
	}
	if _, err := config.Init(); err != nil {
		return fmt.Errorf("no se pudieron restablecer los permisos de las carpetas de Bastion: %w", err)
	}
	if probs := config.TrustProblems(); len(probs) > 0 {
		return fmt.Errorf("las carpetas de Bastion siguen sin ser seguras: %v", probs[0].Err)
	}
	fmt.Fprintln(os.Stderr, "  Permisos restablecidos: solo los administradores pueden modificarlas.")
	return nil
}

// loadCatalog carga el paquete oficial y las reglas adicionales.
func loadCatalog(cfg config.Config) (*rule.Catalog, error) {
	c := rule.NewCatalog()
	if err := c.LoadFS(rules.FS, "rules/"); err != nil {
		return nil, fmt.Errorf("paquete oficial de reglas: %w", err)
	}
	dirs := append([]string{}, cfg.Rules.ExtraDirs...)
	dirs = append(dirs, gf.rulesDir...)
	for _, d := range dirs {
		if err := c.LoadDir(d); err != nil {
			return nil, fmt.Errorf("reglas de %s: %w", d, err)
		}
	}
	if errs := c.Validate(probes.KnownSet(), remediate.ValidateAction); len(errs) > 0 {
		var b strings.Builder
		for _, e := range errs {
			b.WriteString("\n  · " + e.Error())
		}
		return nil, fmt.Errorf("hay reglas inválidas:%s", b.String())
	}
	return c, nil
}

// resolveProfile elige el perfil pedido o el de por defecto de la plataforma.
func resolveProfile(c *rule.Catalog, info platform.Info, requested string) (*rule.Profile, error) {
	if requested != "" && requested != "auto" {
		p := c.Profiles[requested]
		if p == nil {
			var ids []string
			for _, x := range c.ProfilesFor(info.Tags) {
				ids = append(ids, x.ID)
			}
			return nil, fmt.Errorf("perfil %q desconocido; disponibles para este equipo: %s", requested, strings.Join(ids, ", "))
		}
		return p, nil
	}
	p := c.DefaultProfile(info.Tags)
	if p == nil {
		return nil, fmt.Errorf("no hay un perfil por defecto para %s (%s); usa --profile", info.Name, strings.Join(info.Tags, ", "))
	}
	return p, nil
}

func stdoutStyle() report.Style { return report.NewStyle(os.Stdout, gf.noColor) }
func stderrStyle() report.Style { return report.NewStyle(os.Stderr, gf.noColor) }

// envOverrides son las variables que cambian de dónde lee Bastion su
// configuración, sus datos o sus actualizaciones.
var envOverrides = []string{"BASTION_HOME", "BASTION_RELEASES_URL", "BASTION_REPO"}

// dropUntrustedEnv descarta, con privilegios, las variables que redirigen
// la configuración, las instantáneas o las actualizaciones, salvo con
// --trust-env. En Windows, cualquier programa del usuario puede fijarlas en
// HKCU\Environment y la consola elevada del administrador las hereda: con
// ellas, "harden" o "rollback" leerían una configuración o instantáneas que
// controla ese programa, y "update" descargaría de su servidor.
//
// "deadman" es interno (lo lanza harden con su mismo entorno) y las
// conserva para usar las mismas instantáneas.
func dropUntrustedEnv(cmd *cobra.Command) {
	if gf.trustEnv || cmd.Name() == "deadman" || !probes.Privileged() {
		return
	}
	for _, k := range envOverrides {
		if v := os.Getenv(k); v != "" {
			fmt.Fprintf(os.Stderr, "aviso: con privilegios se ignora %s=%s (usa --trust-env si es intencionado", k, v)
			if k == "BASTION_RELEASES_URL" || k == "BASTION_REPO" {
				fmt.Fprint(os.Stderr, ", o --releases-url / --repo en bastion update")
			}
			fmt.Fprintln(os.Stderr, ")")
			_ = os.Unsetenv(k)
		}
	}
}
