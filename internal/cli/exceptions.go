package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/adarve/internal/config"
	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/exceptions"
	"github.com/Ruby570bocadito/adarve/internal/platform"
	"github.com/Ruby570bocadito/adarve/internal/probes"
	"github.com/Ruby570bocadito/adarve/internal/report"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

func exceptionsPath() string { return exceptions.Path(config.ConfigDir()) }

// loadExceptions lee exceptions.yaml. Como config.yaml, sin privilegios no
// se puede leer en Windows: entonces no se aplica ninguna sin avisar.
func loadExceptions() *exceptions.File {
	if !configTrusted() {
		return &exceptions.File{Schema: exceptions.Schema} // ver loadConfig
	}
	f, err := exceptions.Load(exceptionsPath())
	if err != nil && !(errors.Is(err, fs.ErrPermission) && !probes.Privileged()) {
		fmt.Fprintln(os.Stderr, "aviso:", err)
	}
	return f
}

// evaluate ejecuta las reglas y aplica las excepciones (las caducadas
// quedan anotadas en Result.Exception y el control sigue fallando).
func evaluate(ctx context.Context, eng *engine.Engine, rules []*rule.Rule, info platform.Info, progress func(int, int)) []engine.Result {
	results := eng.Run(ctx, rules, progress)
	engine.ApplyExceptions(results, loadExceptions(), info.Hostname, time.Now())
	return results
}

func newExceptionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "exceptions",
		Aliases: []string{"exception", "excepciones"},
		Short:   "Gestionar excepciones: controles fallidos aceptados con motivo y caducidad",
		Long: `Una excepción acepta de forma documentada un control que falla: riesgo
asumido, control compensatorio o incompatibilidad conocida. El control
aparece como "excepción", no cuenta en la puntuación y "harden" no lo toca.

Cada excepción lleva un motivo, un responsable y una caducidad de como
mucho un año. Al caducar, el control vuelve a contar como fallido y Adarve
avisa en cada escaneo.

Se guardan en exceptions.yaml, junto a config.yaml; solo un administrador
puede modificarlas.`,
		RunE: func(cmd *cobra.Command, _ []string) error { return listExceptions(false) },
	}

	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "Listar las excepciones y su vigencia",
		RunE:  func(cmd *cobra.Command, _ []string) error { return listExceptions(asJSON) },
	}
	list.Flags().BoolVar(&asJSON, "json", false, "salida JSON")

	var reason, expires, owner string
	var hosts []string
	add := &cobra.Command{
		Use:   "add <ID>",
		Short: "Añadir o renovar la excepción de un control",
		Example: `  adarve exceptions add WIN-SYS-003 --reason "Equipo sin UEFI; se sustituye en enero" --expires 2027-01-31
  adarve exceptions add LNX-FW-001 --reason "Filtrado en el cortafuegos perimetral (FW-02)" --expires 90d
  adarve exceptions add WIN-RDP-001 --reason "Cliente RDP heredado del proveedor" --expires 6m --host SRV-ERP01`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return addException(strings.ToUpper(args[0]), reason, expires, owner, hosts)
		},
	}
	add.Flags().StringVarP(&reason, "reason", "r", "", "motivo de la excepción (obligatorio)")
	add.Flags().StringVarP(&expires, "expires", "e", "", "caducidad: fecha AAAA-MM-DD o plazo 90d, 12w, 6m (obligatorio, máximo 1 año)")
	add.Flags().StringVar(&owner, "owner", "", "responsable (por defecto, el usuario actual)")
	add.Flags().StringSliceVar(&hosts, "host", nil, "limitar a estos equipos (por defecto, cualquiera que use este fichero)")
	_ = add.MarkFlagRequired("reason")
	_ = add.MarkFlagRequired("expires")

	var rmHost string
	remove := &cobra.Command{
		Use:     "remove <ID>",
		Aliases: []string{"rm", "delete"},
		Short:   "Eliminar la excepción de un control",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return removeException(strings.ToUpper(args[0]), rmHost)
		},
	}
	remove.Flags().StringVar(&rmHost, "host", "", "eliminar solo la excepción de este equipo")

	cmd.AddCommand(list, add, remove)
	return cmd
}

func requireConfigWrite() error {
	if probes.Privileged() || config.Env("HOME") != "" {
		return ensureDataDirs()
	}
	return fmt.Errorf("modificar excepciones requiere privilegios. %s", report.AdminHint(platform.Detect().Family))
}

func addException(id, reason, expires, owner string, hosts []string) error {
	if err := requireConfigWrite(); err != nil {
		return err
	}
	cat, err := loadCatalog(loadConfig())
	if err != nil {
		return err
	}
	r := cat.Rule(id)
	if r == nil {
		return fmt.Errorf("no existe la regla %s", id)
	}
	now := time.Now()
	exp, err := exceptions.ParseExpiry(expires, now)
	if err != nil {
		return err
	}
	if owner == "" {
		if u, err := user.Current(); err == nil {
			owner = u.Username
		}
	}
	e := exceptions.Entry{
		Rule: r.ID, Reason: strings.TrimSpace(reason), Owner: owner, Hosts: hosts,
		Created: now.Format(exceptions.DateLayout), Expires: exp.Format(exceptions.DateLayout),
	}
	if err := e.Validate(); err != nil {
		return err
	}
	if !exp.After(now) {
		return fmt.Errorf("la caducidad %s ya ha pasado", e.Expires)
	}
	path := exceptionsPath()
	f, err := exceptions.Load(path)
	if err != nil {
		return err
	}
	replaced := f.Upsert(e)
	if err := f.Save(path); err != nil {
		return fmt.Errorf("no se pudo guardar %s: %w", path, err)
	}
	s := stdoutStyle()
	verb := "añadida"
	if replaced {
		verb = "renovada"
	}
	fmt.Printf("\n  %s Excepción %s: %s %s\n", s.Green(report.Sym("✓")), verb, s.Cyan(r.ID), r.Title)
	fmt.Printf("    %s %s\n", s.Dim("Motivo      "), e.Reason)
	fmt.Printf("    %s %s\n", s.Dim("Responsable "), e.Owner)
	fmt.Printf("    %s %s (%d días)\n", s.Dim("Caduca      "), e.Expires, e.DaysLeft(now))
	if len(hosts) > 0 {
		fmt.Printf("    %s %s\n", s.Dim("Equipos     "), strings.Join(hosts, ", "))
	}
	fmt.Printf("    %s\n\n", s.Dim(path))
	return nil
}

func removeException(id, host string) error {
	if err := requireConfigWrite(); err != nil {
		return err
	}
	path := exceptionsPath()
	f, err := exceptions.Load(path)
	if err != nil {
		return err
	}
	n := f.Remove(id, host)
	if n == 0 {
		return fmt.Errorf("no hay ninguna excepción para %s", id)
	}
	if err := f.Save(path); err != nil {
		return err
	}
	s := stdoutStyle()
	what := "Excepción eliminada"
	if n > 1 {
		what = fmt.Sprintf("%d excepciones eliminadas", n)
	}
	fmt.Printf("\n  %s %s para %s: el control vuelve a contar en la puntuación.\n\n", s.Green(report.Sym("✓")), what, s.Cyan(id))
	return nil
}

func listExceptions(asJSON bool) error {
	f, err := exceptions.Load(exceptionsPath())
	if err != nil {
		if errors.Is(err, fs.ErrPermission) && !probes.Privileged() {
			return fmt.Errorf("sin privilegios no se pueden leer las excepciones: %s", report.AdminHint(platform.Detect().Family))
		}
		fmt.Fprintln(os.Stderr, "aviso:", err)
	}
	now := time.Now()
	if asJSON {
		type item struct {
			exceptions.Entry
			Expired  bool `json:"expired"`
			DaysLeft int  `json:"days_left"`
		}
		out := []item{}
		for _, e := range f.Exceptions {
			out = append(out, item{e, e.Expired(now), e.DaysLeft(now)})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	s := stdoutStyle()
	if len(f.Exceptions) == 0 {
		fmt.Printf("\n  No hay excepciones. Para aceptar un control fallido:\n    %s\n\n",
			s.Bold(`adarve exceptions add <ID> --reason "motivo" --expires 90d`))
		return nil
	}
	cat, _ := loadCatalog(loadConfig())
	tb := report.Table{Indent: "  "}
	fmt.Println()
	tb.Row(report.Styled("CONTROL", s.Bold), report.Styled("CADUCA", s.Bold), report.Styled("RESPONSABLE", s.Bold), report.Styled("EQUIPOS", s.Bold), report.Styled("MOTIVO", s.Bold))
	expired := 0
	for _, e := range f.Exceptions {
		when := report.Styled(fmt.Sprintf("%s (%dd)", e.Expires, e.DaysLeft(now)), nil)
		switch {
		case e.Expired(now):
			when = report.Styled(e.Expires+" caducada", s.Red)
			expired++
		case e.DaysLeft(now) <= 30:
			when = report.Styled(fmt.Sprintf("%s (%dd)", e.Expires, e.DaysLeft(now)), s.Yellow)
		}
		hosts := "todos"
		if len(e.Hosts) > 0 {
			hosts = strings.Join(e.Hosts, ",")
		}
		id := report.Styled(e.Rule, s.Cyan)
		if cat != nil && cat.Rule(e.Rule) == nil {
			id = report.Styled(e.Rule+" (regla desconocida)", s.Yellow)
		}
		tb.Row(id, when, e.Owner, hosts, e.Reason)
	}
	tb.Write(os.Stdout)
	if len(f.Exceptions) == 1 {
		fmt.Print("\n  1 excepción")
	} else {
		fmt.Printf("\n  %d excepciones", len(f.Exceptions))
	}
	switch {
	case expired == 1:
		fmt.Printf(" · %s", s.Red("1 caducada (vuelve a contar como fallida)"))
	case expired > 1:
		fmt.Printf(" · %s", s.Red(fmt.Sprintf("%d caducadas (vuelven a contar como fallidas)", expired)))
	}
	fmt.Printf("\n  %s\n\n", s.Dim(exceptionsPath()))
	return nil
}
