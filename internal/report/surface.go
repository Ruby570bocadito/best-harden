package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Ruby570bocadito/adarve/internal/surface"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

// SurfaceConsole escribe el análisis de superficie de ataque para humanos.
// Sin all, los servicios que solo escuchan en el propio equipo se resumen.
func SurfaceConsole(w io.Writer, rep *surface.Report, all bool, s Style) {
	w = SafeWriter(w) // nombres de procesos, recursos y cuentas: sin secuencias de escape
	line := s.Dim(strings.Repeat("─", 72))
	host := rep.Host
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s  %s %s\n", s.Bold(s.Cyan(Sym("▲")+" ADARVE")), s.Dim("·"), s.Dim("superficie de ataque  "+rep.Version))
	fmt.Fprintln(w, "  "+line)
	fmt.Fprintf(w, "  %s %s %s\n", s.Dim(pad("Equipo", 9)), s.Bold(host.Hostname), s.Dim("· "+host.DisplayName()))
	local, ephemeral := 0, 0
	for _, p := range rep.Ports {
		switch {
		case p.Ephemeral:
			ephemeral++
		case p.Scope != surface.ScopeNetwork:
			local++
		}
	}
	reach := fmt.Sprintf("%d en la red", rep.Exposed)
	if rep.Firewall != nil {
		open := rep.Reachable - rep.Limited
		reach += " · " + s.Bold(plural(open, "abierto", "abiertos")+" a cualquiera") +
			" · " + plural(rep.Limited, "limitado", "limitados") + " a ciertas redes · " + plural(rep.Exposed-rep.Reachable, "filtrado", "filtrados")
	} else {
		reach = s.Bold(reach)
	}
	fmt.Fprintf(w, "  %s %s · %d solo locales\n", s.Dim(pad("Servicios", 9)), reach, local)
	if fw := rep.Firewall; fw != nil && fw.Linux() {
		state := s.Green("entrada bloqueada por defecto")
		if fw.InputPolicy == "accept" {
			state = s.Yellow("entrada permitida por defecto")
		}
		if fw.InputPolicy == "" {
			fmt.Fprintf(w, "  %s %s\n", s.Dim(pad("Firewall", 9)), s.Yellow("sin reglas de entrada (nftables, iptables): no filtra nada"))
		} else {
			fmt.Fprintf(w, "  %s %s · %s %s\n", s.Dim(pad("Firewall", 9)), fw.Source, state, s.Dim(fmt.Sprintf("· %d reglas de entrada", fw.InboundRules)))
		}
	} else if fw != nil {
		var parts []string
		for _, p := range fw.Active() {
			state := s.Green("activo")
			if !p.Enabled {
				state = s.Red("desactivado")
			} else if !p.BlockInbound {
				state = s.Yellow("activo, entrada permitida por defecto")
			} else {
				state += ", entrada bloqueada por defecto"
			}
			parts = append(parts, "perfil "+p.Name+": "+state)
		}
		fmt.Fprintf(w, "  %s %s %s\n", s.Dim(pad("Firewall", 9)), strings.Join(parts, " · "), s.Dim(fmt.Sprintf("· %d reglas de entrada", fw.InboundRules)))
	}

	fmt.Fprintln(w)
	c := scoreColor(s, rep.Score)
	fmt.Fprintf(w, "  %s  %s %s  %s\n", s.Bold("EXPOSICIÓN"), c(s.Bold(fmt.Sprintf("%3d/100", rep.Score))), c(s.Bold(rep.Grade)), bar(s, rep.Score, 32))
	counts := map[rule.Severity]int{}
	for _, f := range rep.Findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, sev := range rule.Severities {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(SeverityLabel(sev))))
		}
	}
	summary := s.Green(Sym("✓") + " sin hallazgos")
	if len(rep.Findings) > 0 {
		summary = s.Red(Sym("✗")+" "+plural(len(rep.Findings), "hallazgo", "hallazgos")) + s.Dim(" ("+strings.Join(parts, ", ")+")")
	}
	fmt.Fprintf(w, "              %s\n", summary)
	surfaceChanges(w, rep, s)

	if len(rep.Findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s\n", s.Bold("HALLAZGOS"), s.Dim(fmt.Sprintf("(%d)", len(rep.Findings))))
		fmt.Fprintln(w, "  "+line)
		for _, f := range rep.Findings {
			sev := f.Severity
			fmt.Fprintf(w, "  %s %s %s %s\n", s.Red(Sym("✗")), sevColor(s, sev)(pad(SeverityLabel(sev), 8)), s.Cyan(pad(f.Subject, 10)), f.Title)
			fmt.Fprintf(w, "  %s %s\n", strings.Repeat(" ", 21), s.Dim(f.Detail))
			fmt.Fprintf(w, "  %s %s\n", strings.Repeat(" ", 21), s.Green(Sym("→")+" "+f.Fix))
		}
	}

	fmt.Fprintln(w)
	var tb Table
	tb.Indent = "  "
	header := []any{Styled("PUERTO", s.Dim), Styled("DIRECCIÓN", s.Dim), Styled("ALCANCE", s.Dim)}
	if rep.Firewall != nil {
		header = append(header, Styled("FIREWALL", s.Dim))
	}
	tb.Row(append(header, Styled("PROCESO", s.Dim), Styled("SERVICIO", s.Dim))...)
	for _, p := range rep.Ports {
		if !all && (p.Scope != surface.ScopeNetwork || p.Ephemeral) {
			continue
		}
		proc := p.Process
		if p.PID > 0 {
			proc = strings.TrimSpace(proc + " (" + strconv.Itoa(p.PID) + ")")
		}
		if len(p.Services) > 0 {
			proc += " · " + strings.Join(p.Services, ", ")
		}
		procCell := Styled(truncate(proc, 46), nil)
		if proc == "" {
			procCell = Styled("?", s.Dim)
		}
		// Solo lo que conviene revisar: la tabla ya es ancha.
		if text, warn := p.Origin(); warn {
			if proc == "" {
				proc = "?"
			}
			procCell = Styled(truncate(proc+" · "+text, 46), s.Yellow)
		}
		scope := Styled("red", s.Yellow)
		switch {
		case p.Ephemeral:
			scope = Styled("cliente", s.Dim)
		case p.Scope == surface.ScopeLoopback:
			scope = Styled("local", s.Dim)
		}
		row := []any{fmt.Sprintf("%d/%s", p.Port, p.Proto), truncate(strings.Join(p.Addresses, ", "), 28), scope}
		if rep.Firewall != nil {
			switch p.Firewall {
			case surface.FirewallOpen:
				row = append(row, Styled("abierto", s.Red))
			case surface.FirewallLimited:
				row = append(row, Styled(truncate("limitado: "+p.FirewallLimit, 30), s.Yellow))
			case surface.FirewallFiltered:
				row = append(row, Styled("filtrado", s.Green))
			default:
				row = append(row, Styled("—", s.Dim))
			}
		}
		tb.Row(append(row, procCell, p.Known)...)
	}
	title := "SERVICIOS EN LA RED"
	if all {
		title = "PUERTOS A LA ESCUCHA"
	}
	fmt.Fprintf(w, "  %s %s\n", s.Bold(title), s.Dim(fmt.Sprintf("(%d)", tb.Len()-1)))
	fmt.Fprintln(w, "  "+line)
	if tb.Len() == 1 {
		fmt.Fprintf(w, "  %s\n", s.Green(Sym("✓")+" Ningún servicio escucha en la red."))
	} else {
		tb.Write(w)
	}
	if !all && local+ephemeral > 0 {
		fmt.Fprintf(w, "  %s\n", s.Dim(fmt.Sprintf("+ %d solo locales y %d sockets de cliente (adarve surface --all)", local, ephemeral)))
	}

	if len(rep.Shares) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s\n", s.Bold("RECURSOS COMPARTIDOS"), s.Dim(fmt.Sprintf("(%d)", len(rep.Shares))))
		fmt.Fprintln(w, "  "+line)
		for _, sh := range rep.Shares {
			var acc []string
			for _, a := range sh.Access {
				x := a.Account + ": " + a.Right
				if a.Deny {
					x += " (denegado)"
				}
				acc = append(acc, x)
			}
			acc = append(acc, sh.Options...)
			name := sh.Name
			if sh.Path != "" && sh.Path != sh.Name {
				name += " " + s.Dim(sh.Path)
			}
			fmt.Fprintf(w, "  %s %s  %s\n", s.Dim(pad(sh.Kind, 6)), name, s.Dim(strings.Join(acc, " · ")))
		}
	}
	if len(rep.Admins) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s\n", s.Bold("ADMINISTRADORES"), s.Dim(fmt.Sprintf("(%d)", len(rep.Admins))))
		fmt.Fprintln(w, "  "+line)
		for _, a := range rep.Admins {
			extra := strings.Trim(strings.Join([]string{a.Kind, a.Source}, " · "), " ·")
			fmt.Fprintf(w, "  %s %s\n", a.Name, s.Dim(extra))
		}
	}

	fmt.Fprintln(w)
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "  %s %s\n", s.Yellow("!"), s.Dim(n))
	}
	if rep.Firewall == nil {
		fmt.Fprintf(w, "  %s %s\n", s.Dim("·"), s.Dim("Sin evaluar el firewall, cada puerto en la red se muestra como accesible, aunque puede estar filtrado."))
	}
	fmt.Fprintln(w)
}

// surfaceChanges muestra lo que ha cambiado desde el último análisis
// guardado: primero lo que aumenta la exposición.
func surfaceChanges(w io.Writer, rep *surface.Report, s Style) {
	w = SafeWriter(w)
	ch := rep.Changes
	if ch == nil {
		return
	}
	since := ch.Since.Local().Format("02/01/2006 15:04")
	if len(ch.Items) == 0 {
		fmt.Fprintf(w, "              %s\n", s.Dim("Sin cambios en la exposición desde el "+since+"."))
		return
	}
	fmt.Fprintln(w)
	delta := ""
	if d := rep.Score - ch.ScoreBefore; d != 0 {
		delta = fmt.Sprintf(" · exposición %d → %d", ch.ScoreBefore, rep.Score)
	}
	fmt.Fprintf(w, "  %s %s\n", s.Bold("CAMBIOS DESDE EL "+since), s.Dim(fmt.Sprintf("(%d)%s", len(ch.Items), delta)))
	fmt.Fprintln(w, "  "+s.Dim(strings.Repeat("─", 72)))
	for _, c := range ch.Items {
		var sym string
		switch c.Kind {
		case surface.ChangeNew:
			sym = s.Red("+")
		case surface.ChangeWorse:
			sym = s.Red(Sym("↑"))
		case surface.ChangeBetter:
			sym = s.Green(Sym("↓"))
		case surface.ChangeGone:
			sym = s.Green("-")
		case surface.ChangeFinding:
			sym = s.Red("!")
		case surface.ChangeResolved:
			sym = s.Green(Sym("✓"))
		}
		text := c.Title
		switch c.Kind {
		case surface.ChangeFinding:
			text = "Hallazgo nuevo (" + strings.ToLower(SeverityLabel(c.Severity)) + "): " + text
		case surface.ChangeResolved:
			text = "Resuelto: " + text
		}
		fmt.Fprintf(w, "  %s %s\n", sym, text)
	}
}
