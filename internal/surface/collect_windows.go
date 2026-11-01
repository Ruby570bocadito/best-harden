//go:build windows

package surface

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Ruby570bocadito/adarve/internal/probes"
)

// Collect recoge el inventario en Windows con comandos fijos del sistema
// (netstat, tasklist) y consultas PowerShell de la lista blanca.
func Collect(ctx context.Context) (Inventory, error) {
	var inv Inventory
	out, err := run(ctx, probes.System32("netstat.exe"), "-ano")
	if err != nil {
		return inv, err
	}
	inv.Listeners = parseNetstat(out)
	for i := range inv.Listeners {
		// Los sockets UDP en el rango dinámico (49152-65535) son de clientes:
		// consultas DNS, descubrimiento, sesiones de escritorio remoto…
		l := &inv.Listeners[i]
		l.Ephemeral = l.Proto == "udp" && ephemeralUDP(l.Port, 49152, 65535)
	}
	if tl, err := run(ctx, probes.System32("tasklist.exe"), "/svc", "/fo", "csv", "/nh"); err == nil {
		procs := parseTasklist(tl)
		for i := range inv.Listeners {
			if p, ok := procs[inv.Listeners[i].PID]; ok {
				inv.Listeners[i].Process = p.image
				inv.Listeners[i].Services = p.services
			}
		}
	} else {
		inv.Notes = append(inv.Notes, "No se pudo asociar cada puerto con su proceso (tasklist): "+err.Error())
	}
	// Usuario de cada proceso: las reglas del firewall con propietario
	// (LocalUserOwner) solo se aplican a los procesos de ese usuario. Se lee
	// del token de cada proceso a la escucha: "tasklist /v" puede tardar
	// minutos (consulta el título de todas las ventanas).
	owners := map[int][2]string{}
	for i := range inv.Listeners {
		l := &inv.Listeners[i]
		o, ok := owners[l.PID]
		if !ok {
			o[0], o[1] = processOwner(l.PID)
			owners[l.PID] = o
		}
		l.User, l.UserSID = o[0], o[1]
	}

	collectSignatures(ctx, &inv)

	if data, err := probes.QueryPS(ctx, "smb_shares"); err == nil {
		inv.Shares = parsePSShares(data)
	} else if reason, ok := probes.AsPrivilege(err); ok {
		inv.Notes = append(inv.Notes, "Recursos compartidos sin evaluar: "+reason)
	} else {
		inv.Notes = append(inv.Notes, "No se pudieron leer los recursos compartidos: "+err.Error())
	}
	if data, err := probes.QueryPS(ctx, "local_admins"); err == nil {
		inv.Admins = parsePSAdmins(data)
	} else {
		inv.Notes = append(inv.Notes, "No se pudieron leer los miembros de Administradores: "+err.Error())
	}
	if fw, err := collectFirewall(ctx); err == nil {
		inv.Firewall = fw
	} else {
		inv.Notes = append(inv.Notes, "No se pudo leer la política del Firewall de Windows: los puertos se muestran sin filtrar. "+err.Error())
	}
	if fw := inv.Firewall; fw != nil {
		if fw.Source == "com" {
			inv.Notes = append(inv.Notes, "Sin acceso al registro, las reglas del firewall se han leído con COM, que no muestra las limitadas a dispositivos de confianza (Wi-Fi Direct, UPnP) o a IPsec: algún puerto puede aparecer abierto sin estarlo. Como administrador el resultado es exacto.")
		}
		for _, p := range fw.Active() {
			if !p.Enabled {
				inv.Notes = append(inv.Notes, "El Firewall de Windows está desactivado en el perfil "+p.Name+": si usas otro cortafuegos, Adarve no puede evaluarlo y considera abiertos todos los puertos.")
			}
		}
	}
	if !probes.Privileged() {
		inv.Notes = append(inv.Notes, "Sin privilegios de administrador algunos procesos aparecen sin nombre.")
	}
	return inv, nil
}

// collectFirewall lee la política del Firewall de Windows: los perfiles con
// COM y las reglas del registro, donde están completas. Si el registro no
// se puede leer (sin privilegios), las reglas también salen de COM.
func collectFirewall(ctx context.Context) (*Firewall, error) {
	query := "firewall_policy"
	rules, err := readFirewallRules()
	if err == nil && len(rules) > 0 {
		query = "firewall_profiles"
	}
	data, err := probes.QueryPS(ctx, query)
	if err != nil {
		return nil, err
	}
	fw := parsePSFirewall(data)
	if fw == nil {
		return nil, errors.New("la consulta no devolvió los perfiles")
	}
	fw.Source = "com"
	if query == "firewall_profiles" {
		fw.Rules, fw.InboundRules, fw.Source = rules, len(rules), "registry"
	}
	return fw, nil
}

// collectSignatures anota la ruta del ejecutable de cada proceso que
// escucha en la red y su firma Authenticode (incrustada o de catálogo).
func collectSignatures(ctx context.Context, inv *Inventory) {
	paths := map[int]string{}
	var list []string
	seen := map[string]bool{}
	for i := range inv.Listeners {
		l := &inv.Listeners[i]
		if l.Scope != ScopeNetwork || l.Ephemeral || l.PID <= 4 { // 0 y 4: inactivo y System
			continue
		}
		p, ok := paths[l.PID]
		if !ok {
			p = imagePath(l.PID)
			paths[l.PID] = p
		}
		l.Path = p
		if p != "" && !seen[strings.ToLower(p)] && len(list) < 200 {
			seen[strings.ToLower(p)] = true
			list = append(list, p)
		}
	}
	if len(list) == 0 {
		return
	}
	data, err := probes.QueryPSEnv(ctx, "file_signatures", "ADARVE_PATHS="+strings.Join(list, "\n"))
	if err != nil {
		inv.Notes = append(inv.Notes, "No se pudo comprobar la firma de los programas que escuchan en la red: "+err.Error())
		return
	}
	sigs := parsePSSignatures(data)
	for i := range inv.Listeners {
		l := &inv.Listeners[i]
		if s, ok := sigs[strings.ToLower(l.Path)]; ok && l.Path != "" {
			l.Signature, l.Signer = s.status, s.signer
		}
	}
}

// imagePath devuelve la ruta del ejecutable de un proceso (vacía si no se
// puede abrir: sin privilegios, los de otros usuarios).
func imagePath(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) // #nosec G115 -- los PID de Windows son de 32 bits
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf)) // #nosec G115 -- buffer de tamaño fijo (MAX_PATH ampliado)
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// processOwner devuelve el usuario (DOMINIO\usuario) y el SID del
// propietario de un proceso; vacíos si no se puede abrir su token (sin
// privilegios, los de otros usuarios).
func processOwner(pid int) (user, sid string) {
	if pid <= 4 { // 0 y 4: inactivo y System
		return "", ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) // #nosec G115 -- los PID de Windows son de 32 bits
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", ""
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", ""
	}
	sid = tu.User.Sid.String()
	if account, domain, _, err := tu.User.Sid.LookupAccount(""); err == nil {
		user = account
		if domain != "" {
			user = domain + `\` + account
		}
	}
	return user, sid
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return probes.DecodeConsole(out.Bytes()), nil
}
