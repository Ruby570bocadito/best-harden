package surface

import (
	"fmt"
	"path"
	"strings"

	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

// sigInfo es el origen de un ejecutable.
type sigInfo struct{ status, signer string }

// parsePSSignatures interpreta la consulta file_signatures: estado de
// Get-AuthenticodeSignature y titular del certificado por ruta (en
// minúsculas: las rutas de Windows no distinguen mayúsculas).
func parsePSSignatures(data map[string]any) map[string]sigInfo {
	out := map[string]sigInfo{}
	files, _ := data["files"].(map[string]any)
	for p, v := range files {
		m, _ := v.(map[string]any)
		status, _ := m["status"].(string)
		subject, _ := m["signer"].(string)
		var s sigInfo
		switch status {
		case "Valid":
			s.status = SigValid
		case "NotSigned":
			s.status = SigUnsigned
		case "HashMismatch":
			s.status = SigInvalid
		case "NotTrusted", "UnknownError":
			// UnknownError: la firma no se puede verificar (certificado
			// caducado sin sello de tiempo, revocado, cadena incompleta…).
			s.status = SigUntrusted
		default:
			continue // formato no admitido o error al leerlo: sin dato
		}
		if s.status != SigUnsigned {
			s.signer = certCN(subject)
		}
		out[strings.ToLower(p)] = s
	}
	return out
}

// certCN extrae el nombre común (CN) del titular de un certificado:
// "CN=Valve Corp., O=Valve Corp., C=US" → "Valve Corp.".
func certCN(subject string) string {
	for rest := subject; rest != ""; {
		rest = strings.TrimLeft(rest, " ,")
		key, val, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		var v string
		if strings.HasPrefix(val, `"`) {
			end := strings.Index(val[1:], `"`)
			if end < 0 {
				break
			}
			v, rest = val[1:end+1], val[end+2:]
		} else {
			v, rest, _ = strings.Cut(val, ",")
		}
		if strings.EqualFold(strings.TrimSpace(key), "CN") {
			return strings.TrimSpace(v)
		}
	}
	return strings.TrimSpace(subject)
}

// parseDpkgSearch interpreta "dpkg-query -S ruta…": una línea "paquete:
// ruta" (o "paq1, paq2: ruta") por fichero de algún paquete; los que no
// son de ninguno salen por la salida de error.
func parseDpkgSearch(out string) map[string]string {
	pkgs := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		i := strings.Index(l, ": /")
		if i <= 0 || strings.HasPrefix(l, "diversion ") || strings.HasPrefix(l, "local diversion ") {
			continue
		}
		pkg := strings.TrimSpace(l[:i])
		if j := strings.IndexByte(pkg, ','); j > 0 {
			pkg = pkg[:j]
		}
		if j := strings.IndexByte(pkg, ':'); j > 0 {
			pkg = pkg[:j] // sin la arquitectura (openssh-server:amd64)
		}
		pkgs[strings.TrimSpace(l[i+2:])] = pkg
	}
	return pkgs
}

// parseRpmQuery interpreta "rpm -qf --qf '%{NAME}\n' ruta…": una línea por
// ruta, en el mismo orden; "file … is not owned by any package" si no es
// de ninguno.
func parseRpmQuery(paths []string, out string) map[string]string {
	pkgs := map[string]string{}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != len(paths) {
		return pkgs // salida inesperada: mejor sin dato que equivocado
	}
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.Contains(l, " ") {
			pkgs[paths[i]] = l // #nosec G602 -- len(lines) == len(paths), comprobado arriba
		}
	}
	return pkgs
}

// usrMergeAlt es la otra ruta de un fichero con /usr fusionado: dpkg puede
// tenerlo registrado como /bin/x aunque el proceso diga /usr/bin/x.
func usrMergeAlt(p string) string {
	for _, d := range []string{"/bin/", "/sbin/", "/lib/", "/lib64/"} {
		if strings.HasPrefix(p, "/usr"+d) {
			return strings.TrimPrefix(p, "/usr")
		}
		if strings.HasPrefix(p, d) {
			return "/usr" + p
		}
	}
	return ""
}

// snapName devuelve el snap de una ruta /snap/<nombre>/<revisión>/….
func snapName(p string) string {
	if !strings.HasPrefix(p, "/snap/") {
		return ""
	}
	parts := strings.SplitN(strings.TrimPrefix(path.Clean(p), "/snap/"), "/", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[0]
}

// exposedBinary es un ejecutable sin firma, fuera de los paquetes o con una
// firma que no vale, con puertos accesibles desde la red.
type exposedBinary struct {
	name, path, signer, status string
	ports                      []string
}

// baseName es el nombre del fichero de una ruta de Windows o de Unix.
func baseName(p string) string {
	return path.Base(strings.ReplaceAll(p, `\`, "/"))
}

// binaryFindings genera los hallazgos de origen de los programas que
// aceptan conexiones desde la red: uno agrupado para los que no tienen
// firma (o no son de ningún paquete) y uno por programa con una firma que no
// vale, que es mucho más grave.
func binaryFindings(bins []*exposedBinary) []Finding {
	var out []Finding
	var unsigned, unpackaged []*exposedBinary
	for _, b := range bins {
		ports := strings.Join(b.ports, ", ")
		switch b.status {
		case SigUnsigned:
			unsigned = append(unsigned, b)
		case SigNoPackage:
			unpackaged = append(unpackaged, b)
		case SigInvalid:
			out = append(out, Finding{ID: "SURF-BADSIG", Severity: rule.SevHigh, Subject: ports,
				Title: fmt.Sprintf("La firma de %s no es válida: el fichero se ha modificado después de firmarlo", b.name),
				Detail: fmt.Sprintf("Windows dice que el contenido de %s no coincide con su firma (de %s). Puede ser una actualización a medias, "+
					"pero también un programa manipulado, y acepta conexiones desde la red (%s).", b.path, firstNonEmpty(b.signer, "un firmante desconocido"), ports),
				Fix: fmt.Sprintf("Termina el proceso, analiza el fichero con Microsoft Defender (Start-MpScan -ScanType CustomScan -ScanPath '%s') "+
					"y reinstala el programa desde su origen oficial.", b.path)})
		case SigUntrusted:
			out = append(out, Finding{ID: "SURF-BADSIG", Severity: rule.SevMedium, Subject: ports,
				Title: fmt.Sprintf("%s está firmado con un certificado en el que Windows no confía (%s)", b.name, firstNonEmpty(b.signer, "firmante desconocido")),
				Detail: fmt.Sprintf("La firma de %s no garantiza quién lo ha hecho: el certificado es propio (autofirmado), de una entidad en la que "+
					"Windows no confía, está revocado o no se puede verificar (caducado sin sello de tiempo). Acepta conexiones desde la red (%s).", b.path, ports),
				Fix: fmt.Sprintf("Comprueba de dónde viene el programa; si no lo reconoces, analízalo con Microsoft Defender (Start-MpScan -ScanType CustomScan -ScanPath '%s') "+
					"y reinstálalo desde su origen oficial.", b.path)})
		}
	}
	group := func(bs []*exposedBinary, id, one, many, detail, fix string) {
		if len(bs) == 0 {
			return
		}
		var names, paths, ports []string
		for _, b := range bs {
			names = append(names, fmt.Sprintf("%s (%s)", b.name, strings.Join(b.ports, ", ")))
			paths = append(paths, b.path)
			ports = append(ports, b.ports...)
		}
		subject := strings.Join(ports, ", ")
		if len(ports) > 4 {
			subject = strings.Join(ports[:4], ", ") + "…"
		}
		title := fmt.Sprintf(one, names[0])
		if len(bs) > 1 {
			title = fmt.Sprintf(many, len(bs), shortList(names, 3))
		}
		out = append(out, Finding{ID: id, Severity: rule.SevLow, Subject: subject, Title: title,
			Detail: detail + " Rutas: " + strings.Join(paths, "; ") + ".", Fix: fix})
	}
	group(unsigned, "SURF-UNSIGNED", "%s no tiene firma digital y acepta conexiones desde la red",
		"%d programas sin firma digital aceptan conexiones desde la red: %s",
		"Sin firma no se puede comprobar quién ha hecho un programa ni que no se haya modificado después. Es lo habitual en puertas traseras, "+
			"pero también en herramientas pequeñas, juegos y programas hechos con Python o Node.",
		"Comprueba que reconoces cada programa y su carpeta. Si alguno no te suena, analízalo con Microsoft Defender "+
			"(Start-MpScan -ScanType CustomScan -ScanPath '<ruta>') antes de seguir usándolo; si lo usas, limita su regla del firewall a la red local (adarve surface fix).")
	group(unpackaged, "SURF-UNPACKAGED", "%s no es de ningún paquete y acepta conexiones desde la red",
		"%d programas que no son de ningún paquete aceptan conexiones desde la red: %s",
		"Lo que no viene de un paquete no recibe las actualizaciones de seguridad del sistema y nada garantiza su origen: hay que mantenerlo al día a mano.",
		"Comprueba que reconoces cada programa y su origen, y actualízalo desde allí; si solo se usa en el propio equipo, haz que escuche en 127.0.0.1.")
	return out
}

// Origin resume de dónde viene el ejecutable de un puerto, para mostrarlo
// junto al proceso. warn indica que conviene revisarlo (sin firma, firma
// que no vale, fuera de los paquetes).
func (p Port) Origin() (text string, warn bool) {
	switch p.Signature {
	case SigValid:
		return "firmado por " + firstNonEmpty(p.Signer, "?"), false
	case SigUnsigned:
		return "sin firma digital", true
	case SigInvalid:
		return "firma no válida", true
	case SigUntrusted:
		return "certificado sin confianza", true
	case SigPackage:
		return "paquete " + firstNonEmpty(p.Signer, "?"), false
	case SigNoPackage:
		return "fuera de los paquetes", true
	}
	return "", false
}
