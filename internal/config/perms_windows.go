//go:build windows

package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func icacls(args ...string) error {
	return exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), args...).Run()
}

// restrictPermissions limita el directorio a Administradores y SYSTEM.
// Se usan SIDs para que funcione con Windows en cualquier idioma.
//
// Un usuario sin privilegios puede crear carpetas en %ProgramData%: si
// creara C:\ProgramData\Adarve antes de la instalación, seguiría siendo
// su propietario (y el propietario siempre puede cambiar los permisos) y
// podría dejar un config.yaml que apuntara las actualizaciones a un espejo
// suyo. Por eso, además de fijar los permisos de la carpeta, se pasa la
// propiedad de todo a Administradores y se restablecen los permisos de su
// contenido para que solo hereden los de la carpeta.
func restrictPermissions(dir string) error {
	if err := icacls(dir, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"); err != nil {
		return err
	}
	if err := icacls(dir, "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "/Q"); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return err
	}
	return icacls(filepath.Join(dir, "*"), "/reset", "/T", "/C", "/Q")
}

// GrantUserRead da permiso de lectura sobre dir al usuario que ejecuta
// Adarve. Con UAC, el navegador y el Explorador se ejecutan sin elevar y el
// grupo Administradores no les sirve: sin este permiso el usuario no podría
// abrir sus propios informes.
func GrantUserRead(dir string) error {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := tu.User.Sid.String()
	if sid == "S-1-5-18" { // SYSTEM (tarea programada o servicio): nada que hacer
		return nil
	}
	return icacls(dir, "/grant", "*"+sid+":(OI)(CI)RX", "/Q")
}

// trustedSIDs pueden modificar los ficheros de Adarve: SYSTEM,
// Administradores, TrustedInstaller, CREADOR PROPIETARIO (solo se hereda) y
// DERECHOS DE PROPIETARIO (el propietario ya se exige de confianza).
var trustedSIDs = map[string]bool{
	"S-1-5-18":     true,
	"S-1-5-32-544": true,
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
	"S-1-3-0": true,
	"S-1-3-4": true,
}

// Derechos de acceso a ficheros (winnt.h).
const (
	fileWriteData   = 0x2 // también FILE_ADD_FILE en carpetas
	fileAppendData  = 0x4 // también FILE_ADD_SUBDIRECTORY
	fileWriteEA     = 0x10
	fileDeleteChild = 0x40
)

// writeMask devuelve los derechos que, en manos de un usuario sin
// privilegios, permiten sustituir o alterar path.
func writeMask(kind Kind) windows.ACCESS_MASK {
	common := windows.ACCESS_MASK(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL)
	switch kind {
	case KindAncestor:
		return common | fileDeleteChild
	default:
		return common | windows.GENERIC_WRITE | fileWriteData | fileAppendData | fileWriteEA | fileDeleteChild
	}
}

// CheckAdminOnly comprueba que path pertenezca a Administradores, SYSTEM o
// TrustedInstaller y que su DACL no conceda a nadie más derechos para
// modificarlo (según kind).
func CheckAdminOnly(path string, kind Kind) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("no se pueden leer los permisos de %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("no se puede leer el propietario de %s", path)
	}
	if !trustedSIDs[owner.String()] {
		return fmt.Errorf("%s pertenece a %s, no a Administradores ni a SYSTEM", path, sidName(owner))
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("no se pueden leer los permisos de %s: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s no tiene lista de permisos: cualquiera puede modificarlo", path)
	}
	bad := writeMask(kind)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("no se pueden leer los permisos de %s: %w", path, err)
		}
		// Solo cuentan las entradas de permiso que se aplican al propio
		// objeto: ACCESS_ALLOWED (0) y ACCESS_ALLOWED_CALLBACK (9), que
		// tienen la misma estructura.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != 9 {
			continue
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&bad == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustedSIDs[sid.String()] {
			return fmt.Errorf("%s: %s puede modificarlo (derechos 0x%x)", path, sidName(sid), uint32(ace.Mask))
		}
	}
	return nil
}

func sidName(sid *windows.SID) string {
	if acc, dom, _, err := sid.LookupAccount(""); err == nil {
		if dom != "" {
			return dom + `\` + acc
		}
		return acc
	}
	return sid.String()
}
