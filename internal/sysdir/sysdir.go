// Package sysdir resuelve las carpetas del sistema de Windows sin fiarse de
// las variables de entorno.
//
// SystemRoot, windir o ProgramData las puede cambiar cualquier programa del
// usuario (HKCU\Environment) y una consola de administrador las hereda: una
// ruta construida con ellas permitiría que Adarve, ejecutado con privilegios,
// lanzara un powershell.exe o un icacls.exe ajeno. Por eso se preguntan al
// sistema (GetSystemDirectory, GetSystemWindowsDirectory, SHGetKnownFolderPath).
package sysdir

import "path/filepath"

// System32 devuelve la ruta absoluta de una herramienta de System32.
func System32(exe string) string { return filepath.Join(systemDir(), exe) }

// WindowsTemp es %SystemRoot%\Temp, resuelto sin variables de entorno.
func WindowsTemp() string { return filepath.Join(windowsDir(), "Temp") }

// ProgramData es la carpeta de datos de programa de todos los usuarios.
func ProgramData() string { return programData() }
