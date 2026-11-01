//go:build !windows

package sysdir

// Fuera de Windows no se usan: devuelven las rutas por defecto para que el
// código común compile y se pueda probar.
func systemDir() string   { return `C:\Windows\System32` }
func windowsDir() string  { return `C:\Windows` }
func programData() string { return `C:\ProgramData` }
