//go:build windows

package cli

import (
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// shellExecuteInfo es SHELLEXECUTEINFOW (shellapi.h).
type shellExecuteInfo struct {
	cbSize      uint32
	fMask       uint32
	hwnd        uintptr
	verb        *uint16
	file        *uint16
	parameters  *uint16
	directory   *uint16
	show        int32
	instApp     uintptr
	idList      uintptr
	class       *uint16
	keyClass    uintptr
	hotKey      uint32
	iconMonitor uintptr
	process     windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
)

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// relaunchElevated vuelve a lanzar Bastion con los argumentos dados en una
// ventana de administrador (aviso de UAC), espera a que termine y devuelve
// su código de salida. El proceso elevado no hereda las variables de
// entorno de esta consola: todo lo que necesite debe ir en args.
func relaunchElevated(args []string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = windows.EscapeArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	params, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return 0, err
	}
	info := shellExecuteInfo{fMask: seeMaskNoCloseProcess | seeMaskNoAsync, verb: verb, file: file,
		parameters: params, show: windows.SW_SHOWNORMAL}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, e := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		if errors.Is(e, windows.ERROR_CANCELLED) {
			return 0, errors.New("se canceló el aviso de Windows: no se ha actualizado nada")
		}
		return 0, e
	}
	if info.process == 0 {
		return 0, errors.New("no se pudo seguir la ventana de administrador: comprueba el resultado en ella")
	}
	defer windows.CloseHandle(info.process)
	if _, err := windows.WaitForSingleObject(info.process, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.process, &code); err != nil {
		return 0, err
	}
	return int(code), nil
}

func canElevate() bool { return true }
