//go:build windows

package sysdir

import (
	"sync"

	"golang.org/x/sys/windows"
)

var dirs = sync.OnceValues(func() (sys, win string) {
	sys, err := windows.GetSystemDirectory()
	if err != nil || sys == "" {
		sys = `C:\Windows\System32`
	}
	win, err = windows.GetSystemWindowsDirectory()
	if err != nil || win == "" {
		win = `C:\Windows`
	}
	return sys, win
})

func systemDir() string  { s, _ := dirs(); return s }
func windowsDir() string { _, w := dirs(); return w }

var programDataDir = sync.OnceValue(func() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil && p != "" {
		return p
	}
	return `C:\ProgramData`
})

func programData() string { return programDataDir() }
