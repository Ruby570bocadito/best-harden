// Adarve: auditoría y hardening para Windows, Windows Server y Linux.
package main

import (
	"os"

	"github.com/Ruby570bocadito/adarve/internal/cli"
	"github.com/Ruby570bocadito/adarve/internal/selfupdate"
)

func main() {
	selfupdate.CleanupOld()
	os.Exit(cli.Execute())
}
