//go:build !windows

package cli

import "errors"

func relaunchElevated([]string) (int, error) {
	return 0, errors.New("la elevación automática solo existe en Windows: usa sudo")
}

func canElevate() bool { return false }
