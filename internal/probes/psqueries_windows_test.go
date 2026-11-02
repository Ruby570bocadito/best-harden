//go:build windows

package probes

import (
	"regexp"
	"testing"
)

// En Windows PowerShell 5.1, [string]::Join con una variable que no es un
// array (un ArrayList, una List) la toma como un único objeto y devuelve el
// nombre del tipo: «System.Collections.ArrayList» hacía fallar WIN-DEF-013
// en cualquier Windows, tuviera o no exclusiones. Con @(...) o con -join,
// no pasa.
func TestPSQueriesJoin(t *testing.T) {
	joinVar := regexp.MustCompile(`\[string\]::Join\([^,]+,\s*\$`)
	for name, q := range psQueries {
		if joinVar.MatchString(q.script) {
			t.Errorf("%s: [string]::Join sobre una variable; usa -join o @(...)", name)
		}
	}
}
