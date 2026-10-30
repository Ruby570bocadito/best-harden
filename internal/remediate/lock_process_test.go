package remediate

import (
	"bufio"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestHelperHoldLock no es un test: es el proceso hijo de
// TestLockAcrossProcesses. Toma el bloqueo, lo anuncia y espera a que lo maten.
func TestHelperHoldLock(t *testing.T) {
	dir := os.Getenv("BASTION_TEST_LOCK_DIR")
	if dir == "" {
		t.Skip("solo como proceso auxiliar")
	}
	if _, err := (&Store{Dir: dir}).Lock(); err != nil {
		os.Stdout.WriteString("error " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Stdout.WriteString("locked\n")
	time.Sleep(time.Minute)
	os.Exit(0)
}

// TestLockAcrossProcesses comprueba el bloqueo entre procesos de verdad (el
// caso de harden y el dead-man switch) y que, si el dueño muere sin
// liberarlo, el sistema lo libera.
func TestLockAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldLock$")
	cmd.Env = append(os.Environ(), "BASTION_TEST_LOCK_DIR="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill() //nolint:errcheck // limpieza si el test falla antes
	line, _ := bufio.NewReader(out).ReadString('\n')
	if line != "locked\n" {
		t.Fatalf("el proceso hijo no tomó el bloqueo: %q", line)
	}

	st := &Store{Dir: dir}
	if _, err := st.Lock(); err == nil {
		t.Fatal("otro proceso tiene el bloqueo: no debe poder tomarse")
	}
	// El dueño muere sin liberar nada (como un harden interrumpido).
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for {
		unlock, err := st.Lock()
		if err == nil {
			unlock()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("el bloqueo de un proceso muerto debe liberarse: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
