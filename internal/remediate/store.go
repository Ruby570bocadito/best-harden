package remediate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// ManifestSchema es la versión del formato de manifiesto de cambios.
const ManifestSchema = "bastion.change/v1"

// Estados de un cambio.
const (
	StatusInProgress = "in-progress"
	StatusApplied    = "applied"
	StatusPartial    = "partial"
	StatusFailed     = "failed"
	StatusRolledBack = "rolled-back"
	StatusNothing    = "nothing"
)

// Entry es una acción aplicada (o intentada) con su estado previo.
type Entry struct {
	Seq          int         `json:"seq"`
	RuleID       string      `json:"rule_id"`
	Action       rule.Action `json:"action"`
	Description  string      `json:"description"`
	Before       State       `json:"before"`
	RemoteAccess bool        `json:"remote_access,omitempty"`
	// Attempted se marca ANTES de aplicar (registro previo): si el proceso
	// muere a mitad, el rollback también restaura esta entrada.
	Attempted  bool   `json:"attempted"`
	Applied    bool   `json:"applied"`
	RolledBack bool   `json:"rolled_back,omitempty"`
	Error      string `json:"error,omitempty"`
}

// RuleOutcome es el resultado final de una regla dentro de un cambio.
type RuleOutcome struct {
	RuleID  string `json:"rule_id"`
	Title   string `json:"title"`
	Outcome string `json:"outcome"`
	Message string `json:"message,omitempty"`
}

// Manifest describe un cambio completo y permite deshacerlo.
type Manifest struct {
	Schema          string        `json:"schema"`
	ID              string        `json:"id"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
	ToolVersion     string        `json:"tool_version"`
	Host            string        `json:"host"`
	Profile         string        `json:"profile"`
	Wave            int           `json:"wave"`
	Status          string        `json:"status"`
	RebootRequired  bool          `json:"reboot_required,omitempty"`
	Confirmed       bool          `json:"confirmed,omitempty"`
	DeadmanDeadline *time.Time    `json:"deadman_deadline,omitempty"`
	DeadmanFired    bool          `json:"deadman_fired,omitempty"`
	Entries         []*Entry      `json:"entries"`
	Rules           []RuleOutcome `json:"rules"`

	store *Store
	mu    sync.Mutex
}

var reChangeID = regexp.MustCompile(`^chg-[0-9]{8}-[0-9]{6}(-[0-9]+)?$`)

// Store guarda los manifiestos en <datos>/snapshots/<id>/manifest.json.
type Store struct{ Dir string }

// NewManifest crea un manifiesto vacío con un ID basado en la fecha.
func (s *Store) NewManifest(host, profile, version string, wave int) *Manifest {
	now := time.Now()
	id := "chg-" + now.Format("20060102-150405")
	for i := 2; ; i++ {
		if _, err := os.Stat(filepath.Join(s.Dir, id)); errors.Is(err, fs.ErrNotExist) {
			break
		}
		id = fmt.Sprintf("chg-%s-%d", now.Format("20060102-150405"), i)
	}
	return &Manifest{Schema: ManifestSchema, ID: id, CreatedAt: now.UTC(), ToolVersion: version,
		Host: host, Profile: profile, Wave: wave, Status: StatusInProgress, store: s}
}

func (m *Manifest) dir() string { return filepath.Join(m.store.Dir, m.ID) }

// Save escribe el manifiesto de forma atómica: un temporal único (dos
// procesos, el principal y el dead-man switch, pueden escribir el mismo
// cambio), sincronizado a disco antes de renombrarlo.
func (m *Manifest) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.UpdatedAt = time.Now().UTC()
	dir := m.dir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "manifest.json"), b, 0o640)
}

// writeFileAtomic escribe en un temporal único del mismo directorio, hace
// fsync y lo renombra. En Windows el renombrado puede fallar un instante si
// otro proceso está leyendo el destino: se reintenta.
func writeFileAtomic(path string, b []byte, mode fs.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	for i := 0; ; i++ {
		err = os.Rename(tmp, path)
		if err == nil || i >= 20 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	ok = true
	return nil
}

// Load lee un manifiesto por ID.
func (s *Store) Load(id string) (*Manifest, error) {
	if !reChangeID.MatchString(id) {
		return nil, fmt.Errorf("ID de cambio inválido: %q (formato chg-AAAAMMDD-HHMMSS)", id)
	}
	b, err := os.ReadFile(filepath.Join(s.Dir, id, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("no existe el cambio %s", id)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.ID != id {
		return nil, fmt.Errorf("el manifiesto %s declara otro ID (%q)", id, m.ID)
	}
	m.store = s
	return &m, nil
}

// List devuelve los manifiestos, del más reciente al más antiguo.
func (s *Store) List() ([]*Manifest, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Manifest
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "chg-") {
			continue
		}
		if m, err := s.Load(e.Name()); err == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Latest devuelve el último cambio que se puede deshacer.
func (s *Store) Latest() (*Manifest, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if m.Status != StatusRolledBack && m.Status != StatusNothing && m.pending(nil) > 0 {
			return m, nil
		}
	}
	return nil, errors.New("no hay cambios que deshacer")
}

func (m *Manifest) pending(filter func(*Entry) bool) int {
	n := 0
	for _, e := range m.Entries {
		if e.Attempted && !e.RolledBack && (filter == nil || filter(e)) {
			n++
		}
	}
	return n
}

// mergeFromDisk incorpora lo que otro proceso (el dead-man switch, un
// rollback) haya escrito en disco: las entradas restauradas y si saltó el
// dead-man switch. Solo avanza esos indicadores (nunca los deshace), así que
// es seguro llamarlo con cualquier copia. Se llama con el bloqueo del cambio.
func (m *Manifest) mergeFromDisk() {
	disk, err := m.store.Load(m.ID)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	bySeq := map[int]*Entry{}
	for _, e := range disk.Entries {
		bySeq[e.Seq] = e
	}
	for _, e := range m.Entries {
		d := bySeq[e.Seq]
		if d == nil || d.RuleID != e.RuleID || d.Action.Type != e.Action.Type {
			continue
		}
		if d.RolledBack && !e.RolledBack {
			e.RolledBack = true
		}
		if e.Error == "" && d.Error != "" {
			e.Error = d.Error
		}
	}
	if disk.DeadmanFired {
		m.DeadmanFired = true
		m.Confirmed = false
	}
	if disk.Confirmed && !m.DeadmanFired {
		m.Confirmed = true
	}
}

// ---- Bloqueos ------------------------------------------------------------

// LockWait es lo que se espera como mucho por el bloqueo de un cambio que
// tiene otro proceso (p. ej. el dead-man switch revirtiendo). Variable para
// los tests.
var LockWait = 15 * time.Minute

// staleLockAge es la antigüedad a partir de la cual un bloqueo sin PID
// legible se considera abandonado. Si el bloqueo tiene PID, se considera
// abandonado solo cuando ese proceso ya no existe (sin límite de tiempo:
// una confirmación remota o un rollback largo no lo invalidan). La
// reutilización de PID tras un reinicio puede retener un bloqueo huérfano;
// en ese caso el mensaje de error indica qué fichero borrar.
const staleLockAge = 30 * time.Minute

// lockStale indica si el fichero de bloqueo está abandonado.
func lockStale(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false // desapareció o no se puede leer: se reintenta
	}
	if f := strings.Fields(string(b)); len(f) > 0 {
		if pid, err := strconv.Atoi(f[0]); err == nil && pid > 0 {
			return !processAlive(pid)
		}
	}
	st, err := os.Stat(path)
	return err == nil && time.Since(st.ModTime()) > staleLockAge
}

// acquireLock crea path en exclusiva (con el PID dentro) y espera hasta wait
// si lo tiene otro proceso vivo.
func acquireLock(path string, wait time.Duration) (func(), error) {
	deadline := time.Now().Add(wait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err == nil {
			fmt.Fprintf(f, "%d %s\n", os.Getpid(), time.Now().Format(time.RFC3339))
			f.Sync()
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if lockStale(path) {
			os.Remove(path)
			continue
		}
		if !time.Now().Before(deadline) {
			return nil, errBusy
		}
		time.Sleep(50 * time.Millisecond)
	}
}

var errBusy = errors.New("bloqueo ocupado")

// Lock evita dos operaciones de hardening simultáneas. Un bloqueo cuyo
// proceso ya no existe se considera abandonado.
func (s *Store) Lock() (func(), error) {
	if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(s.Dir, ".lock")
	unlock, err := acquireLock(path, 0)
	if errors.Is(err, errBusy) {
		return nil, fmt.Errorf("hay otra operación de hardening en curso (si no es así, borra %s)", path)
	}
	return unlock, err
}

// withLock ejecuta fn con el bloqueo de este cambio (entre procesos).
func (m *Manifest) withLock(fn func() error) error {
	if err := os.MkdirAll(m.dir(), 0o750); err != nil {
		return err
	}
	path := filepath.Join(m.dir(), ".lock")
	unlock, err := acquireLock(path, LockWait)
	if errors.Is(err, errBusy) {
		return fmt.Errorf("el cambio %s está bloqueado por otro proceso (si no es así, borra %s)", m.ID, path)
	}
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// withLockBestEffort es como withLock, pero si no consigue el bloqueo ejecuta
// fn de todos modos (y devuelve también ese error). Se usa para deshacer
// cambios: no restaurar es peor que hacerlo sin bloqueo.
func (m *Manifest) withLockBestEffort(fn func() error) error {
	ran := false
	err := m.withLock(func() error { ran = true; return fn() })
	if !ran {
		return errors.Join(err, fn())
	}
	return err
}

// saveMerged guarda el manifiesto con el bloqueo del cambio, tras incorporar
// lo que otro proceso haya escrito.
func (m *Manifest) saveMerged() error {
	return m.withLock(func() error {
		m.mergeFromDisk()
		return m.Save()
	})
}

// Log añade una línea al registro de cambios (changes.log, JSON por línea).
func (s *Store) Log(id, ruleID, event, detail string) {
	f, err := os.OpenFile(filepath.Join(s.Dir, "changes.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(map[string]string{
		"time": time.Now().UTC().Format(time.RFC3339), "change": id, "rule": ruleID, "event": event, "detail": detail,
	})
	f.Write(append(b, '\n'))
}
