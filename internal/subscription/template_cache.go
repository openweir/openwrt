package subscription

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/openweir/openwrt/internal/atomicfile"
	"github.com/openweir/subconv/rules"
)

// The router's copy of the rules branch (TemplateDir) is the last version a refresh got whole:
// its manifest, floor, template and rule sets, under their branch paths, in a generation
// directory that the link @current names. A refresh reads the generation that was current when
// it began, and keeps what it gets in memory (templateStage). Only once every rule set of the
// template arrived does it write the next generation and move the link to it, in one rename: a
// refresh that fails, runs out of time or is killed leaves the copy as it was. Names that start
// with '@', which no branch path has, are the copy's own.
const (
	// Held, exclusively, to pin a generation, promote one and sweep.
	templateLock = "@lock"
	// The link to the current generation, and the link that replaces it.
	templateCurrent     = "@current"
	templateCurrentNext = "@current.next"
	// A generation: complete once the link names it.
	templateGeneration = "@gen-"
	// The temporary files of the copy before generations, which a helper killed mid-write left.
	// A helper of that version may still be writing one during an upgrade: only old ones go.
	templateTemp      = ".new-"
	templateTempStale = 10 * time.Minute
)

// templateStage is the rules client's cache in one refresh: the generation current when the
// refresh first used the copy (its base), held so that no sweep removes it meanwhile, under what
// the refresh got that differs from it, in memory.
type templateStage struct {
	root string

	mu     sync.Mutex
	pinned bool
	name   string   // of the base generation; "" when the base is root, the copy before generations
	base   *os.File // the base directory, with a shared lock; nil without one
	staged map[string][]byte
}

func (s *templateStage) Get(key string) ([]byte, bool) {
	s.mu.Lock()
	value, ok := s.staged[key]
	base := s.pin()
	s.mu.Unlock()
	if ok {
		return value, true
	}
	return readGeneration(base, key)
}

func (s *templateStage) Put(key string, value []byte) {
	if !rules.ValidPath(key) || len(value) > MaxBody {
		return
	}
	s.mu.Lock()
	base := s.pin()
	s.mu.Unlock()
	old, ok := readGeneration(base, key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok && bytes.Equal(old, value) {
		delete(s.staged, key)
		return
	}
	if s.staged == nil {
		s.staged = map[string][]byte{}
	}
	s.staged[key] = bytes.Clone(value)
}

// pin sweeps the copy and holds its current generation, on first use. It returns the base
// directory, or "" without one.
func (s *templateStage) pin() string {
	if !s.pinned {
		s.pinned = true
		if lock, err := lockTemplate(s.root); err == nil {
			s.name = sweepTemplate(s.root)
			s.base = holdGeneration(filepath.Join(s.root, s.name))
			unlock(lock)
		}
	}
	if s.base == nil {
		return ""
	}
	return s.base.Name()
}

// discard forgets what the refresh got: the client reads the base alone.
func (s *templateStage) discard() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staged = nil
}

// close lets go of the base.
func (s *templateStage) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staged = nil
	if s.base != nil {
		s.base.Close()
		s.base = nil
	}
}

// promote makes what the refresh got the router's copy: a new generation of the manifest, the
// floor and the files the manifest lists takes the place of the current one. Files the refresh
// did not change are links to the base's; the rest of the base, which the manifest no longer
// lists, is left behind with it. When another refresh promoted the same version or a newer one
// since this one began, that stays. The stage is spent.
func (s *templateStage) promote() {
	s.mu.Lock()
	defer s.mu.Unlock()
	staged := s.staged
	s.staged = nil
	if len(staged) == 0 {
		return
	}
	base := s.pin()
	get := func(key string) ([]byte, bool) {
		if value, ok := staged[key]; ok {
			return value, true
		}
		return readGeneration(base, key)
	}
	raw, _ := get(rules.ManifestPath)
	m, err := rules.ParseManifest(raw)
	if err != nil {
		return
	}
	lock, err := lockTemplate(s.root)
	if err != nil {
		return
	}
	defer unlock(lock)
	if current := currentGeneration(s.root); current != s.name {
		other := filepath.Join(s.root, current)
		if b, ok := readGeneration(other, rules.ManifestPath); ok {
			if om, err := rules.ParseManifest(b); err == nil && om.Version >= m.Version {
				return
			}
		}
		// Keep the higher floor of the two.
		if theirs, ok := readGeneration(other, rules.FloorKey); ok {
			if ours, _ := get(rules.FloorKey); floorVersion(theirs) > floorVersion(ours) {
				staged[rules.FloorKey] = theirs
			}
		}
	}
	dir, err := os.MkdirTemp(s.root, templateGeneration)
	if err != nil {
		return
	}
	if err = fillGeneration(dir, base, staged, m); err == nil {
		err = switchGeneration(s.root, filepath.Base(dir))
	}
	if err != nil {
		os.RemoveAll(dir)
		return
	}
	// The refresh reads no more: its base can go now.
	if s.base != nil {
		s.base.Close()
		s.base = nil
	}
	sweepTemplate(s.root)
}

// fillGeneration writes the manifest, the floor and the files the manifest lists into dir: what
// the refresh staged, and links to the rest in the base. A file neither has is left out.
func fillGeneration(dir, base string, staged map[string][]byte, m *rules.Manifest) error {
	keys := []string{rules.ManifestPath, rules.FloorKey}
	for _, f := range m.Files {
		keys = append(keys, f.Path)
	}
	dirs := map[string]bool{dir: true}
	done := map[string]bool{}
	for _, key := range keys {
		if done[key] || !rules.ValidPath(key) {
			continue
		}
		done[key] = true
		path := filepath.Join(dir, filepath.FromSlash(key))
		for d := filepath.Dir(path); !dirs[d]; d = filepath.Dir(d) {
			dirs[d] = true
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if value, ok := staged[key]; ok {
			if err := writeSynced(path, value); err != nil {
				return err
			}
			continue
		}
		if base == "" {
			continue
		}
		from := filepath.Join(base, filepath.FromSlash(key))
		if err := os.Link(from, path); err == nil || errors.Is(err, fs.ErrNotExist) {
			continue
		}
		// A file system without links: copy.
		if value, err := os.ReadFile(from); err != nil || writeSynced(path, value) != nil {
			return errors.New("template_cache_write_failed")
		}
	}
	for d := range dirs {
		if err := atomicfile.SyncDir(d); err != nil {
			return err
		}
	}
	return nil
}

// switchGeneration points the link at a generation, in one rename.
func switchGeneration(root, name string) error {
	next := filepath.Join(root, templateCurrentNext)
	os.Remove(next)
	err := os.Symlink(name, next)
	if err == nil {
		err = atomicfile.SyncDir(root)
	}
	if err == nil {
		err = os.Rename(next, filepath.Join(root, templateCurrent))
	}
	if err != nil {
		os.Remove(next)
		return err
	}
	return atomicfile.SyncDir(root)
}

// writeSynced is not atomicfile: it fills a new generation, which switchGeneration publishes whole.
func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func readGeneration(dir, key string) ([]byte, bool) {
	if dir == "" || !rules.ValidPath(key) {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(key)))
	return b, err == nil
}

func floorVersion(b []byte) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func lockTemplate(root string) (*os.File, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(root, templateLock), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// currentGeneration is the generation the link names, or "" for root: the copy before
// generations, or none.
func currentGeneration(root string) string {
	name, err := os.Readlink(filepath.Join(root, templateCurrent))
	if err != nil || !strings.HasPrefix(name, templateGeneration) || strings.ContainsRune(name, filepath.Separator) {
		return ""
	}
	return name
}

// holdGeneration opens a generation's directory with a shared lock, which keeps sweeps from
// removing it while a refresh reads it. The lock goes with the process, however it ends.
func holdGeneration(dir string) *os.File {
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil {
		f.Close()
		return nil
	}
	return f
}

// ifUnheld runs remove when no refresh holds the generation in dir.
func ifUnheld(dir string, remove func()) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	defer f.Close()
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		remove()
	}
}

// sweepTemplate, under the lock, removes what no refresh uses: generations other than the
// current one that no refresh holds (one a promotion did not finish, or that a newer one
// replaced), a link a promotion did not finish, and once a generation is current, the copy
// before generations; while that copy is still current, its old temporary files. It returns
// the current generation.
func sweepTemplate(root string) string {
	current := currentGeneration(root)
	entries, _ := os.ReadDir(root)
	before := false
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(root, name)
		switch {
		case name == templateLock || name == templateCurrent || name == current:
		case strings.HasPrefix(name, templateGeneration) && e.IsDir():
			ifUnheld(path, func() { os.RemoveAll(path) })
		case strings.HasPrefix(name, "@"):
			os.RemoveAll(path)
		default:
			before = true
		}
	}
	switch {
	case before && current != "":
		ifUnheld(root, func() {
			for _, e := range entries {
				if !strings.HasPrefix(e.Name(), "@") {
					os.RemoveAll(filepath.Join(root, e.Name()))
				}
			}
		})
	case before:
		stale := time.Now().Add(-templateTempStale)
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return nil
			case path != root && strings.HasPrefix(d.Name(), "@"):
				if d.IsDir() {
					return filepath.SkipDir
				}
			case d.Type().IsRegular() && strings.HasPrefix(d.Name(), templateTemp):
				if info, err := d.Info(); err == nil && info.ModTime().Before(stale) {
					os.Remove(path)
				}
			}
			return nil
		})
	}
	return current
}
