package subscription

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/openweir/subconv/rules"
)

// branchManifest lists files by path and content.
func branchManifest(t *testing.T, version int64, files map[string]string) []byte {
	t.Helper()
	m := rules.Manifest{Version: version}
	for _, path := range slices.Sorted(maps.Keys(files)) {
		sum := sha256.Sum256([]byte(files[path]))
		m.Files = append(m.Files, rules.File{Path: path, Size: int64(len(files[path])), SHA256: hex.EncodeToString(sum[:])})
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// stageVersion stages a version's manifest, floor and files over the stage's base.
func stageVersion(t *testing.T, s *templateStage, version int64, files map[string]string) {
	t.Helper()
	s.Put(rules.ManifestPath, branchManifest(t, version, files))
	s.Put(rules.FloorKey, []byte(fmt.Sprintln(version)))
	for path, data := range files {
		s.Put(path, []byte(data))
	}
}

func current(t *testing.T, root string) string {
	t.Helper()
	name, err := os.Readlink(filepath.Join(root, templateCurrent))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, name)
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	var names []string
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	slices.Sort(names)
	return names
}

var version1 = map[string]string{rules.TemplatePath: "t1", "providers/a.txt": "a", "providers/b.txt": "b"}

// A promotion writes what changed, links what did not and leaves behind what the manifest no
// longer lists; a refresh still reading the generation it replaced keeps it until done.
func TestTemplatePromotionWritesOnlyChanges(t *testing.T) {
	root := t.TempDir()
	s := &templateStage{root: root}
	stageVersion(t, s, 1, version1)
	if _, err := os.Lstat(filepath.Join(root, templateCurrent)); err == nil {
		t.Fatal("staged values reached the copy before the promotion")
	}
	s.promote()
	s.close()
	gen1 := current(t, root)
	if got := entries(t, gen1); !slices.Equal(got, []string{"floor", "manifest.json", "providers/a.txt", "providers/b.txt", "template.yaml"}) {
		t.Fatal(got)
	}
	a1, _ := os.Stat(filepath.Join(gen1, "providers/a.txt"))

	// The same version again: nothing to promote.
	s = &templateStage{root: root}
	stageVersion(t, s, 1, version1)
	s.promote()
	s.close()
	if current(t, root) != gen1 {
		t.Fatal("an unchanged version was written again")
	}

	reader := &templateStage{root: root}
	if _, ok := reader.Get(rules.ManifestPath); !ok {
		t.Fatal("no manifest")
	}
	s = &templateStage{root: root}
	stageVersion(t, s, 2, map[string]string{rules.TemplatePath: "t1", "providers/a.txt": "a", "providers/c.txt": "c"})
	s.Put("../escape", []byte("x"))
	if _, ok := s.Get("../escape"); ok {
		t.Fatal("cache left its directory")
	}
	s.promote()
	s.close()
	gen2 := current(t, root)
	if got := entries(t, gen2); gen2 == gen1 || !slices.Equal(got, []string{"floor", "manifest.json", "providers/a.txt", "providers/c.txt", "template.yaml"}) {
		t.Fatal(gen2, got)
	}
	if a2, _ := os.Stat(filepath.Join(gen2, "providers/a.txt")); !os.SameFile(a1, a2) {
		t.Fatal("an unchanged rule set was written again")
	}
	// The reader keeps its generation, whole.
	if b, ok := reader.Get("providers/b.txt"); !ok || string(b) != "b" {
		t.Fatal("a generation in use went")
	}
	reader.close()
	next := &templateStage{root: root}
	next.Get(rules.ManifestPath)
	next.close()
	if _, err := os.Stat(gen1); err == nil {
		t.Fatal("a generation no refresh uses stayed")
	}
}

// A refresh that began on an older copy does not replace a newer version another one promoted
// meanwhile, nor lower its floor.
func TestTemplatePromotionKeepsANewerCopy(t *testing.T) {
	root := t.TempDir()
	s := &templateStage{root: root}
	stageVersion(t, s, 1, version1)
	s.promote()
	s.close()

	older, newer := &templateStage{root: root}, &templateStage{root: root}
	older.Get(rules.ManifestPath)
	newer.Get(rules.ManifestPath)
	s = &templateStage{root: root}
	stageVersion(t, s, 3, map[string]string{rules.TemplatePath: "t3", "providers/a.txt": "a"})
	s.promote()
	s.close()
	gen3 := current(t, root)
	stageVersion(t, older, 2, map[string]string{rules.TemplatePath: "t2", "providers/a.txt": "a"})
	older.promote()
	older.close()
	if current(t, root) != gen3 {
		t.Fatal("an older version replaced a newer one")
	}
	stageVersion(t, newer, 4, map[string]string{rules.TemplatePath: "t4", "providers/a.txt": "a"})
	newer.Put(rules.FloorKey, []byte("1\n"))
	newer.promote()
	newer.close()
	gen4 := current(t, root)
	if b, _ := os.ReadFile(filepath.Join(gen4, rules.ManifestPath)); gen4 == gen3 || !slices.Equal(b, branchManifest(t, 4, map[string]string{rules.TemplatePath: "t4", "providers/a.txt": "a"})) {
		t.Fatal("a newer version stayed out")
	}
	if floor, _ := os.ReadFile(filepath.Join(gen4, rules.FloorKey)); string(floor) != "3\n" {
		t.Fatalf("floor %q", floor)
	}
}

// What killed helpers and the copy before generations left goes, once no refresh can use it.
func TestTemplateSweep(t *testing.T) {
	root := t.TempDir()
	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// The copy as earlier versions kept it, with the temporary files of killed writes.
	write(rules.ManifestPath, string(branchManifest(t, 1, version1)))
	for path, data := range version1 {
		write(path, data)
	}
	write("providers/.new-old", "x")
	write("providers/.new-recent", "x")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(root, "providers/.new-old"), old, old); err != nil {
		t.Fatal(err)
	}
	// A generation a killed promotion did not finish, and its link.
	write(templateGeneration+"cut/manifest.json", "{}")
	if err := os.Symlink(templateGeneration+"cut", filepath.Join(root, templateCurrentNext)); err != nil {
		t.Fatal(err)
	}

	s := &templateStage{root: root}
	if b, ok := s.Get("providers/a.txt"); !ok || string(b) != "a" {
		t.Fatal("the copy before generations is not read")
	}
	if got := entries(t, root); !slices.Equal(got, []string{"@lock", "manifest.json", "providers/.new-recent", "providers/a.txt", "providers/b.txt", "template.yaml"}) {
		t.Fatal(got)
	}
	stageVersion(t, s, 2, map[string]string{rules.TemplatePath: "t2", "providers/a.txt": "a"})
	s.promote()
	s.close()
	gen := current(t, root)
	if got := entries(t, gen); !slices.Equal(got, []string{"floor", "manifest.json", "providers/a.txt", "template.yaml"}) {
		t.Fatal(got)
	}
	names, _ := os.ReadDir(root)
	var left []string
	for _, e := range names {
		left = append(left, e.Name())
	}
	if !slices.Equal(left, []string{templateCurrent, filepath.Base(gen), templateLock}) {
		t.Fatal(left)
	}
}
