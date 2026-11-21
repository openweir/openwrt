package router

import (
	"context"
	"path/filepath"

	"github.com/openweir/openwrt/internal/cnlist"
)

// chinaList is the core's path to a China list (cnlist.Path): its home links the downloads
// as cnlists and the packaged copies as builtin.
func chinaList(list string) string {
	path := cnlist.Path(list)
	if filepath.Dir(path) == filepath.Clean(cnlist.Dir) {
		return "./cnlists/" + filepath.Base(path)
	}
	return "./builtin/" + filepath.Base(path)
}

// Reapply reloads a running core in place, so a provider that moved to another file follows
// it; a reload that changes nothing is a no-op. It never restarts the takeover, and a core
// that is not running reads the files when it starts.
func (m *Manager) Reapply() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hotLocked(m.state.Intent, m.state.Intent)
}

// RefreshChinaRanges replaces the firewall's China shortcut sets from the address list in
// use; the helper leaves them alone while the shortcut is off.
func (s *System) RefreshChinaRanges(ctx context.Context) error {
	_, err := command(ctx, networkHelper, "refresh-cn")
	return err
}
