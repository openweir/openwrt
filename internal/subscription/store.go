package subscription

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/openweir/openwrt/internal/tlsdiag"
)

var ErrSuperseded = errors.New("subscription intent superseded")
var ErrRevoked = errors.New("subscription access revoked")
var ErrNotReady = errors.New("subscription is not ready")
var ErrSuspended = errors.New("subscription temporarily unavailable")
var ErrLoginRequired = errors.New("subscription login required")

type Store struct{ dir string }

func OpenStore(dir string) *Store { return &Store{dir} }

type Ticket struct {
	Source     string `json:"source"`
	Epoch      uint64 `json:"epoch"`
	Generation uint64 `json:"generation"`
}
type record struct {
	legacy               bool
	NeedsRefresh         bool                `json:"needs_refresh,omitempty"`
	LastTLS              *tlsdiag.Diagnostic `json:"last_tls,omitempty"`
	ClockRetryGeneration uint64              `json:"clock_retry_generation,omitempty"`
	DownloadScope        string              `json:"download_scope,omitempty"`
	LastProviderScope    string              `json:"last_provider_scope,omitempty"`
	DownloadMembers      map[string]string   `json:"download_members,omitempty"`
	Providers            *providerReceipt    `json:"providers,omitempty"`
	Usage                *Usage              `json:"usage,omitempty"`
	LastFailure          string              `json:"last_failure,omitempty"`
	LastProvider         *ProviderDiagnostic `json:"last_provider,omitempty"`
	LastChange           *ChangeCounts       `json:"last_change,omitempty"`
	UpdatedAt            string              `json:"updated_at,omitempty"`
	SchemaVersion        int                 `json:"schema_version"`
	Source               string              `json:"source"`
	Epoch                uint64              `json:"epoch"`
	Generation           uint64              `json:"generation"`
	Revoked              bool                `json:"revoked,omitempty"`
	Suspended            bool                `json:"suspended,omitempty"`
	LoginRequired        bool                `json:"login_required,omitempty"`
	Current              *Profile            `json:"current,omitempty"`
	Config               *Source             `json:"config,omitempty"`
	Previous             *Profile            `json:"previous,omitempty"`
	// Attempts counts refreshes begun since the last success. With the latest start they
	// space out the scheduler's retries; begin writes the record anyway.
	Attempts    int    `json:"attempts,omitempty"`
	AttemptedAt string `json:"attempted_at,omitempty"`
}

const maxRecord = 64 << 20

// errUnchanged lets an update leave the record as it is: records hold whole profiles and
// rule sets, and every write is synced to flash.
var errUnchanged = errors.New("record unchanged")

func failureDigest(r *record) string {
	return digest([]any{r.LastFailure, r.LastTLS, r.ClockRetryGeneration, r.LastProvider, r.LastProviderScope})
}

// A single writer lock covers read, authorization check and publication. All
// authorization generations and the only two usable snapshots share one commit.
func (s *Store) update(id string, fn func(*record) error) error {
	return s.updateContext(context.Background(), id, fn)
}

func (s *Store) updateContext(ctx context.Context, id string, fn func(*record) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !sourceIDValid(id) || s.dir == "" {
		return errors.New("invalid source")
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	lock, e := os.OpenFile(filepath.Join(s.dir, "state.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); e != nil {
		return e
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := ctx.Err(); err != nil {
		return err
	}
	r, e := s.read(id)
	if errors.Is(e, os.ErrNotExist) {
		r = &record{SchemaVersion: SchemaVersion, Source: id, Epoch: 1}
	} else if e != nil {
		return e
	}
	if e = fn(r); errors.Is(e, errUnchanged) {
		return nil
	} else if e != nil {
		return e
	}
	path := s.path(id)
	f, e := os.CreateTemp(s.dir, ".snapshot-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	err := json.NewEncoder(f).Encode(r)
	if err == nil {
		var st os.FileInfo
		st, err = f.Stat()
		if err == nil && st.Size() > maxRecord {
			err = errors.New("snapshot exceeds storage limit")
		}
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *Store) path(id string) string {
	return filepath.Join(s.dir, "subscription-"+digest(id)+".json")
}
func (s *Store) raw(id string) (*record, error) {
	return s.decode(s.path(id), nil)
}

func openRecordFile(path string) (*os.File, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > maxRecord {
		f.Close()
		return nil, errors.New("invalid subscription storage")
	}
	return f, nil
}

func (s *Store) decode(path string, checksum io.Writer) (*record, error) {
	f, e := openRecordFile(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	reader := io.LimitReader(f, maxRecord+1)
	if checksum != nil {
		reader = io.TeeReader(reader, checksum)
	}
	d := json.NewDecoder(reader)
	d.UseNumber()
	var r record
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || (r.SchemaVersion != SchemaVersion && r.SchemaVersion != 1) || !sourceIDValid(r.Source) || s.path(r.Source) != path || r.Epoch == 0 {
		return nil, errors.New("invalid subscription state")
	}
	if r.SchemaVersion == 1 {
		r.legacy = true
		r.NeedsRefresh = r.Config != nil && !r.Revoked
		r.SchemaVersion = SchemaVersion
		r.Current = nil
		r.Previous = nil
		r.Providers = nil
		r.DownloadMembers = nil
		r.LastChange = nil
		r.LastProvider = nil
		r.LastFailure = ""
		r.Epoch++
	}
	for _, p := range []*Profile{r.Current, r.Previous} {
		if p != nil && (p.SchemaVersion != SchemaVersion || p.Source != r.Source) {
			return nil, errors.New("invalid subscription snapshot")
		}
	}
	return &r, nil
}
func (s *Store) Begin(id string) (Ticket, error) {
	t, _, err := s.begin(context.Background(), id, 0, false)
	return t, err
}

func (s *Store) begin(ctx context.Context, id string, retryGeneration uint64, scheduled bool) (Ticket, *record, error) {
	var t Ticket
	var snapshot *record
	e := s.updateContext(ctx, id, func(r *record) error {
		if retryGeneration != 0 && (r.ClockRetryGeneration != retryGeneration || r.Generation != retryGeneration || !r.LastTLS.Recheck(time.Now())) {
			return ErrSuperseded
		}
		if r.Revoked {
			return ErrRevoked
		}
		if r.LoginRequired {
			return ErrLoginRequired
		}
		r.Generation++
		// An administrator's refresh starts the retry sequence over.
		if !scheduled {
			r.Attempts = 0
		}
		r.Attempts++
		r.AttemptedAt = time.Now().UTC().Format(time.RFC3339)
		t = Ticket{id, r.Epoch, r.Generation}
		snapshot = r
		return nil
	})
	return t, snapshot, e
}
func check(r *record, t Ticket) error {
	if r.Revoked || r.Epoch != t.Epoch {
		return ErrRevoked
	}
	if r.Generation != t.Generation {
		return ErrSuperseded
	}
	return nil
}
func (s *Store) Commit(t Ticket, c Candidate) error {
	// Only Refresh knows whether a profile matched this particular ticket.
	c.unchanged = false
	return s.commit(context.Background(), t, c, nil, "")
}
func (s *Store) commit(ctx context.Context, t Ticket, c Candidate, recheck func() error, replacement string) error {
	if c.Decision != "ready" || c.Profile.Source != t.Source || c.Profile.SchemaVersion != SchemaVersion {
		return errors.New("invalid candidate")
	}
	return s.updateContext(ctx, t.Source, func(r *record) error {
		if e := check(r, t); e != nil {
			return e
		}
		if recheck != nil {
			if e := recheck(); e != nil {
				return e
			}
		}
		if !c.unchanged {
			r.Previous = r.Current
		}
		r.NeedsRefresh = false
		r.Current = &c.Profile
		if r.Config != nil && r.Config.AutoName && c.Profile.Title != "" {
			r.Config.Name, r.Config.AutoName = c.Profile.Title, false
		}
		r.Providers = c.receipt
		r.Usage = c.Usage
		if replacement != "" && replacement != r.Config.URL {
			r.Config.URL = replacement
			r.Epoch++
			r.Previous = nil
		}
		r.LastFailure = ""
		r.LastTLS = nil
		r.ClockRetryGeneration = 0
		r.LastProvider = nil
		r.LastChange = &ChangeCounts{len(c.Changes.Added), len(c.Changes.Removed), len(c.Changes.Groups)}
		r.Suspended = false
		r.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		r.Attempts, r.AttemptedAt = 0, ""
		r.Generation++
		return nil
	})
}
func (s *Store) Load(id string) (Profile, error) {
	return currentProfile(s.read(id))
}

func currentProfile(r *record, e error) (Profile, error) {
	if errors.Is(e, os.ErrNotExist) {
		return Profile{}, ErrNotReady
	}
	if e != nil {
		return Profile{}, e
	}
	if r.Revoked {
		return Profile{}, ErrRevoked
	}
	if r.Suspended {
		return Profile{}, ErrSuspended
	}
	if r.Current == nil {
		return Profile{}, ErrNotReady
	}
	return *r.Current, nil
}
func (s *Store) Rollback(id string) error { return s.RollbackChecked(context.Background(), id, nil) }
func (s *Store) RollbackChecked(ctx context.Context, id string, v Validator) error {
	var t Ticket
	var recheck func() error
	if v != nil {
		r, e := s.read(id)
		if e != nil {
			return e
		}
		if r.Revoked {
			return ErrRevoked
		}
		if r.Suspended {
			return ErrSuspended
		}
		if r.Previous == nil {
			return ErrNotReady
		}
		t = Ticket{id, r.Epoch, r.Generation}
		recheck, e = v(ctx, *r.Previous)
		if e != nil {
			return e
		}
		if recheck == nil {
			return errors.New("preflight_revision_missing")
		}
	}

	return s.update(id, func(r *record) error {
		if r.Revoked {
			return ErrRevoked
		}
		if r.Suspended {
			return ErrSuspended
		}
		if r.Previous == nil {
			return ErrNotReady
		}
		if recheck != nil {
			if err := check(r, t); err != nil {
				return err
			}
			if err := recheck(); err != nil {
				return err
			}
		}
		r.Generation++
		r.Providers = nil
		r.Current, r.Previous = r.Previous, r.Current
		return nil
	})
}
func (s *Store) Revoke(id string) error {
	return s.update(id, func(r *record) error {
		r.Epoch++
		r.Generation++
		r.Revoked = true
		r.Config = nil
		r.DownloadScope = ""
		r.LastProviderScope = ""
		r.DownloadMembers = nil
		r.Usage = nil
		r.LastFailure = ""
		r.LastTLS = nil
		r.ClockRetryGeneration = 0
		r.LastProvider = nil
		r.LastChange = nil
		r.LoginRequired = false
		r.Current = nil
		r.Previous = nil
		return nil
	})
}
func (s *Store) RevokeIfCurrent(t Ticket) error {
	return s.update(t.Source, func(r *record) error {
		if e := check(r, t); e != nil {
			return e
		}
		r.Epoch++
		r.Generation++
		r.Revoked = true
		r.Config = nil
		r.DownloadScope = ""
		r.LastProviderScope = ""
		r.DownloadMembers = nil
		r.Usage = nil
		r.LastFailure = ""
		r.LastTLS = nil
		r.ClockRetryGeneration = 0
		r.LastProvider = nil
		r.LastChange = nil
		r.Current = nil
		r.Previous = nil
		return nil
	})
}
func (s *Store) RequireLogin(t Ticket) error {
	return s.update(t.Source, func(r *record) error {
		if e := check(r, t); e != nil {
			return e
		}
		r.Generation++
		r.LoginRequired = true
		if r.Config != nil {
			r.Config.Token = ""
		}
		return nil
	})
}

func (s *Store) Current(t Ticket) bool {
	r, e := s.read(t.Source)
	return e == nil && check(r, t) == nil
}

// Configure explicitly creates a source or updates filters and request preferences.
// A verified platform login is the only path that can renew a revoked authority.
func (s *Store) Configure(src Source) error {
	// An unnamed link is called after its host until the subscription names itself.
	src.AutoName = false
	if src.Kind == "external" && strings.TrimSpace(src.Name) == "" {
		if u, err := url.Parse(src.URL); err == nil && u.Hostname() != "" {
			src.Name, src.AutoName = u.Hostname(), true
		}
	}
	return s.configure(src, false)
}
func (s *Store) configure(src Source, authenticated bool) error {
	if e := src.validate(); e != nil {
		return e
	}
	return s.update(src.ID, func(r *record) error {
		if r.Config != nil {
			old := r.Config
			if old.Kind == "external" && old.URL != src.URL {
				r.Epoch++
				r.DownloadScope = ""
				r.LastProviderScope = ""
				r.DownloadMembers = nil
				r.LastProvider = nil
				r.Current = nil
				r.Previous = nil
			}
			if old.Kind != src.Kind || old.Origin != src.Origin || old.UserID != src.UserID || old.PlanID != src.PlanID {
				return errors.New("source_identity_mismatch")
			}
		}
		if src.Kind == "platform" && !authenticated {
			return errors.New("verified_login_required")
		}
		if r.Revoked {
			if !authenticated && src.Kind == "platform" {
				return ErrRevoked
			}
			r.Epoch++
			r.Revoked = false
			r.LoginRequired = false
		}
		if authenticated {
			r.LoginRequired = false
			if src.Plan != nil && (!src.Plan.Usable || src.Plan.Status == "expired") {
				r.Suspended = true
			}
		}
		r.Generation++
		r.Config = &src
		// A changed source deserves a prompt retry.
		r.Attempts, r.AttemptedAt = 0, ""
		return nil
	})
}
func (s *Store) SaveAccount(a Account, loginIntent string) ([]string, error) {
	var changed []string
	e := s.saveAccount(a, loginIntent, &changed)
	return changed, e
}
func (s *Store) saveAccount(a Account, loginIntent string, changed *[]string) error {
	lock, e := s.lockAccounts()
	if e != nil {
		return e
	}
	defer unlock(lock)
	if loginIntent == "" {
		return ErrSuperseded
	}
	raw, e := os.ReadFile(s.loginPath(a.origin))
	if e != nil || string(raw) != loginIntent {
		return ErrSuperseded
	}
	if e = os.Remove(s.loginPath(a.origin)); e != nil {
		return e
	}
	account := Source{Origin: a.origin, UserID: a.userID}
	if _, e = os.Stat(s.accountPath(&account)); e == nil {
		if _, e = s.purgeAccount(&account); e != nil {
			return e
		}
		if e = os.Remove(s.accountPath(&account)); e != nil {
			return e
		}
		if e = s.syncDir(); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}

	known := map[string]bool{}
	for _, p := range a.Plans {
		known[a.Source(p).ID] = true
	}
	prior, e := s.List()
	if e != nil {
		return e
	}
	for _, st := range prior {
		if known[st.Source] {
			continue
		}
		r, e := s.read(st.Source)
		if e != nil {
			return e
		}
		if r.Config != nil && r.Config.Kind == "platform" && r.Config.Origin == a.origin && r.Config.UserID == a.userID {
			if e = s.Revoke(st.Source); e != nil {
				return e
			}
			*changed = append(*changed, st.Source)
		}
	}
	for _, p := range a.Plans {
		src := a.Source(p)
		*changed = append(*changed, src.ID)
		current, e := s.read(src.ID)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if p.Status == "disabled" {
			if current != nil && !current.Revoked {
				if e = s.Revoke(src.ID); e != nil {
					return e
				}
			}
			continue
		}
		if current != nil && current.Config != nil {
			old := current.Config
			src.Filters = old.Filters
			src.AllowLocalFallback = old.AllowLocalFallback
			src.Rules = old.Rules
		}
		if e = s.configure(src, true); e != nil {
			return e
		}
	}
	return nil
}

// UpdatePreferences cannot replace the authority, platform origin or bearer token.
type Preferences struct {
	MainlandFallback   *bool             `json:"mainland_fallback,omitempty"`
	DownloadChoice     *DownloadChoice   `json:"download_choice,omitempty"`
	KeepUserAgent      bool              `json:"keep_user_agent,omitempty"`
	Name               string            `json:"name,omitempty"`
	UserAgent          string            `json:"user_agent"`
	Filters            map[string]string `json:"filters"`
	AllowLocalFallback bool              `json:"allow_local_fallback"`
	// Rules is the routing choice (Source.Rules); an older client leaves it out.
	Rules *string `json:"rules,omitempty"`
}

func (s *Store) Preferences(id string, p Preferences) error {
	return s.update(id, func(r *record) error {
		if r.Revoked {
			return ErrRevoked
		}
		if r.Config == nil {
			return ErrNotReady
		}
		// Older clients may submit the retired per-source opt-in. Keep their
		// other preferences intact and let the next import resolve it automatically.
		if p.MainlandFallback != nil {
			return nil
		}
		r.Attempts, r.AttemptedAt = 0, ""
		if p.DownloadChoice != nil {
			return saveDownloadChoice(r, *p.DownloadChoice)
		}
		v := r.Config
		if v.Kind == "platform" {
			v.UserAgent = platformUserAgent
		} else if !p.KeepUserAgent {
			v.UserAgent = p.UserAgent
		}
		if p.Name != "" && v.Kind != "platform" && p.Name != v.Name {
			v.Name, v.AutoName = p.Name, false
		}
		v.AllowLocalFallback = p.AllowLocalFallback
		if p.Rules != nil {
			v.Rules = *p.Rules
		}
		if v.Kind == "platform" {
			if p.Filters != nil {
				v.Filters = p.Filters
			}
		}
		if e := v.validate(); e != nil {
			return e
		}
		r.Generation++
		return nil
	})
}

type ChangeCounts struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	Groups  int `json:"affected_groups"`
}
type Status struct {
	NeedsRefresh     bool                `json:"needs_refresh,omitempty"`
	LastTLS          *tlsdiag.Diagnostic `json:"last_tls,omitempty"`
	RetryAfterClock  bool                `json:"-"`
	Attempts         int                 `json:"-"`
	AttemptedAt      string              `json:"-"`
	DownloadOverride bool                `json:"download_override,omitempty"`
	Usage            *Usage              `json:"usage,omitempty"`
	LastFailure      string              `json:"last_failure,omitempty"`
	LastProvider     *ProviderDiagnostic `json:"last_provider,omitempty"`
	LastChange       *ChangeCounts       `json:"last_change,omitempty"`
	Plan             *Plan               `json:"plan,omitempty"`
	Agent            string              `json:"agent,omitempty"`
	CustomAgent      bool                `json:"custom_agent,omitempty"`
	LocalFallback    bool                `json:"local_fallback,omitempty"`
	Rules            string              `json:"rules,omitempty"`
	Template         *TemplateUse        `json:"template,omitempty"`
	HasHistory       bool                `json:"has_history,omitempty"`
	UpdatedAt        string              `json:"updated_at,omitempty"`
	Source           string              `json:"source"`
	Name             string              `json:"name,omitempty"`
	Kind             string              `json:"kind,omitempty"`
	Epoch            uint64              `json:"epoch"`
	Generation       uint64              `json:"generation"`
	Revoked          bool                `json:"revoked"`
	Suspended        bool                `json:"suspended"`
	LoginRequired    bool                `json:"login_required"`
	Ready            bool                `json:"ready"`
	Format           string              `json:"format,omitempty"`
	Local            bool                `json:"local"`
	NodeCount        int                 `json:"node_count"`
	GroupCount       int                 `json:"group_count"`
	RuleCount        int                 `json:"rule_count"`
	Notices          []Notice            `json:"notices,omitempty"`
}

func statusOf(r *record) Status {
	st := Status{NeedsRefresh: r.NeedsRefresh, LastTLS: r.LastTLS, RetryAfterClock: r.ClockRetryGeneration != 0 && r.ClockRetryGeneration == r.Generation, Attempts: r.Attempts, AttemptedAt: r.AttemptedAt, LastFailure: r.LastFailure, LastProvider: r.LastProvider, LastChange: r.LastChange, UpdatedAt: r.UpdatedAt, Source: r.Source, Epoch: r.Epoch, Generation: r.Generation, Suspended: r.Suspended, Revoked: r.Revoked, LoginRequired: r.LoginRequired, Ready: r.Current != nil && !r.Revoked && !r.Suspended}
	if r.Config != nil {
		st.DownloadOverride = len(r.DownloadMembers) > 0
		st.Name = publicLabel(r.Config.Name, "Subscription")
		st.Kind = r.Config.Kind
		if !r.Revoked {
			st.Usage = r.Usage
		}
		st.HasHistory = r.Previous != nil && !r.Suspended && !r.Revoked
		st.LocalFallback = r.Config.AllowLocalFallback
		st.Rules = r.Config.Rules
		if r.Config.Kind == "platform" {
			st.Plan = r.Config.Plan
		}
		if r.Config.Kind != "file" {
			agent := r.Config.subscriptionAgent()
			for _, known := range UserAgents {
				if known == agent {
					st.Agent = known
					break
				}
			}
			st.CustomAgent = st.Agent == ""
		}
	}
	if st.Ready {
		p := r.Current
		st.Format = p.Format
		st.Local = p.Local
		st.Template = p.Template
		st.NodeCount = len(p.Nodes)
		st.GroupCount = len(p.Groups)
		st.RuleCount = len(p.Rules)
		st.Notices = p.Notices
	}
	return st
}

// SourceURL returns an external subscription's link for the administrator's edit form. It is
// kept out of Status so that summaries never carry the credential-bearing URL.
func (s *Store) SourceURL(id string) (string, error) {
	r, e := s.read(id)
	if e != nil {
		return "", e
	}
	if r.Config == nil || r.Config.Kind != "external" || r.Revoked {
		return "", errors.New("not_external")
	}
	return r.Config.URL, nil
}
func (s *Store) Status(id string) (Status, error) {
	r, e := s.read(id)
	if e != nil {
		return Status{}, e
	}
	return statusOf(r), nil
}
func (s *Store) List() ([]Status, error) {
	entries, e := os.ReadDir(s.dir)
	out := []Status{}
	if errors.Is(e, os.ErrNotExist) {
		return out, nil
	}
	if e != nil {
		return nil, e
	}
	for _, file := range entries {
		if !strings.HasPrefix(file.Name(), "subscription-") || filepath.Ext(file.Name()) != ".json" || !file.Type().IsRegular() {
			continue
		}
		r, e := s.readPath(filepath.Join(s.dir, file.Name()), nil)
		if e != nil {
			return nil, e
		}
		if r.legacy {
			// Re-read under the writer lock. A concurrent refresh may already have migrated it.
			if e := s.update(r.Source, func(*record) error { return nil }); e != nil {
				return nil, e
			}
			r, e = s.read(r.Source)
			if e != nil {
				return nil, e
			}
		}
		out = append(out, statusOf(r))
	}
	return out, nil
}

type PublicGroup struct {
	Hidden  bool     `json:"hidden,omitempty"`
	Default string   `json:"default,omitempty"`
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Members []string `json:"members"`
}
type PublicProfile struct {
	Source  string        `json:"source"`
	Format  string        `json:"format"`
	Local   bool          `json:"local"`
	Nodes   []Member      `json:"nodes"`
	Groups  []PublicGroup `json:"groups"`
	Rules   []Rule        `json:"rules"`
	Final   string        `json:"final,omitempty"`
	Notices []Notice      `json:"notices,omitempty"`
}

func (p Profile) Summary() PublicProfile {
	s := PublicProfile{Source: p.Source, Format: p.Format, Local: p.Local, Final: p.Final, Rules: p.Rules, Notices: p.Notices, Nodes: []Member{}, Groups: []PublicGroup{}}
	for _, n := range p.Nodes {
		s.Nodes = append(s.Nodes, n.Summary())
	}
	for _, g := range p.Groups {
		member, _ := g.Options["default"].(string)
		if !slices.Contains(g.Members, member) {
			member = ""
		}
		s.Groups = append(s.Groups, PublicGroup{Hidden: g.Hidden, ID: g.ID, Name: publicLabel(g.Name, "Policy group"), Kind: g.Kind, Members: g.Members, Default: member})
	}
	return s
}

// Logout fences and invalidates every plan discovered for this verified account.
// Recovery checks the durable marker before exposing any account snapshot.
func (s *Store) Logout(id string) ([]string, error) {
	return s.withdraw(id, nil)
}
func (s *Store) withdraw(id string, ticket *Ticket) ([]string, error) {
	lock, e := s.lockAccounts()
	if e != nil {
		return nil, e
	}
	defer unlock(lock)
	r, e := s.read(id)
	if e != nil {
		return nil, e
	}
	if ticket != nil {
		if e = check(r, *ticket); e != nil {
			return nil, e
		}
	}
	if r.Config == nil || r.Config.Kind != "platform" {
		return []string{id}, s.Revoke(id)
	}
	account := r.Config
	if e = os.Remove(s.loginPath(account.Origin)); e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if e = s.markAccount(account); e != nil {
		return nil, e
	}
	return s.purgeAccount(account)
}
func (s *Store) lockAccounts() (*os.File, error) {
	if e := os.MkdirAll(s.dir, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(s.dir, "account.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func unlock(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }
func (s *Store) accountPath(c *Source) string {
	return filepath.Join(s.dir, "withdrawn-"+digest([]string{c.Origin, c.UserID}))
}
func (s *Store) withdrawalPath(r *record) string {
	if r.Config == nil || r.Config.Kind != "platform" {
		return ""
	}
	return s.accountPath(r.Config)
}
func (s *Store) markAccount(c *Source) error {
	f, e := os.OpenFile(s.accountPath(c), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	e = f.Sync()
	f.Close()
	if e != nil {
		return e
	}
	return s.syncDir()
}
func (s *Store) syncDir() error {
	d, e := os.Open(s.dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (s *Store) purgeAccount(c *Source) ([]string, error) {
	list, e := s.List()
	if e != nil {
		return nil, e
	}
	var changed []string
	for _, v := range list {
		r, e := s.raw(v.Source)
		if e != nil {
			return changed, e
		}
		if r.Config == nil || r.Config.Kind != "platform" || r.Config.Origin != c.Origin || r.Config.UserID != c.UserID {
			continue
		}
		if e = s.Revoke(v.Source); e != nil {
			return changed, e
		}
		changed = append(changed, v.Source)
	}
	return changed, nil
}
func (s *Store) read(id string) (*record, error) {
	return s.readWithChecksum(id, nil)
}

func (s *Store) readWithChecksum(id string, checksum io.Writer) (*record, error) {
	return s.readPath(s.path(id), checksum)
}

func (s *Store) readPath(path string, checksum io.Writer) (*record, error) {
	r, e := s.decode(path, checksum)
	if e != nil {
		return nil, e
	}
	if marker := s.withdrawalPath(r); marker != "" {
		if _, e = os.Stat(marker); e == nil {
			r.Revoked = true
			r.Current = nil
			r.Previous = nil
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	return r, nil
}

func (s *Store) Suspend(t Ticket) error {
	return s.update(t.Source, func(r *record) error {
		if e := check(r, t); e != nil {
			return e
		}
		r.Generation++
		r.Suspended = true
		return nil
	})
}

func (s *Store) loginPath(origin string) string {
	return filepath.Join(s.dir, "login-"+digest(strings.TrimRight(origin, "/")))
}
func (s *Store) BeginLogin(origin string) (string, error) {
	if !validOrigin(origin) {
		return "", errors.New("invalid_origin")
	}
	lock, e := s.lockAccounts()
	if e != nil {
		return "", e
	}
	defer unlock(lock)
	var nonce [24]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return "", e
	}
	id := hex.EncodeToString(nonce[:])
	// A torn or partial intent cannot authorize the subsequent commit.
	f, e := os.OpenFile(s.loginPath(origin), os.O_CREATE|os.O_TRUNC|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return "", e
	}
	if _, e = f.WriteString(id); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return "", e
	}
	if ce != nil {
		return "", ce
	}
	return id, s.syncDir()
}
