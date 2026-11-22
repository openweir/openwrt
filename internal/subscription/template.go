package subscription

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openweir/subconv/rules"
)

// A source chooses its routing (Source.Rules): its own rules, which subconv replaces with its
// routing template when they are missing or too lossy, or always the template.
const (
	RoutingOwn      = ""
	RoutingTemplate = "template"
)

// Where the router gets subconv's rules branch, and keeps what it last got of it. Without
// hosts every subscription keeps its own routing; tests point both elsewhere.
var (
	TemplateHosts = rules.DefaultHosts()
	TemplateDir   = "/etc/openweir/template"
)

// TemplateUse tells that a profile routes by the built-in template, and why.
type TemplateUse struct {
	// Version is the rules branch's manifest version: the Unix time it was built.
	Version int64  `json:"version"`
	Reason  string `json:"reason"`
	// Cached: no host answered, so the router's copy was used.
	Cached bool `json:"cached,omitempty"`
	// Dropped of Total of the subscription's rules did not convert, when that was the reason.
	Dropped int `json:"dropped,omitempty"`
	Total   int `json:"total,omitempty"`
}

// templateCache is the rules client's cache on flash: the last good manifest, template and
// rule sets, for when no host answers. Keys are branch paths. A value is written, in one
// rename, only when it changed.
type templateCache struct{ dir string }

func (c templateCache) path(key string) (string, bool) {
	if !rules.ValidPath(key) {
		return "", false
	}
	return filepath.Join(c.dir, filepath.FromSlash(key)), true
}

func (c templateCache) Get(key string) ([]byte, bool) {
	path, ok := c.path(key)
	if !ok {
		return nil, false
	}
	b, err := os.ReadFile(path)
	return b, err == nil
}

func (c templateCache) Put(key string, value []byte) {
	path, ok := c.path(key)
	if !ok || len(value) > MaxBody {
		return
	}
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, value) {
		return
	}
	// A cache that cannot store a value drops it; the client checks what it reads.
	_ = writeFileAtomic(path, value)
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".new-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return err
	}
	return syncDirectory(dir)
}

// branch is the rules client of one refresh. Its requests go as provider downloads do
// (Fetcher.request: public addresses only, the redirect policy, the router's second way out),
// and its answers are kept for the refresh, so the rule sets are fetched against the manifest
// the template came with.
func (f Fetcher) branch() (*rules.Client, func()) {
	if len(TemplateHosts) == 0 {
		return nil, func() {}
	}
	e, done := f.embeddedFetcher()
	cache := templateCache{dir: TemplateDir}
	return &rules.Client{
		HTTP: &http.Client{
			Transport:     &branchTransport{f: e, seen: map[string]branchAnswer{}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		// The client keeps its own rollback floor in the cache: a version only one mirror served
		// must not become a floor that agreeing hosts cannot lower.
		Hosts: TemplateHosts,
		Cache: cache,
	}, done
}

type branchAnswer struct {
	r   response
	err error
}

type branchTransport struct {
	f    Fetcher
	mu   sync.Mutex
	seen map[string]branchAnswer
}

func (t *branchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.String()
	t.mu.Lock()
	a, ok := t.seen[key]
	t.mu.Unlock()
	if !ok {
		a.r, a.err = t.f.request(req.Context(), http.MethodGet, key, nil, "", "OpenWeir", false, MaxBody)
		// A request the client gave up on says nothing about the host.
		if req.Context().Err() == nil {
			t.mu.Lock()
			t.seen[key] = a
			t.mu.Unlock()
		}
	}
	if a.err != nil {
		return nil, a.err
	}
	return &http.Response{
		StatusCode:    a.r.status,
		Status:        fmt.Sprintf("%d %s", a.r.status, http.StatusText(a.r.status)),
		Header:        a.r.header,
		Body:          io.NopCloser(bytes.NewReader(a.r.body)),
		ContentLength: int64(len(a.r.body)),
		Request:       req,
	}, nil
}

// embeddedFetcher is f for the URLs a document or the rules branch chose: public addresses
// only, over the router's second way out too. done releases its connections.
func (f Fetcher) embeddedFetcher() (Fetcher, func()) {
	e := Fetcher{Fallback: f.Fallback, egress: f.egress, embedded: true, Client: f.embeddedClient}
	if e.Client != nil {
		return e, func() {}
	}
	tr := publicProviderTransport()
	e.Client = &http.Client{Transport: tr, Timeout: 15 * time.Second}
	return e, tr.CloseIdleConnections
}

// Template rule sets download six at a time, and all of them within a share of the refresh's
// time: a cold cache holds some seventy.
const (
	templateParallel = 6
	templateTimeout  = 40 * time.Second
)

var errTemplateSet = errors.New("template_rule_set_unavailable")

// fetchTemplateSets gets the rule set of each of the template's providers (by provider name):
// from the hosts serving the template's version, checked against its manifest, or else from the
// router's cache of that version. It fails when any is unavailable.
func fetchTemplateSets(ctx context.Context, client *rules.Client, version int64, providers map[string]any) (map[string][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, templateTimeout)
	defer cancel()
	paths := map[string]string{}
	for name, def := range providers {
		path, ok := branchPath(client.Hosts, field(object(def), "url"))
		if !ok {
			return nil, errTemplateSet
		}
		paths[name] = path
	}
	get := func(path string) ([]byte, error) { return nil, errTemplateSet }
	if snap, err := client.Latest(ctx); err == nil && snap.Manifest.Version == version {
		get = func(path string) ([]byte, error) { return snap.Fetch(ctx, path) }
	} else if b, ok := client.Cache.Get(rules.ManifestPath); ok {
		if m, err := rules.ParseManifest(b); err == nil && m.Version == version {
			get = func(path string) ([]byte, error) {
				file, listed := m.File(path)
				if data, ok := client.Cache.Get(path); listed && ok && file.Matches(data) {
					return data, nil
				}
				return nil, errTemplateSet
			}
		}
	}
	sets := make(map[string][]byte, len(paths))
	var mu sync.Mutex
	var failure error
	slots := make(chan struct{}, templateParallel)
	var wg sync.WaitGroup
	for name, path := range paths {
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			if ctx.Err() != nil {
				return
			}
			data, err := get(path)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && failure == nil {
				failure = err
				cancel()
			}
			sets[name] = data
		})
	}
	wg.Wait()
	if failure == nil {
		failure = ctx.Err()
	}
	if failure != nil {
		return nil, errTemplateSet
	}
	return sets, nil
}

// branchPath is a template provider's place on the branch: its URL without the host the
// template was filled in with.
func branchPath(hosts []rules.Host, url string) (string, bool) {
	for _, h := range hosts {
		if p, ok := strings.CutPrefix(url, h.Base+"/"); ok && rules.ValidPath(p) {
			return p, true
		}
	}
	return "", false
}
