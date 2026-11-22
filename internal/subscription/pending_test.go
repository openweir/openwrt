package subscription

import (
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
)

const (
	rejectingFeed = "proxies: [{name: Edge, type: http, server: edge.example, port: 8080}]\nrules: ['DOMAIN,ads.example,REJECT', 'MATCH,DIRECT']"
	// The same subscription without its REJECT rule: applying it needs the administrator.
	permissiveFeed = "proxies: [{name: Edge, type: http, server: edge.example, port: 8080}]\nrules: ['DOMAIN,media.example,DIRECT', 'MATCH,DIRECT']"
)

// A scheduled refresh whose update the router cannot apply by itself keeps it on the source
// instead of passing for done, and keeps counting attempts so that the scheduler's back-off
// goes on. A commit or the administrator's own refresh settles it.
func TestScheduledRefreshKeepsUpdateItCannotApply(t *testing.T) {
	store := OpenStore(t.TempDir())
	src := Source{ID: "sub", Name: "sub", Kind: "external", URL: "https://example.com/feed"}
	if err := store.Configure(src); err != nil {
		t.Fatal(err)
	}
	body, reachable := rejectingFeed, true
	var afterBegin os.FileInfo
	f := Fetcher{Client: &http.Client{Transport: setFixtureTransport(func(*http.Request) (*http.Response, error) {
		afterBegin, _ = os.Stat(store.path(src.ID))
		if !reachable {
			return nil, errReset
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	refresh := func(policy Policy, decision string) (Candidate, Status) {
		t.Helper()
		c, err := f.Refresh(t.Context(), store, src.ID, nil, policy)
		if (err == nil) != reachable || c.Decision != decision {
			t.Fatal(err, c.Decision, c.Notices)
		}
		st, err := store.Status(src.ID)
		if err != nil {
			t.Fatal(err)
		}
		return c, st
	}
	refresh(Policy{}, "ready")
	reachable = false
	if _, st := refresh(Policy{Scheduled: true}, ""); st.LastFailure != "subscription_request_failed" || st.Attempts != 1 {
		t.Fatal(st.LastFailure, st.Attempts)
	}

	reachable, body = true, permissiveFeed
	c, st := refresh(Policy{Scheduled: true}, "confirmation_required")
	if p := st.PendingUpdate; p == nil || p.Code != PendingConfirmation || !slices.Equal(p.Notices, []string{"rejection_removed"}) {
		t.Fatal("scheduled refresh left no pending update", p)
	}
	// The download worked: the earlier failure is over, and the back-off is not.
	if st.LastFailure != "" || st.Attempts != 2 || st.AttemptedAt == "" || !st.Ready {
		t.Fatal(st.LastFailure, st.Attempts, st.Ready)
	}
	if current, _ := store.Load(src.ID); len(current.Rules) != 1 || current.Rules[0].Target != Reject {
		t.Fatal("pending update replaced the current profile")
	}
	_, again := refresh(Policy{Scheduled: true}, "confirmation_required")
	if now, _ := os.Stat(store.path(src.ID)); again.Attempts != 3 || !os.SameFile(afterBegin, now) || again.PendingUpdate.Code != PendingConfirmation {
		t.Fatal("the same pending update rewrote the record", again.Attempts)
	}

	// The administrator's refresh showed the update to them. Dismissed, it is no longer pending.
	if _, st := refresh(Policy{}, "confirmation_required"); st.PendingUpdate != nil || st.Attempts != 1 {
		t.Fatal("reviewed update still pending", st.PendingUpdate)
	}
	refresh(Policy{Scheduled: true}, "confirmation_required")
	// Applied, it is part of the current profile.
	if _, st := refresh(Policy{Confirm: c.ConfirmationID}, "ready"); st.PendingUpdate != nil || st.Attempts != 0 {
		t.Fatal("applied update still pending", st.PendingUpdate)
	}

	// An update that would drop a member in use is blocked; the next commit clears it.
	if _, st := refresh(Policy{Scheduled: true, ActiveIDs: []string{"group:gone"}}, "blocked"); st.PendingUpdate == nil ||
		st.PendingUpdate.Code != PendingBlocked || !slices.Contains(st.PendingUpdate.Notices, "active_target_missing") || st.LastFailure != "" {
		t.Fatal("blocked update not pending", st.PendingUpdate, st.LastFailure)
	}
	if _, st := refresh(Policy{Scheduled: true}, "ready"); st.PendingUpdate != nil || st.Attempts != 0 {
		t.Fatal("committed refresh left the pending update", st.PendingUpdate)
	}
}

// Only notice codes reach the record, dangerous ones first and each once.
func TestPendingUpdateKeepsNoticeCodes(t *testing.T) {
	if (Candidate{Decision: "ready"}).Pending() != nil {
		t.Fatal("ready candidate pending")
	}
	c := Candidate{Decision: "confirmation_required", Notices: []Notice{
		{Code: "subconv_unsupported_rule", At: "https://feed.example/?token=secret"},
		{Code: "rejection_removed", Dangerous: true},
		{Code: "subconv_unsupported_rule", At: "rule 2"},
		{Code: "Not A Code"},
	}}
	if p := c.Pending(); p.Code != PendingConfirmation || !slices.Equal(p.Notices, []string{"rejection_removed", "subconv_unsupported_rule"}) {
		t.Fatal(p)
	}
	for range 20 {
		c.Notices = append(c.Notices, Notice{Code: "code_" + string(rune('a'+len(c.Notices)))})
	}
	if p := c.Pending(); len(p.Notices) != maxPendingNotices {
		t.Fatal(len(p.Notices))
	}
}
