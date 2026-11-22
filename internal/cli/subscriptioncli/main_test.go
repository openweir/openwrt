package subscriptioncli

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	sub "github.com/openweir/openwrt/internal/subscription"
)

// The tests stay off the network: no subscription fetches subconv's routing template.
func TestMain(m *testing.M) {
	sub.TemplateHosts = nil
	os.Exit(m.Run())
}

func TestPublicMethodsDoNotExposeRawSubscription(t *testing.T) {
	st := sub.OpenStore(t.TempDir())
	ctx := context.Background()
	for _, v := range []struct {
		method string
		in     input
	}{{"configure", input{Config: &sub.Source{ID: "file", Kind: "file", Name: "File"}}}, {"refresh", input{Source: "file", Content: "http://user:do-not-leak@private.example:8080#Edge"}}, {"list", input{}}, {"profile", input{Source: "file"}}, {"nodes", input{Source: "file"}}, {"groups", input{Source: "file"}}, {"rules", input{Source: "file"}}, {"status", input{Source: "file"}}} {
		out, _, e := run(ctx, st, v.method, v.in, sub.Fetcher{})
		if e != nil {
			t.Fatal(v.method, e)
		}
		raw, _ := json.Marshal(out)
		for _, s := range []string{"do-not-leak", "private.example", "server_port", "outbound"} {
			if strings.Contains(string(raw), s) {
				t.Fatal(v.method, "exposed", s)
			}
		}
	}
	if _, _, e := run(ctx, st, "profile", input{Source: "file", Limit: 999}, sub.Fetcher{}); e == nil {
		t.Fatal("unbounded read")
	}
}

func TestProviderNamesCannotReExposeCredentials(t *testing.T) {
	p, e := sub.Parse("source", []byte(`{"outbounds":[{"tag":"https://feed.example/sub?token=private-value","type":"http","server":"example.org","server_port":80},{"tag":"Bearer private-value","type":"selector","outbounds":["https://feed.example/sub?token=private-value"]}],"route":{"final":"Bearer private-value"}}`))
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(p.Summary())
	if strings.Contains(string(encoded), "private-value") || p.Summary().Groups[0].Members[0] != p.Nodes[0].ID {
		t.Fatal("public label leaked a credential or lost the assigned member")
	}
}

func TestOnlyChangedProfilesNotifyRouter(t *testing.T) {
	st := sub.OpenStore(t.TempDir())
	ctx := t.Context()
	if err := st.Configure(sub.Source{ID: "file", Kind: "file", Name: "File"}); err != nil {
		t.Fatal(err)
	}
	checks := 0
	f := sub.Fetcher{BeforeCommit: func(context.Context, sub.Profile) (func() error, error) {
		checks++
		return func() error { return nil }, nil
	}}
	first := "http://old.example:81#Edge"
	next := "http://new.example:81#Edge"
	for i, text := range []string{first, next, next} {
		_, changes, err := run(ctx, st, "refresh", input{Source: "file", Content: text}, f)
		wantNotify := i < 2
		if err != nil || (len(changes) == 1) != wantNotify || len(changes) > 1 {
			t.Fatalf("refresh %d: %v, notified %v", i, err, changes)
		}
	}
	if checks != 2 {
		t.Fatalf("expected two candidate checks, got %d", checks)
	}
	if err := st.Rollback("file"); err != nil {
		t.Fatal(err)
	}
	actual, err := st.Load("file")
	original, _ := sub.Parse("file", []byte(first))
	if err != nil || actual.Nodes[0].ID != original.Nodes[0].ID {
		t.Fatal("identical refresh displaced rollback snapshot", err)
	}
}

// The daemon logs a refresh whose update was not applied by the code it returns.
func TestRefreshReturnsPendingUpdate(t *testing.T) {
	st := sub.OpenStore(t.TempDir())
	if err := st.Configure(sub.Source{ID: "file", Kind: "file", Name: "File"}); err != nil {
		t.Fatal(err)
	}
	const feed = "proxies: [{name: Edge, type: http, server: edge.example, port: 8080}]\nrules: ['DOMAIN,ads.example,REJECT', 'MATCH,DIRECT']"
	for i, text := range []string{feed, strings.Replace(feed, "REJECT", "DIRECT", 1)} {
		out, _, err := run(t.Context(), st, "refresh", input{Source: "file", Content: text, Scheduled: true}, sub.Fetcher{})
		raw, _ := json.Marshal(out)
		if pending := strings.Contains(string(raw), `"pending_update":{"code":"confirmation_required","notices":["rejection_removed"]}`); err != nil || pending != (i == 1) {
			t.Fatal(err, string(raw))
		}
	}
}
