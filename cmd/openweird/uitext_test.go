package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openweir/openwrt/internal/subscription"
	"github.com/openweir/openwrt/internal/tlsdiag"
	"github.com/openweir/subconv"
)

// The LuCI pages read the router's codes in Chinese: dom.js through diagnosticMessage (the log,
// task errors, the service's problem, the kernel page), sources.js for import notices and failed
// subscription operations, and records.js for the log's sources. A code without a text there
// reaches the page raw, and a text whose code nothing emits any more is dead weight.
//
// The codes are read from the Go source where they are emitted: the logger, the service phase,
// the routing audit, DNS issues, subscription notices, the subscription helper's failure codes,
// the kernel's rejection reasons, what the kernel's jobs fail with, the kernel helper commands
// the router reports failed and the task names runJob logs. A computed value is followed
// through constants, assignments, the cases of a switch on it, the arguments callers pass and
// the literals a function returns. What cannot be followed is listed in computed, with the codes
// it can hold or samples of its family.

const luci = "../../files/www/luci-static/resources/openweir/"

// The dom.js maps diagnosticMessage reads.
var diagnosticMaps = []string{"diagnosticText", "errorText", "providerErrors", "kernelErrors"}

// The maps each kind of code is read from; sources.js reads notices first.
var readers = map[string][]string{
	"source":  {"sources"},
	"log":     diagnosticMaps,
	"notice":  append([]string{"notices"}, diagnosticMaps...),
	"failure": append([]string{"notices"}, diagnosticMaps...),
	"reason":  diagnosticMaps,
	"kernel":  diagnosticMaps,
}

// The kinds whose codes each map reads; any other key in it has no emitter. A task's step reads
// as a diagnosticText code when taskStep does not name it.
var served = map[string][]string{
	"sources":        {"source"},
	"notices":        {"notice", "failure"},
	"providerErrors": {"log", "notice", "failure", "reason"},
	"diagnosticText": {"log", "notice", "failure", "reason", "step"},
	"errorText":      {"log", "notice", "failure", "reason", "kernel"},
	"kernelErrors":   {"kernel"},
}

// The subscription helper reports these packages' errors as codes (subscriptioncli.code): a
// snake_case error as it is, an English one with underscores for its spaces.
var failurePackages = []string{"internal/subscription", "internal/cli/subscriptioncli", "internal/proxyspec"}

// Errors of those packages that never leave them.
var internalErrors = []string{
	"record unchanged", // errUnchanged: an update leaving the record as it is
}

// Emission points whose value is computed at run time, by file and function: the codes they can
// emit, or samples of a family that a dom.js errorPatterns entry reads.
var computed = map[string]struct {
	kind  string
	codes []string
}{
	// "<phase> <error>": the phase is checked where phase is called; diagnosticMessage reads both.
	"internal/router/manager.go:phase": {kind: "log"},
	// A change the core could not apply in place, followed by its error.
	"internal/router/manager.go:reload": {"log", []string{"reload fallback core is not running"}},
	// The routing audit logs what its log calls are given.
	"internal/router/health.go:newAudit": {kind: "log"},
	// "<action> <stage> <task>[ <code>]", checked by TestTaskNamesReadInChinese.
	"cmd/openweird/main.go:runJob": {kind: "log"},
	// A node dropped for a broken dialer-proxy chain, or for its own error (addProxy, proxyspec).
	"internal/subscription/document.go:chains":     {"notice", []string{"dialer_proxy_unavailable", "dialer_proxy_cycle"}},
	"internal/subscription/document.go:parseClash": {"notice", []string{"invalid_endpoint", "node_limit", "unsupported_node", "mihomo_protocol_unsupported"}},
	// subconv's warnings as subconv_<code>. Its invalid_credential becomes one of the credential
	// notices, and template_applied is recorded on the profile instead.
	"internal/subscription/convert.go:warningNotice": {"notice", append(prefixed("subconv_",
		subconv.WarnUnsupportedProxy, subconv.WarnUnsupportedOption, subconv.WarnInvalidProxy,
		subconv.WarnIgnoredOption, subconv.WarnUnsupportedRule, subconv.WarnUnsupportedRuleSet,
		subconv.WarnUnsupportedProvider, subconv.WarnUnsupportedGroup, subconv.WarnUnknownReference,
		subconv.WarnCyclicReference, subconv.WarnEmptyGroup, subconv.WarnRenamed,
		subconv.WarnLocalProvider, subconv.WarnTemplateUnavailable),
		"nonstandard_snell_credential", "invalid_credential", "node_missing_credential")},
	// A failed refresh keeps the error's code (collected where it is made), or update_failed.
	"internal/subscription/fetch.go:Refresh": {"failure", []string{"update_failed"}},
	// subscription_http_<status> and provider_http_<status>.
	"internal/subscription/fetch.go:statusErr":    {"failure", []string{"subscription_http_403"}},
	"internal/subscription/providers.go:download": {"failure", []string{"provider_http_404"}},
	// The core rejected one entry of a given type.
	"internal/cli/kernelcli/check.go:rejection": {"reason", []string{"candidate core rejected vmess configuration"}},
	// The certificate check a kernel download failed, as the kernel helper reports it.
	"cmd/openweird/kernel.go:publicKernelError": {"kernel", []string{
		(&tlsdiag.Diagnostic{Reason: "untrusted"}).Wire(),
		(&tlsdiag.Diagnostic{Reason: "expired", CheckedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}).Wire(),
	}},
	// A kernel change the service did not confirm: the previous kernel runs again, or the
	// service's problem, if any.
	"cmd/openweird/kernel.go:waitForKernel": {"kernel", []string{
		"candidate failed startup or health checks; previous kernel v1.19.0 is running",
		"kernel change unconfirmed: core exited during startup", "kernel change unconfirmed: ",
	}},
	// begin takes its options in a list.
	"internal/router/system.go:Start": {"kernel", []string{"openweir-kernel begin failed"}},
	// The steps of the jobs that take one from the request, as dispatch and kernelJob allow them.
	"cmd/openweird/main.go:dispatch": {"action", append(prefixed("subscription_write/",
		"login", "configure", "preferences", "rollback", "revoke", "logout", "site"), "kernel_read/versions")},
	"cmd/openweird/kernel.go:kernelJob": {"action", prefixed("kernel/", "install-json", "select", "rollback")},
}

func prefixed(prefix string, codes ...string) []string {
	for i, c := range codes {
		codes[i] = prefix + c
	}
	return codes
}

// The kernel's rejections read "<object>: <reason>", the object a generated node or group ID, an
// entry of the configuration or the whole configuration (kernelcli rejection, router Issue).
var rejectionSamples = []string{
	"node:0123456789abcdef0123456789abcdef: candidate core rejected vmess configuration",
	"group:0123456789abcdef0123456789abcdef: no compatible members on this device",
	"proxy group[2]: candidate core rejected the configuration",
	"configuration: candidate core rejected the configuration",
}

func TestEmittedCodesReadInChinese(t *testing.T) {
	src := parseRouter(t)
	codes := src.emitted(t)
	maps, text := luciMaps(t)
	patterns := errorPatterns(t, text["dom.js"])
	readable := func(kind, code string) bool {
		for _, m := range readers[kind] {
			if maps[m][code] {
				return true
			}
		}
		// noticeRows handles some notices by their code.
		if kind == "notice" && strings.Contains(text["pages/sources.js"], "'"+code+"'") {
			return true
		}
		return kind != "source" && slices.ContainsFunc(patterns, func(re *regexp.Regexp) bool { return re.MatchString(code) })
	}
	for kind, set := range codes {
		if readers[kind] == nil {
			continue
		}
		for code, at := range set {
			if !readable(kind, code) {
				t.Errorf("%s %q (%s) has no Chinese text in %v", kind, code, at, readers[kind])
			}
		}
	}
	for _, sample := range rejectionSamples {
		if !readable("reason", sample) {
			t.Errorf("rejection %q has no dom.js errorPatterns entry", sample)
		}
	}

	english := src.englishErrors(t)
	for name, kinds := range served {
		for key := range maps[name] {
			if slices.ContainsFunc(kinds, func(kind string) bool { _, ok := codes[kind][key]; return ok }) {
				continue
			}
			// An English error from the router or its shell helpers.
			if (name == "diagnosticText" || name == "errorText") && !regexp.MustCompile(`^[a-z0-9_]+$`).MatchString(key) && english(key) {
				continue
			}
			t.Errorf("%s has a text for %q, which nothing emits", name, key)
		}
	}
}

// runJob logs "<action> <stage> <task>[ <code>]" when a job ends; taskName reads the action, a
// head and step for one taskText does not name in full.
func TestTaskNamesReadInChinese(t *testing.T) {
	src := parseRouter(t)
	codes := src.emitted(t)
	maps, text := luciMaps(t)
	heads, steps := map[string]bool{}, map[string]bool{}
	for action, at := range codes["action"] {
		if maps["taskText"][action] {
			heads[action] = true
			continue
		}
		head, step, _ := strings.Cut(action, "/")
		heads[head] = true
		if step != "" {
			steps[step] = true
		}
		if !maps["taskText"][head] || step != "" && !maps["taskStep"][step] && !maps["diagnosticText"][step] {
			t.Errorf("task %q (%s) has no Chinese name in taskText and taskStep", action, at)
		}
	}
	for key := range maps["taskText"] {
		if !heads[key] {
			t.Errorf("taskText names %q, which no job runs", key)
		}
	}
	for key := range maps["taskStep"] {
		if !steps[key] {
			t.Errorf("taskStep names %q, which no job runs", key)
		}
	}

	// The stages a finished job is logged with, and held for a refresh whose update waits for
	// the administrator (heldUpdate), which the log line follows with the pending update's code.
	stages := map[string]bool{}
	for _, fn := range src.funcs["cmd/openweird"]["runJob"] {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if sel, ok := n.Lhs[0].(*ast.SelectorExpr); ok && sel.Sel.Name == "Stage" {
					if lit, ok := n.Rhs[0].(*ast.BasicLit); ok {
						v, _ := strconv.Unquote(lit.Value)
						stages[v] = true
					}
				}
			case *ast.BasicLit:
				if m := regexp.MustCompile(`^" ([a-z]+) "$`).FindStringSubmatch(n.Value); m != nil {
					stages[m[1]] = true
				}
			}
			return true
		})
	}
	if !maps["taskStage"]["held"] || !stages["held"] {
		t.Errorf("runJob logs a held refresh as %v; taskStage reads %v", stages, maps["taskStage"])
	}
	if len(stages) != len(maps["taskStage"]) {
		t.Errorf("runJob logs the stages %v; taskStage reads %v", stages, maps["taskStage"])
	}
	read := regexp.MustCompile(`const task = /\^\(\\S\+\) \(([a-z|]+)\) `).FindStringSubmatch(text["dom.js"])
	if read == nil {
		t.Fatal("diagnosticMessage's task line not found")
	}
	for stage := range stages {
		if !maps["taskStage"][stage] {
			t.Errorf("stage %q has no Chinese text in taskStage", stage)
		}
		if !slices.Contains(strings.Split(read[1], "|"), stage) {
			t.Errorf("diagnosticMessage does not read the stage %q", stage)
		}
	}
	pending := []string{subscription.PendingConfirmation, subscription.PendingBlocked}
	for _, code := range pending {
		if !maps["diagnosticText"][code] || !maps["pendingUpdates"][code] {
			t.Errorf("held update %q needs a text in diagnosticText (the log) and pendingUpdates (its card)", code)
		}
	}
	if len(maps["pendingUpdates"]) != len(pending) {
		t.Errorf("pendingUpdates reads %v; the router holds updates as %v", maps["pendingUpdates"], pending)
	}
}

type routerSource struct {
	fset  *token.FileSet
	files map[string][]*ast.File                // by package directory, relative to the module
	funcs map[string]map[string][]*ast.FuncDecl // by package directory and name
	vars  map[string]map[string]ast.Expr        // package-level constants and variables
	path  map[*ast.File]string                  // relative to the module
}

// parseRouter reads the Go programs that run on the router.
func parseRouter(t *testing.T) *routerSource {
	t.Helper()
	s := &routerSource{fset: token.NewFileSet(), files: map[string][]*ast.File{}, funcs: map[string]map[string][]*ast.FuncDecl{}, vars: map[string]map[string]ast.Expr{}, path: map[*ast.File]string{}}
	for _, root := range []string{"cmd/openweird", "cmd/openweir-kernel", "cmd/openweir-net", "cmd/openweir-subscription", "internal"} {
		err := filepath.WalkDir("../../"+root, func(p string, d fs.DirEntry, err error) error {
			rel := strings.TrimPrefix(filepath.ToSlash(p), "../../")
			if err != nil || rel == "internal/release" {
				if err == nil {
					err = filepath.SkipDir // release tooling, not on the router
				}
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(s.fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			dir := filepath.ToSlash(filepath.Dir(rel))
			s.files[dir] = append(s.files[dir], f)
			s.path[f] = rel
			if s.funcs[dir] == nil {
				s.funcs[dir], s.vars[dir] = map[string][]*ast.FuncDecl{}, map[string]ast.Expr{}
			}
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					s.funcs[dir][d.Name.Name] = append(s.funcs[dir][d.Name.Name], d)
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						if v, ok := spec.(*ast.ValueSpec); ok && len(v.Names) == len(v.Values) {
							for i, n := range v.Names {
								s.vars[dir][n.Name] = v.Values[i]
							}
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// scope is where an expression sits: its package directory, file and enclosing function.
type scope struct {
	dir  string
	file *ast.File
	fn   *ast.FuncDecl
}

func (s *routerSource) site(c scope) string {
	name := ""
	if c.fn != nil {
		name = c.fn.Name.Name
	}
	return s.path[c.file] + ":" + name
}

// Functions that pass on a code their callers give them; the callers are checked instead.
var forwarders = []string{"Log", "LogDetail", "notice"}

// emitted returns the codes of every emission point by kind, each with where it was found.
func (s *routerSource) emitted(t *testing.T) map[string]map[string]string {
	t.Helper()
	codes := map[string]map[string]string{}
	add := func(kind, code, at string) {
		if code == "" {
			return
		}
		if codes[kind] == nil {
			codes[kind] = map[string]string{}
		}
		if _, ok := codes[kind][code]; !ok {
			codes[kind][code] = at
		}
	}
	used := map[string]bool{}
	dynamic := func(kind string, c scope, pos token.Pos) {
		site := s.site(c)
		x, listed := computed[site]
		if !listed || x.kind != kind {
			t.Errorf("%s: computed %s code in %s; follow it to literals or list it in computed", s.fset.Position(pos), kind, site)
			return
		}
		used[site] = true
		for _, v := range x.codes {
			add(kind, v, site)
		}
	}
	emit := func(kind string, c scope, e ast.Expr) {
		values, ok := s.values(c, e, 0)
		if !ok {
			dynamic(kind, c, e.Pos())
			return
		}
		for _, v := range values {
			add(kind, v, s.site(c))
		}
	}
	sentinels := s.sentinels(t)
	errorCode := regexp.MustCompile(`^[a-z][a-z0-9]*([_ ][a-z0-9%]+)+$`)
	type jobCall struct {
		c    scope
		call *ast.CallExpr
	}
	var jobs []jobCall
	for dir, files := range s.files {
		failures := slices.Contains(failurePackages, dir)
		for _, f := range files {
			for _, d := range f.Decls {
				c := scope{dir: dir, file: f}
				if fn, ok := d.(*ast.FuncDecl); ok {
					c.fn = fn
					if slices.Contains(forwarders, fn.Name.Name) {
						continue
					}
				}
				ast.Inspect(d, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.CallExpr:
						name, recv := callee(n)
						switch {
						case (name == "Log" || name == "LogDetail") && len(n.Args) >= 3:
							emit("source", c, n.Args[0])
							emit("log", c, n.Args[2])
						case name == "phase" && dir == "internal/router",
							name == "log" && recv != "" && len(n.Args) == 1:
							emit("log", c, n.Args[0])
						case name == "dnsIssue":
							emit("log", c, n.Args[1])
						case name == "notice" && recv != "":
							emit("notice", c, n.Args[0])
						case name == "classifyRequestFailure":
							emit("failure", c, n.Args[1])
						case name == "runJob":
							emit("action", c, n.Args[1])
							jobs = append(jobs, jobCall{c, n})
						case (name == "command" || name == "jsonCmd") && dir == "internal/router":
							// A kernel helper command that failed without a reason (command).
							i := map[string]int{"command": 1, "jsonCmd": 2}[name]
							if bin, ok := n.Args[i].(*ast.Ident); !ok || bin.Name != "kernelCLI" || len(n.Args) == i+1 {
								break
							}
							verbs, ok := s.values(c, n.Args[i+1], 0)
							if !ok || n.Ellipsis.IsValid() {
								dynamic("kernel", c, n.Pos())
								break
							}
							for _, v := range verbs {
								add("kernel", "openweir-kernel "+v+" failed", s.site(c))
							}
						case failures && (recv == "errors" && name == "New" || recv == "fmt" && name == "Errorf"):
							lit, ok := n.Args[0].(*ast.BasicLit)
							if !ok {
								break
							}
							v, _ := strconv.Unquote(lit.Value)
							if !errorCode.MatchString(v) || sentinels[v] || slices.Contains(internalErrors, v) {
								break
							}
							if strings.Contains(v, "%") {
								dynamic("failure", c, n.Pos())
							} else {
								add("failure", strings.ReplaceAll(v, " ", "_"), s.site(c))
							}
						}
					case *ast.CompositeLit:
						if list, ok := n.Type.(*ast.ArrayType); ok && typeName(list.Elt) == "Notice" {
							for _, e := range n.Elts {
								if row, ok := e.(*ast.CompositeLit); ok && row.Type == nil {
									if v := field(row, "Code", -1); v != nil {
										emit("notice", c, v)
									}
								}
							}
						}
						switch typeName(n.Type) {
						case "Notice":
							if v := field(n, "Code", -1); v != nil {
								emit("notice", c, v)
							}
						case "Issue", "configRejection":
							if v := field(n, "Reason", 2); v != nil {
								emit("reason", c, v)
							}
						}
					case *ast.AssignStmt:
						for i, l := range n.Lhs {
							sel, ok := l.(*ast.SelectorExpr)
							if !ok || len(n.Rhs) != len(n.Lhs) {
								continue
							}
							switch {
							case sel.Sel.Name == "Reason" && dir == "internal/cli/kernelcli":
								emit("reason", c, n.Rhs[i]) // a rejection's reason set after it was made
							case sel.Sel.Name == "LastFailure":
								emit("failure", c, n.Rhs[i]) // what a source's card shows
							}
						}
					}
					return true
				})
			}
		}
	}
	// The codes subscriptioncli.code gives the errors it classifies, and a deadline's error,
	// which it passes on as context_deadline_exceeded.
	for _, fn := range s.funcs["internal/cli/subscriptioncli"]["code"] {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if r, ok := n.(*ast.ReturnStmt); ok && len(r.Results) == 1 {
				if lit, ok := r.Results[0].(*ast.BasicLit); ok {
					v, _ := strconv.Unquote(lit.Value)
					add("failure", v, "internal/cli/subscriptioncli/main.go:code")
				}
			}
			return true
		})
	}
	add("failure", strings.ReplaceAll(context.DeadlineExceeded.Error(), " ", "_"), "internal/cli/subscriptioncli/main.go:code")
	// runJob logs a held refresh with its pending update's code (heldUpdate).
	for _, code := range []string{subscription.PendingConfirmation, subscription.PendingBlocked} {
		add("log", code, "cmd/openweird/refresh.go:heldUpdate")
	}
	// The codes a referenced file's download reports (providerFailure), and the certificate
	// failures a subscription's download reports alike (classifyRequestFailure).
	call, ok := s.vars["internal/subscription"]["providerCodes"].(*ast.CallExpr)
	if !ok {
		t.Fatal("providerCodes not found")
	}
	v, _ := strconv.Unquote(call.Args[0].(*ast.BasicLit).Value)
	for _, code := range strings.Fields(v) {
		add("failure", code, "internal/subscription/provider_diagnostic.go:providerCodes")
		if reason, ok := strings.CutPrefix(code, "provider_tls_"); ok {
			add("failure", "subscription_tls_"+reason, "internal/subscription/provider_diagnostic.go:classifyRequestFailure")
		}
	}
	// What the kernel's jobs fail with, which the kernel page shows and the bootstrap job's log
	// line ends with: the errors their bodies and the functions of this package they call make,
	// the error variables those return and a context's errors. The kernel helper's errors reach
	// them through child and publicKernelError.
	followed := map[*ast.FuncDecl]bool{}
	var fails func(c scope, body ast.Node)
	fails = func(c scope, body ast.Node) {
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.ReturnStmt:
				for _, r := range n.Results {
					if v, ok := s.errorVar(c, r); ok {
						add("kernel", v, s.site(c))
					}
				}
			case *ast.CallExpr:
				switch name, recv := callee(n); {
				case recv == "errors" && name == "New":
					emit("kernel", c, n.Args[0])
				case recv == "fmt" && name == "Errorf":
					dynamic("kernel", c, n.Pos())
				case recv == "ctx" && name == "Err":
					add("kernel", context.DeadlineExceeded.Error(), s.site(c))
					add("kernel", context.Canceled.Error(), s.site(c))
				case recv == "" || recv == receiver(c.fn):
					for _, fn := range s.funcs[c.dir][name] {
						if !followed[fn] {
							followed[fn] = true
							fails(scope{dir: c.dir, file: s.fileOf(c.dir, fn), fn: fn}, fn.Body)
						}
					}
				}
			}
			return true
		})
	}
	kernelJobs := 0
	for _, j := range jobs {
		actions, ok := s.values(j.c, j.call.Args[1], 0)
		if !ok {
			actions = computed[s.site(j.c)].codes
		}
		if slices.ContainsFunc(actions, func(a string) bool { return strings.HasPrefix(a, "kernel") }) {
			kernelJobs++
			fails(j.c, j.call.Args[2])
		}
	}
	if public := s.funcs["cmd/openweird"]["publicKernelError"]; kernelJobs == 0 || len(public) == 0 || !followed[public[0]] {
		t.Fatal("the kernel's jobs and the kernel helper's errors (publicKernelError) not found")
	}
	// A task the manager's restart interrupted, which the kernel page shows for the bootstrap job.
	interrupted := false
	for _, fn := range s.funcs["cmd/openweird"]["loadJobs"] {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if a, ok := n.(*ast.AssignStmt); ok && len(a.Lhs) == 1 && len(a.Rhs) == 1 {
				sel, isField := a.Lhs[0].(*ast.SelectorExpr)
				lit, isLit := a.Rhs[0].(*ast.BasicLit)
				if isField && isLit && sel.Sel.Name == "Error" {
					v, _ := strconv.Unquote(lit.Value)
					add("kernel", v, "cmd/openweird/tasks.go:loadJobs")
					interrupted = true
				}
			}
			return true
		})
	}
	if !interrupted {
		t.Fatal("loadJobs's error for an interrupted task not found")
	}
	for site := range computed {
		if !used[site] {
			t.Errorf("computed lists %s, which emits nothing computed any more", site)
		}
	}
	return codes
}

// sentinels returns the messages of the errors subscriptioncli.code reports by a code of its own.
func (s *routerSource) sentinels(t *testing.T) map[string]bool {
	out := map[string]bool{}
	for _, fn := range s.funcs["internal/cli/subscriptioncli"]["code"] {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "sub" {
					if call, ok := s.vars["internal/subscription"][sel.Sel.Name].(*ast.CallExpr); ok {
						v, _ := strconv.Unquote(call.Args[0].(*ast.BasicLit).Value)
						out[v] = true
					}
				}
			}
			return true
		})
	}
	if len(out) == 0 {
		t.Fatal("subscriptioncli.code classifies no subscription errors")
	}
	return out
}

// englishErrors reports whether an English text is an error the router's Go code or shell
// helpers can still produce: a string literal, a format with its verbs filled in, the text of a
// helper script, or a context error.
func (s *routerSource) englishErrors(t *testing.T) func(string) bool {
	literals := map[string]bool{context.DeadlineExceeded.Error(): true, context.Canceled.Error(): true}
	var formats []*regexp.Regexp
	verb := regexp.MustCompile(`%[sdvq]`)
	for _, files := range s.files {
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, err := strconv.Unquote(lit.Value)
					if err == nil && verb.MatchString(v) {
						formats = append(formats, regexp.MustCompile("^"+verb.ReplaceAllString(regexp.QuoteMeta(v), `\S+`)+"$"))
					} else if err == nil {
						literals[v] = true
					}
				}
				return true
			})
		}
	}
	var scripts strings.Builder
	for _, dir := range []string{"../../files/usr/libexec/openweir", "../../packaging/openwrt"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil && !e.IsDir() {
				scripts.Write(b)
			}
		}
	}
	return func(text string) bool {
		return literals[text] || strings.Contains(scripts.String(), text) ||
			slices.ContainsFunc(formats, func(re *regexp.Regexp) bool { return re.MatchString(text) })
	}
}

// errorVar returns the message of an error variable made with errors.New, the package's own or
// one of a package of this module it imports.
func (s *routerSource) errorVar(c scope, e ast.Expr) (string, bool) {
	dir, name := c.dir, ""
	switch e := e.(type) {
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		x, ok := e.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		name, dir = e.Sel.Name, ""
		for _, imp := range c.file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if rel, ok := strings.CutPrefix(p, "github.com/openweir/openwrt/"); ok && (imp.Name == nil && filepath.Base(rel) == x.Name || imp.Name != nil && imp.Name.Name == x.Name) {
				dir = rel
			}
		}
	default:
		return "", false
	}
	call, ok := s.vars[dir][name].(*ast.CallExpr)
	if !ok {
		return "", false
	}
	if fn, recv := callee(call); fn != "New" || recv != "errors" {
		return "", false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	return v, err == nil
}

// receiver returns the name of a method's receiver, or "" for a function.
func receiver(fn *ast.FuncDecl) string {
	if fn == nil || fn.Recv == nil || len(fn.Recv.List[0].Names) == 0 {
		return ""
	}
	return fn.Recv.List[0].Names[0].Name
}

func callee(call *ast.CallExpr) (name, recv string) {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name, ""
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return f.Sel.Name, x.Name
		}
		return f.Sel.Name, "?"
	}
	return "", ""
}

func typeName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// field returns a composite literal's field by key, or by position when unkeyed.
func field(lit *ast.CompositeLit, name string, position int) ast.Expr {
	for i, e := range lit.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == name {
				return kv.Value
			}
		} else if i == position {
			return e
		}
	}
	return nil
}

// values returns the strings e can hold, or false when part of it is computed at run time.
func (s *routerSource) values(c scope, e ast.Expr, depth int) ([]string, bool) {
	if depth > 8 {
		return nil, false
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		v, err := strconv.Unquote(e.Value)
		return []string{v}, err == nil && e.Kind == token.STRING
	case *ast.ParenExpr:
		return s.values(c, e.X, depth+1)
	case *ast.BinaryExpr:
		l, ok := s.values(c, e.X, depth+1)
		r, ok2 := s.values(c, e.Y, depth+1)
		if e.Op != token.ADD || !ok || !ok2 {
			return nil, false
		}
		var out []string
		for _, a := range l {
			for _, b := range r {
				out = append(out, a+b)
			}
		}
		return out, true
	case *ast.Ident:
		return s.ident(c, e, depth)
	case *ast.SelectorExpr:
		if v, ok := s.tableField(c, e, depth); ok {
			return v, true
		}
		return s.fieldAssignments(c, e.Sel.Name, depth)
	case *ast.CallExpr:
		fun, ok := e.Fun.(*ast.Ident)
		if !ok || len(s.funcs[c.dir][fun.Name]) != 1 {
			return nil, false
		}
		fn := s.funcs[c.dir][fun.Name][0]
		inner := scope{dir: c.dir, file: s.fileOf(c.dir, fn), fn: fn}
		var out []string
		resolved := true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			if r, ok := n.(*ast.ReturnStmt); ok && len(r.Results) > 0 {
				v, ok := s.values(inner, r.Results[0], depth+1)
				resolved = resolved && ok
				out = append(out, v...)
			}
			return true
		})
		return out, resolved
	}
	return nil, false
}

func (s *routerSource) fileOf(dir string, fn *ast.FuncDecl) *ast.File {
	for _, f := range s.files[dir] {
		if f.Pos() <= fn.Pos() && fn.End() <= f.End() {
			return f
		}
	}
	return nil
}

// ident follows a name: the cases of a switch on it, the values assigned to it in its function,
// the arguments the function's callers pass for it, or a package constant.
func (s *routerSource) ident(c scope, id *ast.Ident, depth int) ([]string, bool) {
	if c.fn != nil {
		if cases := switchCases(c.fn.Body, id); cases != nil {
			var out []string
			for _, e := range cases {
				v, ok := s.values(c, e, depth+1)
				if !ok {
					return nil, false
				}
				out = append(out, v...)
			}
			return out, true
		}
		var out []string
		assigned, resolved := false, true
		ast.Inspect(c.fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for i, l := range n.Lhs {
					if l, ok := l.(*ast.Ident); ok && l.Name == id.Name {
						assigned = true
						rhs := i
						if len(n.Rhs) == 1 && i == 0 {
							rhs = 0 // the first result of a call, as values reads a call
						} else if len(n.Rhs) != len(n.Lhs) {
							resolved = false
							continue
						}
						if n.Tok != token.DEFINE && n.Tok != token.ASSIGN {
							resolved = false
							continue
						}
						v, ok := s.values(c, n.Rhs[rhs], depth+1)
						resolved = resolved && ok
						out = append(out, v...)
					}
				}
			case *ast.ValueSpec:
				for i, name := range n.Names {
					if name.Name == id.Name && i < len(n.Values) {
						assigned = true
						v, ok := s.values(c, n.Values[i], depth+1)
						resolved = resolved && ok
						out = append(out, v...)
					}
				}
			}
			return true
		})
		if i := paramIndex(c.fn, id.Name); i >= 0 {
			v, ok := s.callers(c, c.fn.Name.Name, i, depth)
			return append(out, v...), ok && resolved
		}
		if assigned {
			return out, resolved
		}
	}
	if v, ok := s.vars[c.dir][id.Name]; ok {
		return s.values(scope{dir: c.dir}, v, depth+1)
	}
	return nil, false
}

// switchCases returns the values of the case that holds id in a switch on id, if any.
func switchCases(body *ast.BlockStmt, id *ast.Ident) []ast.Expr {
	var found []ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return found == nil
		}
		if tag, ok := sw.Tag.(*ast.Ident); ok && tag.Name == id.Name {
			for _, cc := range sw.Body.List {
				cc := cc.(*ast.CaseClause)
				if cc.Colon < id.Pos() && id.End() <= cc.End() && len(cc.List) > 0 {
					found = cc.List
				}
			}
		}
		return found == nil
	})
	return found
}

func paramIndex(fn *ast.FuncDecl, name string) int {
	i := 0
	for _, f := range fn.Type.Params.List {
		for _, n := range f.Names {
			if n.Name == name {
				return i
			}
			i++
		}
	}
	return -1
}

// callers resolves argument i of every call in the package to the named function.
func (s *routerSource) callers(c scope, name string, i, depth int) ([]string, bool) {
	var out []string
	found, resolved := false, true
	for _, f := range s.files[c.dir] {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if callName, _ := callee(call); callName == name && i < len(call.Args) {
					found = true
					v, ok := s.values(scope{dir: c.dir, file: f, fn: fn}, call.Args[i], depth+1)
					resolved = resolved && ok
					out = append(out, v...)
				}
				return true
			})
		}
	}
	return out, found && resolved
}

// tableField resolves x.f in a loop over a table: for _, x := range []struct{...}{...}.
func (s *routerSource) tableField(c scope, sel *ast.SelectorExpr, depth int) ([]string, bool) {
	x, ok := sel.X.(*ast.Ident)
	if !ok || c.fn == nil {
		return nil, false
	}
	var out []string
	resolved := false
	ast.Inspect(c.fn.Body, func(n ast.Node) bool {
		r, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		v, ok := r.Value.(*ast.Ident)
		table, isLit := r.X.(*ast.CompositeLit)
		if !ok || v.Name != x.Name || !isLit {
			return true
		}
		arr, ok := table.Type.(*ast.ArrayType)
		if !ok {
			return true
		}
		st, ok := arr.Elt.(*ast.StructType)
		if !ok {
			return true
		}
		position, i := -1, 0
		for _, f := range st.Fields.List {
			for _, n := range f.Names {
				if n.Name == sel.Sel.Name {
					position = i
				}
				i++
			}
		}
		resolved = true
		for _, e := range table.Elts {
			row, ok := e.(*ast.CompositeLit)
			if !ok {
				resolved = false
				continue
			}
			vs, ok := s.values(c, field(row, sel.Sel.Name, position), depth+1)
			resolved = resolved && ok
			out = append(out, vs...)
		}
		return false
	})
	return out, resolved
}

// fieldAssignments resolves a struct field by the values assigned to it in the package.
func (s *routerSource) fieldAssignments(c scope, name string, depth int) ([]string, bool) {
	var out []string
	found, resolved := false, true
	for _, f := range s.files[c.dir] {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				a, ok := n.(*ast.AssignStmt)
				if !ok || len(a.Lhs) != len(a.Rhs) {
					return true
				}
				for i, l := range a.Lhs {
					if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
						found = true
						v, ok := s.values(scope{dir: c.dir, file: f, fn: fn}, a.Rhs[i], depth+1)
						resolved = resolved && ok
						out = append(out, v...)
					}
				}
				return true
			})
		}
	}
	return out, found && resolved
}

// luciMaps returns the keys of the LuCI pages' text maps, and the pages' source.
func luciMaps(t *testing.T) (map[string]map[string]bool, map[string]string) {
	t.Helper()
	out, text := map[string]map[string]bool{}, map[string]string{}
	for file, names := range map[string][]string{
		"dom.js":           {"diagnosticText", "errorText", "providerErrors", "kernelErrors", "taskText", "taskStep", "taskStage"},
		"pages/sources.js": {"notices", "pendingUpdates"},
		"pages/records.js": {"sources"},
	} {
		b, err := os.ReadFile(luci + file)
		if err != nil {
			t.Fatal(err)
		}
		text[file] = string(b)
		for _, name := range names {
			keys, err := objectKeys(string(b), name)
			if err != nil || len(keys) == 0 {
				t.Fatalf("%s %s: %v", file, name, err)
			}
			out[name] = keys
		}
	}
	return out, text
}

// objectKeys reads the keys of `const name = { key: value, ... };`.
func objectKeys(src, name string) (map[string]bool, error) {
	_, rest, ok := strings.Cut(src, "const "+name+" = {")
	if !ok {
		_, rest, ok = strings.Cut(src, "export const "+name+" = {")
	}
	if !ok {
		return nil, os.ErrNotExist
	}
	keys := map[string]bool{}
	for i := 0; ; {
		i = skipSpace(rest, i)
		if rest[i] == '}' {
			return keys, nil
		}
		var key string
		if q := rest[i]; q == '\'' || q == '"' {
			end := strings.IndexByte(rest[i+1:], q)
			key, i = rest[i+1:i+1+end], i+end+2
		} else {
			end := i
			for end < len(rest) && (rest[end] == '_' || rest[end] >= 'a' && rest[end] <= 'z' || rest[end] >= 'A' && rest[end] <= 'Z' || rest[end] >= '0' && rest[end] <= '9') {
				end++
			}
			key, i = rest[i:end], end
		}
		if i = skipSpace(rest, i); key == "" || rest[i] != ':' {
			return nil, strconv.ErrSyntax
		}
		keys[key] = true
		// The value runs to a comma or the closing brace outside strings and brackets.
		for depth := 0; ; {
			i++
			switch ch := rest[i]; ch {
			case '\'', '"', '`':
				for i++; rest[i] != ch; i++ {
					if rest[i] == '\\' {
						i++
					}
				}
			case '(', '[', '{':
				depth++
			case ')', ']':
				depth--
			case '}':
				if depth == 0 {
					return keys, nil
				}
				depth--
			}
			if rest[i] == ',' && depth == 0 {
				i++
				break
			}
		}
	}
}

func skipSpace(src string, i int) int {
	for {
		for i < len(src) && strings.ContainsRune(" \t\r\n", rune(src[i])) {
			i++
		}
		if !strings.HasPrefix(src[i:], "//") {
			return i
		}
		i += strings.IndexByte(src[i:], '\n')
	}
}

// errorPatterns compiles dom.js's errorPatterns, the families of errors diagnosticMessage reads.
func errorPatterns(t *testing.T, dom string) []*regexp.Regexp {
	t.Helper()
	_, list, _ := strings.Cut(dom, "const errorPatterns = [")
	list, _, _ = strings.Cut(list, "\n];")
	var out []*regexp.Regexp
	for _, m := range regexp.MustCompile(`(?m)^\s*\[/((?:\\.|[^/\\\n])+)/([a-z]*),`).FindAllStringSubmatch(list, -1) {
		flags := ""
		if strings.Contains(m[2], "s") {
			flags = "(?s)"
		}
		out = append(out, regexp.MustCompile(flags+m[1]))
	}
	if len(out) == 0 {
		t.Fatal("dom.js errorPatterns not found")
	}
	return out
}
