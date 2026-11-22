package router

import (
	"bytes"
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openweir/openwrt/internal/control"
)

const recordLimit = 512

type Event struct {
	Count   int    `json:"count,omitempty"`
	Time    int64  `json:"time"`
	Source  string `json:"source"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"` // a redacted operation of a core error, or the plugins a start stopped
}
type Records struct {
	minTime     int64
	routeSince  int64  // the current core started; earlier routes name another configuration
	source      string // the subscription the running core uses
	recording   bool   // connection records are on; see Policy.RecordConnections
	failures    uint64 // numbers the records of failed dials, which the core gives no ID
	mu          sync.Mutex
	events      []Event
	connections []control.Connection
	index       map[string]int
	pos         int
	ruleHits    map[string]*RuleHit

	// The connection poll's pace; see pollWait.
	viewed time.Time     // the last read of the connection records
	view   chan struct{} // wakes an idle poll for a new reader
}

// RuleHit counts the connections a rule set matched since the records were last
// cleared, beyond the recordLimit connections that are kept.
type RuleHit struct {
	Count int   `json:"count"`
	Last  int64 `json:"last"`
}

const ruleHitLimit = 1024

func NewRecords() *Records {
	return &Records{index: map[string]int{}, ruleHits: map[string]*RuleHit{}, view: make(chan struct{}, 1)}
}

// Each connection poll parses the core's full snapshot. It runs every second only while
// someone reads the records (the records pages poll every 3.5 s, the overview's routes every
// 2.5 s), otherwise every five: connections shorter than that may then go unrecorded and
// uncounted in the rule hits, and a close is noted up to five seconds late. Failed dials
// come from the core log and are unaffected.
const (
	viewedPoll = time.Second
	idlePoll   = 5 * time.Second
	viewWindow = 10 * time.Second
)

// Viewed notes a read of the connection records. A reader arriving while the poll is idle
// wakes it at once.
func (r *Records) Viewed() {
	r.mu.Lock()
	idle := time.Since(r.viewed) > viewWindow
	r.viewed = time.Now()
	r.mu.Unlock()
	if idle {
		select {
		case r.view <- struct{}{}:
		default:
		}
	}
}

// pollWait waits until the next connection snapshot is due.
func (r *Records) pollWait(ctx context.Context) error {
	r.mu.Lock()
	d := idlePoll
	if time.Since(r.viewed) <= viewWindow {
		d = viewedPoll
	}
	r.mu.Unlock()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
	case <-r.view:
	}
	return nil
}

// RuleHits returns the per-rule-set connection counts.
func (r *Records) RuleHits() map[string]RuleHit {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]RuleHit, len(r.ruleHits))
	for k, v := range r.ruleHits {
		out[k] = *v
	}
	return out
}
func (r *Records) Log(source, level, message string) { r.LogDetail(source, level, message, "") }

// LogDetail records an event with a redacted operation shown under it.
func (r *Records) LogDetail(source, level, message, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UnixMilli()
	// Core and DNS repeats within a minute fold into one recent entry, which moves to the end.
	if source == "core" || source == "dns" {
		for i := len(r.events) - 1; i >= 0 && i >= len(r.events)-32; i-- {
			e := r.events[i]
			if e.Source == source && e.Level == level && e.Message == message && e.Detail == detail && now >= e.Time && now-e.Time <= 60000 {
				e.Count = max(e.Count, 1) + 1
				e.Time = now
				copy(r.events[i:], r.events[i+1:])
				r.events[len(r.events)-1] = e
				return
			}
		}
	}
	if len(r.events) == recordLimit {
		copy(r.events, r.events[1:])
		r.events = r.events[:recordLimit-1]
	}
	r.events = append(r.events, Event{Time: now, Source: source, Level: level, Message: message, Detail: detail})
}

// Core stderr is free form, and can contain signed URLs or full config values.
// Keep a bounded redacted event without echoing attacker-controlled content.
type logSink struct {
	r        *Records
	line     []byte
	terminal string // read after the process and its stderr reader have exited
}

// os/exec can deliver partial lines and multiple lines in one write. Keep a
// bounded prefix while waiting for the delimiter, even for malformed output.
func (s *logSink) Write(p []byte) (int, error) {
	count := len(p)
	for len(p) > 0 {
		end := bytes.IndexByte(p, '\n')
		n := end
		if n < 0 {
			n = len(p)
		}
		s.line = append(s.line, p[:min(n, 4096-len(s.line))]...)
		if end < 0 {
			break
		}
		s.flush()
		p = p[end+1:]
	}
	return count, nil
}
func (s *logSink) flush() {
	if line := strings.TrimSpace(string(s.line)); line != "" {
		s.recordLine(line)
	}
	s.line = s.line[:0]
}

// Mihomo may color its log headers even when stderr is a pipe.
var logColor = regexp.MustCompile("\x1b\\[[0-9;]*m")

// corePermissionReason names what the core was denied. The core runs as root with every
// capability (coreCommand), so a denial comes from the firewall or a kernel setting (such as
// ping_group_range for ICMP sockets), not from file ownership or a missing capability.
func corePermissionReason(line string) string {
	switch {
	case strings.Contains(line, "ping_group_range"), strings.Contains(line, "listen ip4:icmp"), strings.Contains(line, "listen ip6:ipv6-icmp"), strings.Contains(line, "icmp socket"):
		return "core_icmp_socket_permission"
	case strings.Contains(line, "listenlocalconn"):
		// TProxy answers UDP from a socket bound to the original destination, often a port below 1024.
		return "core_tproxy_udp_reply_permission"
	case strings.Contains(line, "ip_transparent"), strings.Contains(line, "transparent socket"), strings.Contains(line, "set transparent"), strings.Contains(line, "ipv6_transparent"):
		return "core_tproxy_socket_permission"
	case strings.Contains(line, "so_mark"), strings.Contains(line, "set routing mark"):
		return "core_route_mark_permission"
	case strings.Contains(line, "listen tcp"), strings.Contains(line, "listen udp"), strings.Contains(line, "bind:"):
		return "core_listener_permission"
	case strings.Contains(line, "pthread_create"), strings.Contains(line, "failed to create new os thread"):
		return "core_thread_creation_failed"
	case strings.Contains(line, "/proc/"), strings.Contains(line, "find process"), strings.Contains(line, "process name"):
		return "core_process_lookup_permission"
	case strings.Contains(line, "connect:"), strings.Contains(line, "sendto"), strings.Contains(line, "sendmsg"),
		strings.Contains(line, "dial tcp"), strings.Contains(line, "dial udp"), strings.Contains(line, "write udp"), strings.Contains(line, "write tcp"):
		return "core_outbound_blocked"
	case strings.Contains(line, "open /"), strings.Contains(line, "stat /"), strings.Contains(line, "mkdir /"), strings.Contains(line, "rename /"):
		return "core_file_permission"
	default:
		return "permission_denied"
	}
}

var connectionNoise = map[string]bool{"connection_refused": true, "connection_reset": true, "connection_closed": true,
	"io_timeout": true, "deadline_exceeded": true, "dial_failed": true, "handshake_failed": true}

// ordinary marks core warnings that normal operation produces all the time (OpenClash shows
// them only in its raw core log): one connection or packet failing, which the core retries
// and reports up to ten times per connection, a group starting its health check after
// repeated failures (node failover follows up on those) and the core stopping. Failed dials
// become connection records; the rest are dropped.
var ordinary = []string{"[tcp] dial ", "[udp] dial ", "[udp] resolve ip error", "[udp] destination ip not valid",
	"[udp] dosniff error", "[udp] parse metadata failed", "[metadata] ", "[icmp] failed to connect", "isn't a *net.udpaddr",
	"nil *net.udpaddr", "activate health check", "mihomo shutting down"}

func (s *logSink) recordLine(line string) {
	if strings.Contains(line, "\x1b") {
		line = logColor.ReplaceAllString(line, "")
	}
	original := line
	line = strings.ToLower(line)
	level := "warn"
	fatal := false
	// Only a leading log level (optionally after a timestamp) can classify a
	// process exit. Free-form DNS names, server names and paths stay private.
	for i, field := range strings.Fields(line) {
		if i > 3 {
			break
		}
		field = strings.TrimPrefix(field, "level=")
		field, _, _ = strings.Cut(field, "[")
		switch strings.Trim(field, "[]:") {
		case "fatal", "panic":
			level, fatal = "error", true
		case "error":
			level = "error"
		case "warn", "warning":
			level = "warn"
		case "info", "debug", "trace":
			return
		default:
			continue
		}
		break
	}
	denied := strings.Contains(line, "permission denied") || strings.Contains(line, "operation not permitted")
	// Out of descriptors (EMFILE for the core, or ENFILE for the whole system): the core can
	// neither accept nor open connections, which browsers report as a connection closed
	// unexpectedly. A failed dial still becomes a connection record, and the cause is logged.
	exhausted := strings.Contains(line, "too many open files")
	if !fatal && !denied && slices.ContainsFunc(ordinary, func(n string) bool { return strings.Contains(line, n) }) {
		if c, ok := control.FailedDial(original, time.Now().UnixMilli()); ok {
			s.r.Failed(c)
		}
		if !exhausted {
			return
		}
	}
	source := "core"
	if strings.Contains(line, "dns:") || strings.Contains(line, "dns/") {
		source = "dns"
	}
	reason := "core_diagnostic"
	if denied {
		reason = corePermissionReason(line)
	} else if exhausted {
		reason = "core_file_limit_reached"
	} else {
		for _, x := range []struct{ needle, reason string }{{"address already in use", "listen_address_in_use"}, {"connection refused", "connection_refused"}, {"network is unreachable", "network_unreachable"}, {"i/o timeout", "io_timeout"}, {"context deadline exceeded", "deadline_exceeded"}, {"no such host", "dns_name_not_found"}, {"certificate", "tls_certificate_error"}, {"handshake", "handshake_failed"}, {"no space left", "disk_full"}, {"invalid config", "invalid_configuration"}, {"failed to create new os thread", "core_thread_creation_failed"}, {"pthread_create failed", "core_thread_creation_failed"},
			{"no route to host", "network_unreachable"}, {"connection reset", "connection_reset"}, {"broken pipe", "connection_reset"}, {"unexpected eof", "connection_closed"}, {": eof", "connection_closed"},
			{"geoip", "geodata_unavailable"}, {"geosite", "geodata_unavailable"}, {"mmdb", "geodata_unavailable"},
			{"rule provider", "rule_provider_issue"}, {"rule-provider", "rule_provider_issue"}, {"ruleset", "rule_provider_issue"},
			{"proxy provider", "node_provider_issue"}, {"proxy-provider", "node_provider_issue"}, {"healthcheck", "node_health_check_failed"}, {"health check", "node_health_check_failed"},
			{"sniff", "sniffer_issue"}, {"[tun]", "core_tun_issue"}, {"tun device", "core_tun_issue"}, {"/dev/net/tun", "core_tun_issue"}, {"dial", "dial_failed"}, {"dns", "dns_query_failed"}} {
			if strings.Contains(line, x.needle) {
				reason = x.reason
				break
			}
		}
	}
	// A single connection failing at the target is ordinary traffic; it matters only when the
	// core itself is going down.
	if !fatal && connectionNoise[reason] {
		return
	}
	if fatal && reason != "core_diagnostic" {
		s.terminal = reason
	}
	detail := ""
	if reason == "permission_denied" {
		detail = deniedOperation(line)
	}
	s.r.LogDetail(source, level, reason, detail)
}

var (
	detailAddress = regexp.MustCompile(`\[[0-9a-f:.]+\](:\d+)?|\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b|\b[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}\b`)
	detailHost    = regexp.MustCompile(`\b[a-z0-9-]+(\.[a-z0-9-]+)+\.[a-z]{2,}\b`)
	detailPath    = regexp.MustCompile(`(/[^/\s:]+/[^/\s:]+)/[^\s:]+`)
	detailSafe    = regexp.MustCompile(`[^a-z0-9 _./:<>-]`)
)

// deniedOperation keeps the failing operation of a core permission error, such as
// "listen udp <addr>: bind" or "open /etc/openweir/...", without addresses, host
// names or deep paths.
func deniedOperation(line string) string {
	i := strings.Index(line, "permission denied")
	if i < 0 {
		i = strings.Index(line, "operation not permitted")
	}
	if i < 0 {
		return ""
	}
	parts := strings.Split(strings.TrimRight(line[:i], " :"), ": ")
	if len(parts) > 3 {
		parts = parts[len(parts)-3:]
	}
	op := strings.Join(parts, ": ")
	if j := strings.LastIndexAny(op, "=\""); j >= 0 {
		op = op[j+1:]
	}
	op = detailAddress.ReplaceAllString(op, "<addr>")
	op = detailHost.ReplaceAllString(op, "<host>")
	op = detailPath.ReplaceAllString(op, "$1/...")
	op = strings.TrimSpace(detailSafe.ReplaceAllString(op, ""))
	if len(op) > 96 {
		op = op[:96]
	}
	return op
}

func (r *Records) Observe(c control.Connection) {
	c = sliceConnection(c)
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.Created != 0 && c.Created <= r.minTime {
		return
	}
	if idx, ok := r.index[c.ID]; ok {
		old := r.connections[idx]
		if c.Created != 0 {
			old = c
		}
		if c.Closed != 0 {
			old.Closed = c.Closed
		}
		if c.Result == "traffic_observed" {
			old.Result = c.Result
		}
		r.connections[idx] = old
		return
	}
	if c.Created == 0 && c.Destination == "" {
		return
	}
	r.insertLocked(c)
}

// Record turns the connection records on or off with the running policy.
func (r *Records) Record(on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recording = on
}

// Failed keeps a connection the core could not open. A device retrying the same destination
// through the same outbound within a minute updates its last record instead of adding more.
func (r *Records) Failed(c control.Connection) {
	c = sliceConnection(c)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.recording {
		return
	}
	for k := range min(32, len(r.connections)) {
		j := (r.pos + len(r.connections) - 1 - k) % len(r.connections)
		old := &r.connections[j]
		if old.Result == "failed" && old.Source == c.Source && old.Destination == c.Destination && old.Outbound == c.Outbound && c.Created-old.Created <= 60000 {
			old.Closed = c.Closed
			return
		}
	}
	r.failures++
	c.ID = "failed:" + strconv.FormatUint(r.failures, 10)
	r.insertLocked(c)
}

func (r *Records) insertLocked(c control.Connection) {
	if set, ok := strings.CutPrefix(c.Rule, "RuleSet,"); ok && set != "" {
		hit := r.ruleHits[set]
		if hit == nil && len(r.ruleHits) < ruleHitLimit {
			hit = &RuleHit{}
			r.ruleHits[set] = hit
		}
		if hit != nil {
			hit.Count++
			hit.Last = max(hit.Last, c.Created)
		}
	}
	if len(r.connections) < recordLimit {
		r.index[c.ID] = len(r.connections)
		r.connections = append(r.connections, c)
	} else {
		delete(r.index, r.connections[r.pos].ID)
		r.index[c.ID] = r.pos
		r.connections[r.pos] = c
		r.pos = (r.pos + 1) % recordLimit
	}
}
func (r *Records) Page(kind string, offset, limit int) any {
	r.mu.Lock()
	defer r.mu.Unlock()
	limit = min(max(limit, 1), 100)
	offset = max(offset, 0)
	if kind == "logs" {
		out := []Event{}
		for j := len(r.events) - 1 - offset; j >= 0 && len(out) < limit; j-- {
			out = append(out, r.events[j])
		}
		return out
	}
	out := []control.Connection{}
	for j := len(r.connections) - 1 - offset; j >= 0 && len(out) < limit; j-- {
		out = append(out, r.connections[(j+r.pos)%len(r.connections)])
	}
	return out
}

// CoreStarted scopes the overview's routes to the core that just started. A different
// subscription also drops the rule set hit counts: its sets are other lists even when
// a name repeats. The connection history stays.
func (r *Records) CoreStarted(source string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routeSince = time.Now().UnixMilli()
	if source != r.source {
		r.ruleHits = map[string]*RuleHit{}
		r.source = source
	}
}

func (r *Records) Clear(kind string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if kind == "logs" {
		r.events = nil
	} else {
		r.minTime = time.Now().UnixMilli()
		r.connections = nil
		r.index = map[string]int{}
		r.ruleHits = map[string]*RuleHit{}
		r.pos = 0
	}
}
