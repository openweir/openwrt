package main

import (
	"context"
	"testing"
	"time"

	"github.com/openweir/openwrt/internal/subscription"
	"github.com/openweir/openwrt/internal/tlsdiag"
)

func TestScheduledRefreshWaitsForFirstManualImport(t *testing.T) {
	now := time.Now().UTC()
	st := subscription.Status{Kind: "external", UpdatedAt: now.Add(-2 * time.Hour).Format(time.RFC3339)}
	if dueForRefresh(st, now, time.Time{}, time.Hour) {
		t.Fatal("scheduled an unimported source")
	}
	st.Ready = true
	if !dueForRefresh(st, now, time.Time{}, time.Hour) {
		t.Fatal("skipped a previously imported, due source")
	}
	st.UpdatedAt = now.Format(time.RFC3339)
	if dueForRefresh(st, now, time.Time{}, time.Hour) {
		t.Fatal("scheduled a recently updated source")
	}
}

func TestMigrateRemoteSourceEvenWithAutomaticUpdatesDisabled(t *testing.T) {
	now := time.Now()
	src := subscription.Status{Kind: "external", NeedsRefresh: true}
	if !dueForRefresh(src, now, time.Time{}, 0) || dueForRefresh(src, now, now.Add(-time.Minute), 0) {
		t.Fatal("migration must refresh a remote snapshot with bounded retries")
	}
	src.Kind = "file"
	if dueForRefresh(src, now, time.Time{}, 0) {
		t.Fatal("local file needs manual reimport")
	}
}

func TestManualRefreshPreemptsOnlySameSource(t *testing.T) {
	var work refreshWork
	parent := context.Background()
	scheduled, _, finishScheduled, err := work.acquire(parent, "a", true)
	if err != nil {
		t.Fatal(err)
	}
	manual, wait, finishManual, err := work.acquire(parent, "a", false)
	if err != nil || wait == nil || scheduled.Err() == nil || manual.Err() != nil {
		t.Fatal("manual refresh did not preempt the same source")
	}
	if _, _, _, err = work.acquire(parent, "a", true); err == nil {
		t.Fatal("scheduler superseded active work")
	}
	other, waitOther, finishOther, err := work.acquire(parent, "b", true)
	if err != nil || waitOther != nil || other.Err() != nil {
		t.Fatal("unrelated source blocked")
	}
	finishOther()
	select {
	case <-wait:
		t.Fatal("new helper could run before the previous helper exited")
	default:
	}
	finishScheduled()
	select {
	case <-wait:
	default:
		t.Fatal("manual refresh still waiting for a completed helper")
	}
	if _, _, _, err = work.acquire(parent, "a", true); err == nil {
		t.Fatal("scheduled refresh superseded manual refresh")
	}
	finishManual()
	if len(work.bySource) != 0 {
		t.Fatal("completed state retained")
	}
}

func TestClockChangeRepairsFutureScheduleWithoutFlooding(t *testing.T) {
	now := time.Now()
	src := subscription.Status{Kind: "external", Ready: true, UpdatedAt: now.Add(time.Hour * 24).Format(time.RFC3339)}
	if !dueForRefresh(src, now, time.Time{}, time.Hour) || dueForRefresh(src, now, now.Add(-time.Minute), time.Hour) || dueForRefresh(src, now, time.Time{}, 0) {
		t.Fatal("clock rollback should allow one refresh respecting backoff and settings")
	}
	src.RetryAfterClock = true
	src.Ready = false
	src.LastTLS = &tlsdiag.Diagnostic{Reason: "not_yet_valid", CheckedAt: now.Add(-time.Hour * 24), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if !recoveredClock(src, now) || recoveredClock(src, now.Add(-24*time.Hour)) {
		t.Fatal("invalid initial-import retry")
	}
	src.LoginRequired = true
	if recoveredClock(src, now) {
		t.Fatal("retried after login expired")
	}
}
