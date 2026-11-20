package router

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrialRequiresContinuousHealthAndIndependentHeartbeats(t *testing.T) {
	var checks, pulses atomic.Int32
	var bad time.Time
	start := time.Now()
	c, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	e := confirmWindow(c, 40*time.Millisecond, 10*time.Millisecond, 2*time.Millisecond, func(context.Context) error {
		if checks.Add(1) == 3 {
			bad = time.Now()
			return errors.New("LAN path lost")
		}
		return nil
	}, func(context.Context) error { pulses.Add(1); return nil })
	if e != nil || bad.IsZero() || time.Since(bad) < 40*time.Millisecond || pulses.Load() <= checks.Load() || time.Since(start) > time.Second {
		t.Fatal(e, checks.Load(), pulses.Load())
	}
}
func TestTrialCancellationAndFailedFirstRead(t *testing.T) {
	c, end := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer end()
	down := errors.New("core offline")
	check := func(context.Context) error { return down }
	beat := func(context.Context) error { return down }
	err := confirmWindow(c, time.Second, 5*time.Millisecond, time.Millisecond, check, beat)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, down) {
		t.Fatal("missing timeout or last failed check", err)
	}
	if !errors.Is(confirmWindow(context.Background(), 0, time.Second, time.Second, check, beat), down) {
		t.Fatal("active launch hid failed health")
	}
}

func TestSlowInitialFullProbeKeepsHeartbeatingBeforeWindowBegins(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var count atomic.Int32
	pulsed := make(chan struct{})
	beat := func(context.Context) error {
		if count.Add(1) == 3 {
			close(pulsed)
		}
		return nil
	}
	var first time.Time
	full := func(ctx context.Context) error {
		if first.IsZero() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-pulsed:
				first = time.Now()
			}
		}
		return nil
	}
	window := 25 * time.Millisecond
	if err := confirmWindow(ctx, window, 4*time.Millisecond, 2*time.Millisecond, full, beat); err != nil {
		t.Fatal(err)
	}
	if first.IsZero() || time.Since(first) < window {
		t.Fatal("incomplete health window")
	}
}

func TestLostLocalHeartbeatRestartsFullHealthWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var checks int
	requestFailure := make(chan struct{}, 1)
	failedAt := make(chan time.Time, 1)
	var failure time.Time
	full := func(ctx context.Context) error {
		checks++
		if checks == 3 {
			requestFailure <- struct{}{}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case failure = <-failedAt:
			}
		}
		return nil
	}
	beat := func(context.Context) error {
		select {
		case <-requestFailure:
			failedAt <- time.Now()
			return errors.New("local control unavailable")
		default:
			return nil
		}
	}
	window := 35 * time.Millisecond
	if err := confirmWindow(ctx, window, 6*time.Millisecond, time.Millisecond, full, beat); err != nil {
		t.Fatal(err)
	}
	if failure.IsZero() || time.Since(failure) < window {
		t.Fatal("kernel confirmed without a new continuous window")
	}
}

func TestStartupReadinessKeepsLastCompletedProbeOnTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	dns := errors.New("local core DNS answer unavailable")
	first := true
	ready := func(ctx context.Context) error {
		if first {
			first = false
			return dns
		}
		<-ctx.Done()
		return errors.New("control query canceled during shutdown")
	}
	if err := waitCoreReady(ctx, make(chan struct{}), time.Millisecond, ready); !errors.Is(err, dns) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("missing startup timeout or underlying DNS failure", err)
	}

}
func TestInterfacePrefixesUseRouterAddressIncludingDelegatedIPv6(t *testing.T) {
	var n netifStatus
	n.Up = true
	n.Device = "br-guest.20"
	n.V4 = []netifAddress{{"192.168.5.1", 24}}
	n.Delegated = append(n.Delegated, struct {
		Local netifAddress `json:"local-address"`
	}{netifAddress{"fd00:20::1", 64}})
	p, e := interfacePrefixes(n)
	if e != nil || len(p) != 2 || p[0].String() != "192.168.5.1/24" || p[1].String() != "fd00:20::1/64" {
		t.Fatal(p, e)
	}
	n.Up = false
	if _, e = interfacePrefixes(n); e == nil {
		t.Fatal("accepted offline LAN")
	}
}
