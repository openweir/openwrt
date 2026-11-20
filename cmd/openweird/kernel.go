package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openweir/openwrt/internal/kernel"
	"os"
	"strconv"
	"time"
)

func kernelStatus(ctx context.Context) (kernel.Status, error) {
	var st kernel.Status
	data, e := child(ctx, "openweir-kernel", []string{"status"}, nil)
	if e == nil {
		e = json.Unmarshal(data, &st)
	}
	return st, e
}

// Downloading is separate from selecting. A slow install that loses its
// revision leaves a checked, staged asset available for a later explicit choice.
func (s *app) kernelJob(r request) (any, error) {
	if r.Action != "install-json" && r.Action != "select" && r.Action != "rollback" {
		return nil, errors.New("unknown kernel operation")
	}
	initial, _, _, e := s.m.ReviewToken("")
	if e != nil {
		return nil, e
	}
	var args map[string]json.RawMessage
	if len(r.Args) != 0 && json.Unmarshal(r.Args, &args) != nil {
		return nil, errors.New("invalid kernel request")
	}
	var tag string
	if r.Action != "rollback" && (json.Unmarshal(args["tag"], &tag) != nil || !kernel.TagPattern.MatchString(tag)) {
		return nil, errors.New("invalid version")
	}
	bundle, e := checkKernelArgs(r.Action, args)
	if e != nil {
		return nil, e
	}
	return s.runJob("kernel_write", "kernel/"+r.Action, func(ctx context.Context) (json.RawMessage, error) {
		if e := s.yieldFirstKernel(ctx); e != nil {
			return nil, e
		}
		if bundle != "" {
			defer os.RemoveAll(bundle)
		}
		if r.Action == "install-json" {
			args["stage_only"] = json.RawMessage("true")
			body, e := json.Marshal(args)
			if e != nil {
				return nil, e
			}
			if _, e = child(ctx, "openweir-kernel", []string{"install-json"}, body); e != nil {
				return nil, e
			}
		}
		st, e := kernelStatus(ctx)
		if e != nil {
			return nil, e
		}
		if r.Action == "rollback" {
			tag = st.Previous
			if tag == "" {
				return nil, errors.New("no retained version available")
			}
		}
		token, intent, _, e := s.m.ReviewToken("")
		if e != nil {
			return nil, e
		}
		if token != initial {
			return nil, errors.New("router intent changed; version was not selected")
		}
		if intent.Source != "" {
			if e := s.sys.Preflight(ctx, intent, nil, tag); e != nil {
				return nil, e
			}
		} else if intent.Enabled && intent.Mode != "direct" {
			return nil, errors.New("missing primary source for candidate validation")
		}
		phase, _, _ := s.m.RuntimeState()
		reload := intent.Enabled && intent.Mode != "direct" && (st.Selected != tag || st.Active != tag || phase != "running")
		e = s.m.SelectReviewed(initial, reload, func() error {
			cli := []string{"select", "--tag", tag, "--expected", strconv.FormatUint(st.Revision, 10)}
			_, e := child(ctx, "openweir-kernel", cli, nil)
			return e
		})
		if e != nil {
			return nil, e
		}
		if reload {
			if e := waitForKernel(ctx, tag, st.Active, s.m.RuntimeState, kernelStatus); e != nil {
				return nil, e
			}
		}
		out, _ := json.Marshal(map[string]string{"selected": tag})
		return out, nil
	})
}

// A selected tag is only a saved preference. A running change finishes when
// the supervisor confirms the healthy core, or restores the confirmed release.
func waitForKernel(ctx context.Context, tag, previous string, service func() (string, string, bool), status func(context.Context) (kernel.Status, error)) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		phase, problem, wantsProxy := service()
		if !wantsProxy {
			return errors.New("service stopped before the kernel change was confirmed")
		}
		switch phase {
		case "running", "fail_open", "protected", "release_failed":
			st, e := status(ctx)
			if e != nil {
				return e
			}
			if st.Pending {
				continue
			}
			if phase == "running" && st.Selected == tag && st.Active == tag {
				return nil
			}
			if phase == "running" && previous != "" && st.Selected == previous && st.Active == previous {
				return fmt.Errorf("candidate failed startup or health checks; previous kernel %s is running", previous)
			}
			if phase == "release_failed" || phase != "running" && (previous == "" || st.Selected == tag) {
				return fmt.Errorf("kernel change unconfirmed: %s", problem)
			}
		}
	}
}
