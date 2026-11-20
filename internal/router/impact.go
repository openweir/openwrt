package router

import (
	"context"
	"errors"
	"github.com/openweir/openwrt/internal/kernel"
	"github.com/openweir/openwrt/internal/subscription"
	"slices"
	"strconv"
)

type Issue struct {
	Kind   string `json:"kind"`
	Object string `json:"object"`
	Reason string `json:"reason"`
}

func (i Issue) Error() string {
	if i.Object == "" {
		return i.Reason
	}
	return i.Object + ": " + i.Reason
}

func incompatible(n subscription.Node, c kernel.TargetCapabilities) string {
	if key := n.CapabilityKey(); c.Control == kernel.Controller && subscription.CapabilityAvailability(key, &c.Naive, c.ProtocolSupport) == "unsupported" {
		return "this device release does not support " + key
	}

	return ""
}

type Impact struct {
	Tag          string  `json:"tag"`
	Target       string  `json:"target"`
	Issues       []Issue `json:"issues"`
	CanCompile   bool    `json:"can_compile"`
	Unconfigured bool    `json:"unconfigured,omitempty"`
}

func (s *System) Impact(ctx context.Context, i Intent, tag string) (Impact, error) {
	var status kernel.Status
	var caps kernel.Capabilities
	if tag != "" && !kernel.TagPattern.MatchString(tag) {
		return Impact{}, errors.New("invalid version")
	}
	if e := jsonCmd(ctx, &status, kernelCLI, "status"); e != nil {
		return Impact{}, e
	}
	if tag == "" {
		tag = status.Selected
	}
	if e := jsonCmd(ctx, &caps, kernelCLI, "capabilities", "--tag", tag); e != nil {
		return Impact{}, e
	}
	c, ok := caps.Targets[status.Target]
	if !ok || caps.Tag != tag || caps.Repository != kernel.Repository {
		return Impact{}, errors.New("capability information does not match this target")
	}
	res := Impact{Tag: tag, Target: status.Target, Issues: []Issue{}}
	if i.Source == "" && (!i.Enabled || i.Mode == "direct") {
		res.Unconfigured = true
		return res, nil
	}
	if i.Mode == "direct" {
		i.Mode = "smart"
	}
	p, e := LoadProfile(i, subscription.OpenStore(Root+"/sources"))
	if e != nil {
		return res, e
	}
	unavailable := map[string]bool{}
	for _, n := range p.Nodes {
		if reason := incompatible(n, c); !n.Special && reason != "" {
			unavailable[n.ID] = true
			res.Issues = append(res.Issues, Issue{"node", n.ID, reason})
		}
	}
	network, e := networkOptions(ctx)
	if e != nil {
		return res, e
	}
	e = checkProfile(ctx, i, p, c, network, tag)
	res.CanCompile = e == nil
	if e != nil {
		var issue Issue
		if !errors.As(e, &issue) {
			issue = Issue{"configuration", i.Source, e.Error()}
		}
		if issue.Kind == "node" || issue.Kind == "group" {
			unavailable[issue.Object] = true
		}
		if !slices.Contains(res.Issues, issue) {
			res.Issues = append(res.Issues, issue)
		}
	}
	// Propagate unsupported members to their dependants. Import rejects group cycles.
	groups := append([]subscription.Group{}, p.Groups...)
	for _, g := range i.Policy.Groups {
		x := subscription.Group{ID: g.ID}
		for _, ref := range g.Members {
			x.Members = append(x.Members, ref.ID)
		}
		groups = append(groups, x)
	}
	for changed := true; changed; {
		changed = false
		for _, g := range groups {
			if unavailable[g.ID] {
				continue
			}
			wanted := i.Choices[i.Source][g.ID]
			if unavailable[wanted] || !slices.ContainsFunc(g.Members, func(member string) bool { return !unavailable[member] }) {
				unavailable[g.ID] = true
				res.Issues = append(res.Issues, Issue{"group", g.ID, "selected member or all members unavailable"})
				changed = true
			}
		}
	}
	for n, r := range p.Rules {
		if unavailable[r.Target] {
			res.Issues = append(res.Issues, Issue{"subscription_rule", strconv.Itoa(n + 1), "unavailable target"})
		}
	}
	for _, r := range i.Policy.Rules {
		if (r.Enabled == nil || *r.Enabled) && unavailable[r.Target] {
			res.Issues = append(res.Issues, Issue{"custom_rule", r.ID, "unavailable target"})
		}
	}
	for _, d := range i.Policy.Devices {
		if unavailable[d.Target] {
			res.Issues = append(res.Issues, Issue{"device", d.Address, "unavailable target"})
		}
	}
	return res, nil
}
