package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeOps struct {
	calls      []string
	probeErrs  []error // consumed one per probe call; nil entries / exhausted = success
	probeCount int
	restored   map[string][]string // restore command -> rulesets, in order
}

func (f *fakeOps) ops() iptablesOps {
	f.restored = map[string][]string{}
	return iptablesOps{
		save: func(command string, args ...string) (string, error) {
			f.calls = append(f.calls, strings.TrimSpace(command+" "+strings.Join(args, " ")))
			return ":INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:DOCKER-USER - [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A DOCKER-USER -j RETURN\n-A FORWARD -j DOCKER-USER\n", nil
		},
		restore: func(command, ruleset string) error {
			f.calls = append(f.calls, command+" --noflush")
			f.restored[command] = append(f.restored[command], ruleset)
			return nil
		},
		prepare: func(c string) error { f.calls = append(f.calls, "prepare "+c); return nil },
		probe: func(appConfig) error {
			i := f.probeCount
			f.probeCount++
			if i < len(f.probeErrs) {
				return f.probeErrs[i]
			}
			return nil
		},
		sleep: func(time.Duration) {},
	}
}

var errDown = errors.New("configy down")

func TestApply_PreApplyProbeFails_NoChangeAtAll(t *testing.T) {
	f := &fakeOps{probeErrs: []error{errDown}}
	ok, err := applyWithRollback("v4", "v6", nil, appConfig{}, f.ops())
	if ok || err == nil {
		t.Fatalf("want not confirmed + error, got ok=%v err=%v", ok, err)
	}
	if len(f.calls) != 0 {
		t.Errorf("expected no iptables commands (no snapshot, apply or revert), got %v", f.calls)
	}
}

func TestApply_PostApplyProbeFails_RevertsToConfirmedViaNoflush(t *testing.T) {
	f := &fakeOps{probeErrs: []error{nil, errDown}}
	prev := &appliedState{ipv4: "prev4", ipv6: "prev6"}
	ok, err := applyWithRollback("new4", "new6", prev, appConfig{}, f.ops())
	if ok || err == nil {
		t.Fatalf("want revert, got ok=%v err=%v", ok, err)
	}
	if got := f.restored["iptables-restore"]; len(got) != 2 || got[0] != "new4" || got[1] != "prev4" {
		t.Errorf("iptables-restore sequence = %v, want [new4 prev4]", got)
	}
	if got := f.restored["ip6tables-restore"]; len(got) != 2 || got[0] != "new6" || got[1] != "prev6" {
		t.Errorf("ip6tables-restore sequence = %v, want [new6 prev6]", got)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "-save") {
			t.Errorf("no snapshot should be taken when a confirmed ruleset exists, saw %q", c)
		}
	}
}

func TestApply_FirstApplyRevert_UsesFilterOnlyOwnedChainSnapshot(t *testing.T) {
	f := &fakeOps{probeErrs: []error{nil, errDown}}
	ok, _ := applyWithRollback("new4", "new6", nil, appConfig{}, f.ops())
	if ok {
		t.Fatal("expected revert")
	}
	if f.calls[0] != "iptables-save -t filter" || f.calls[1] != "ip6tables-save -t filter" {
		t.Errorf("snapshots must be filter-table only, got %v", f.calls[:2])
	}
	for _, fam := range []string{"iptables-restore", "ip6tables-restore"} {
		got := f.restored[fam]
		reverted := got[len(got)-1]
		for _, line := range strings.Split(reverted, "\n") {
			if strings.HasPrefix(line, "*") && line != "*filter" {
				t.Errorf("%s revert touches non-filter table: %q", fam, line)
			}
			if strings.HasPrefix(line, ":") && !strings.HasPrefix(line, ":INPUT ") && !strings.HasPrefix(line, ":DOCKER-USER ") {
				t.Errorf("%s revert declares non-owned chain: %q", fam, line)
			}
			if strings.HasPrefix(line, "-A ") && !strings.HasPrefix(line, "-A INPUT ") && !strings.HasPrefix(line, "-A DOCKER-USER ") {
				t.Errorf("%s revert adds rule to non-owned chain: %q", fam, line)
			}
		}
		if !strings.Contains(reverted, "-A INPUT -p tcp --dport 22 -j ACCEPT") || !strings.HasSuffix(reverted, "COMMIT\n") {
			t.Errorf("%s revert lost INPUT rules or COMMIT: %q", fam, reverted)
		}
	}
}

func TestApply_AllRestoresAreNoflush(t *testing.T) {
	for _, probeErrs := range [][]error{nil, {nil, errDown}} {
		f := &fakeOps{probeErrs: probeErrs}
		applyWithRollback("a", "b", nil, appConfig{}, f.ops())
		for _, c := range f.calls {
			if strings.HasSuffix(c, "-restore --noflush") || !strings.Contains(c, "-restore") {
				continue
			}
			t.Errorf("restore without --noflush: %q", c)
		}
	}
}

func TestApply_Success_Confirms(t *testing.T) {
	f := &fakeOps{}
	ok, err := applyWithRollback("new4", "new6", nil, appConfig{}, f.ops())
	if !ok || err != nil {
		t.Fatalf("want confirmed, got ok=%v err=%v", ok, err)
	}
	if len(f.restored["iptables-restore"]) != 1 {
		t.Errorf("success path must not revert, got %v", f.restored)
	}
}

func TestApply_RestoreFailure_RevertsOwnedChains(t *testing.T) {
	f := &fakeOps{}
	o := f.ops()
	n := 0
	inner := o.restore
	o.restore = func(c, r string) error {
		n++
		if n == 2 { // ip6tables apply fails
			return fmt.Errorf("boom")
		}
		return inner(c, r)
	}
	ok, err := applyWithRollback("new4", "new6", &appliedState{ipv4: "p4", ipv6: "p6"}, appConfig{}, o)
	if ok || err == nil {
		t.Fatal("expected failure")
	}
	if got := f.restored["iptables-restore"]; got[len(got)-1] != "p4" {
		t.Errorf("IPv4 not reverted to confirmed ruleset: %v", got)
	}
}

func TestOwnedChainsSnapshot_PolicyAndRules(t *testing.T) {
	got := ownedChainsSnapshot(":INPUT ACCEPT [1:2]\n:FORWARD DROP [0:0]\n-A FORWARD -j DOCKER\n-A INPUT -i lo -j ACCEPT\n-A DOCKER-USER -j RETURN\nCOMMIT\n")
	want := "*filter\n:INPUT ACCEPT [0:0]\n:DOCKER-USER - [0:0]\n-A INPUT -i lo -j ACCEPT\n-A DOCKER-USER -j RETURN\nCOMMIT\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestResolveFailedFetchPorts_HoldsConfirmed_NoRulesetChange(t *testing.T) {
	ports := []PublicPort{{System: "a", Port: 80, Protocol: "tcp"}}
	conf := &appliedState{ports: ports, at: time.Now().Add(-time.Hour)}
	conf.ipv4, conf.ipv6 = generateIPv4Ruleset(ports), generateIPv6Ruleset(ports)
	held := resolveFailedFetchPorts(conf)
	if hashString(generateIPv4Ruleset(held)) != hashString(conf.ipv4) || hashString(generateIPv6Ruleset(held)) != hashString(conf.ipv6) {
		t.Error("held ports must regenerate the identical confirmed ruleset (so the loop skips apply)")
	}
}

func TestResolveFailedFetchPorts_ColdStartIsNilFallback(t *testing.T) {
	if got := resolveFailedFetchPorts(nil); got != nil {
		t.Errorf("want nil fallback on cold start, got %v", got)
	}
}

func TestDegradedTracker_UnreachableThreshold(t *testing.T) {
	var d degradedTracker
	for i := 1; i < degradedUnreachablePolls; i++ {
		d.record(true, false)
		if d.reason() != "" {
			t.Fatalf("degraded after only %d unreachable polls", i)
		}
	}
	d.record(true, false)
	if !strings.Contains(d.reason(), "configy unreachable") {
		t.Errorf("want unreachable reason at threshold, got %q", d.reason())
	}
}

func TestDegradedTracker_RevertThreshold(t *testing.T) {
	var d degradedTracker
	for i := 1; i < degradedRevertPolls; i++ {
		d.record(false, true)
	}
	if d.reason() != "" {
		t.Fatalf("degraded after only %d reverts: %q", degradedRevertPolls-1, d.reason())
	}
	d.record(false, true)
	if !strings.Contains(d.reason(), "reverted") {
		t.Errorf("want revert reason at threshold, got %q", d.reason())
	}
}

func TestDegradedTracker_SingleRevertThenConfirmDoesNotDegrade(t *testing.T) {
	var d degradedTracker
	d.record(false, true)
	d.record(false, false)
	d.record(false, true)
	d.record(false, true)
	if d.reason() != "" {
		t.Errorf("non-consecutive reverts must not degrade, got %q", d.reason())
	}
}

func TestDegradedTracker_ClearsOnFirstGoodPoll(t *testing.T) {
	var d degradedTracker
	for i := 0; i < degradedUnreachablePolls; i++ {
		d.record(true, false)
	}
	d.record(false, false)
	if d.reason() != "" {
		t.Errorf("want cleared, got %q", d.reason())
	}
}

func TestDegradedTracker_UnreachablePollKeepsRevertStreak(t *testing.T) {
	var d degradedTracker
	d.record(false, true)
	d.record(false, true)
	d.record(true, false)
	d.record(false, true)
	if !strings.Contains(d.reason(), "reverted") {
		t.Errorf("revert streak should survive an unreachable poll, got %q", d.reason())
	}
}

func TestApply_ErrorClassification(t *testing.T) {
	f := &fakeOps{probeErrs: []error{errDown}}
	_, err := applyWithRollback("a", "b", nil, appConfig{}, f.ops())
	if !errors.Is(err, errUnreachableBeforeApply) || errors.Is(err, errReverted) {
		t.Errorf("pre-apply failure misclassified: %v", err)
	}
	f = &fakeOps{probeErrs: []error{nil, errDown}}
	_, err = applyWithRollback("a", "b", nil, appConfig{}, f.ops())
	if !errors.Is(err, errReverted) || errors.Is(err, errUnreachableBeforeApply) {
		t.Errorf("post-apply failure misclassified: %v", err)
	}
}
