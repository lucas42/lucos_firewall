package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── resolveEnforceMode unit tests ─────────────────────────────────────────────

func boolPtr(b bool) *bool { return &b }

func TestResolveEnforceMode_ColdStartFetchOK_EnforceTrue(t *testing.T) {
	// Configy returns firewall_enforce: true; no last-known-good yet.
	// Should enter enforce mode and record it as last-known-good.
	dryRun, last := resolveEnforceMode(nil, true, nil, false)
	if dryRun {
		t.Error("expected enforce mode (dryRun=false), got dry-run")
	}
	if last == nil || !*last {
		t.Error("expected last-known-good to be set to true")
	}
}

func TestResolveEnforceMode_ColdStartFetchOK_EnforceFalse(t *testing.T) {
	// Configy returns firewall_enforce: false; no last-known-good yet.
	// Should remain in dry-run mode.
	dryRun, last := resolveEnforceMode(nil, false, nil, false)
	if !dryRun {
		t.Error("expected dry-run mode, got enforce")
	}
	if last == nil || *last {
		t.Error("expected last-known-good to be set to false")
	}
}

func TestResolveEnforceMode_ColdStartFetchFailed(t *testing.T) {
	// Configy unreachable at cold start; no last-known-good.
	// Should default to dry-run and leave last-known-good as nil.
	fetchErr := fmt.Errorf("connection refused")
	dryRun, last := resolveEnforceMode(fetchErr, false, nil, false)
	if !dryRun {
		t.Error("expected dry-run on cold start with configy unreachable")
	}
	if last != nil {
		t.Error("expected last-known-good to remain nil on cold-start failure")
	}
}

func TestResolveEnforceMode_BlipAfterEnforce(t *testing.T) {
	// We were in enforce mode; configy blips. Should hold enforce (last-known-good).
	lastKnown := boolPtr(true)
	fetchErr := fmt.Errorf("timeout")
	dryRun, last := resolveEnforceMode(fetchErr, false, lastKnown, false)
	if dryRun {
		t.Error("expected enforce mode (last-known-good=true), got dry-run during blip")
	}
	if last == nil || !*last {
		t.Error("expected last-known-good to remain true during blip")
	}
}

func TestResolveEnforceMode_BlipAfterDryRun(t *testing.T) {
	// We were in dry-run mode; configy blips. Should hold dry-run (last-known-good).
	lastKnown := boolPtr(false)
	fetchErr := fmt.Errorf("timeout")
	dryRun, last := resolveEnforceMode(fetchErr, false, lastKnown, false)
	if !dryRun {
		t.Error("expected dry-run (last-known-good=false), got enforce during blip")
	}
	if last == nil || *last {
		t.Error("expected last-known-good to remain false during blip")
	}
}

func TestResolveEnforceMode_DryRunOverride_BeatsConfigyEnforce(t *testing.T) {
	// DRY_RUN override is active; configy returns firewall_enforce: true.
	// Override must win — should stay dry-run.
	dryRun, last := resolveEnforceMode(nil, true, nil, true)
	if !dryRun {
		t.Error("expected dry-run: DRY_RUN override must beat configy enforce=true")
	}
	// last-known-good is still updated so when override is removed we recover correctly
	if last == nil || !*last {
		t.Error("expected last-known-good to be updated even when override is active")
	}
}

func TestResolveEnforceMode_DryRunOverride_DuringBlip(t *testing.T) {
	// DRY_RUN override active; configy blips; last-known-good was enforce.
	// Override must win — should stay dry-run.
	lastKnown := boolPtr(true)
	fetchErr := fmt.Errorf("timeout")
	dryRun, _ := resolveEnforceMode(fetchErr, false, lastKnown, true)
	if !dryRun {
		t.Error("expected dry-run: DRY_RUN override must beat last-known-good enforce")
	}
}

func TestResolveEnforceMode_TransitionEnforceToDryRun(t *testing.T) {
	// Host was enforce; configy now returns false. Should switch to dry-run.
	lastKnown := boolPtr(true)
	dryRun, last := resolveEnforceMode(nil, false, lastKnown, false)
	if !dryRun {
		t.Error("expected dry-run after configy flipped firewall_enforce to false")
	}
	if last == nil || *last {
		t.Error("expected last-known-good to be updated to false")
	}
}

// ── fetchEnforceMode HTTP tests ───────────────────────────────────────────────

func cfgWithServer(server *httptest.Server, hostname string) appConfig {
	return appConfig{
		hostname:      hostname,
		configyOrigin: server.URL,
	}
}

func TestFetchEnforceMode_EnforceTrue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hosts/testhost" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(HostConfig{FirewallEnforce: true})
	}))
	defer srv.Close()

	enforce, err := fetchEnforceMode(cfgWithServer(srv, "testhost"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !enforce {
		t.Error("expected enforce=true, got false")
	}
}

func TestFetchEnforceMode_EnforceFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(HostConfig{FirewallEnforce: false})
	}))
	defer srv.Close()

	enforce, err := fetchEnforceMode(cfgWithServer(srv, "testhost"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enforce {
		t.Error("expected enforce=false, got true")
	}
}

func TestFetchEnforceMode_HostNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// 404 should be treated as firewall_enforce: false (dry-run default), not an error.
	enforce, err := fetchEnforceMode(cfgWithServer(srv, "unknownhost"))
	if err != nil {
		t.Fatalf("expected no error for 404 (dry-run default), got: %v", err)
	}
	if enforce {
		t.Error("expected enforce=false for 404 response")
	}
}

func TestFetchEnforceMode_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := fetchEnforceMode(cfgWithServer(srv, "testhost"))
	if err == nil {
		t.Error("expected error for HTTP 500 response")
	}
}

func TestFetchEnforceMode_Unreachable(t *testing.T) {
	cfg := appConfig{
		hostname:      "testhost",
		configyOrigin: "http://127.0.0.1:1", // nothing listening
	}
	_, err := fetchEnforceMode(cfg)
	if err == nil {
		t.Error("expected error for unreachable configy")
	}
}

func TestFetchEnforceMode_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-json{{{"))
	}))
	defer srv.Close()

	_, err := fetchEnforceMode(cfgWithServer(srv, "testhost"))
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

// ── generateIPv4Ruleset / generateIPv6Ruleset ruleset tests ──────────────────

// assertBridgeReturnBeforeDrop verifies that the DOCKER-USER chain in the given
// ruleset contains RETURN rules for br+ and docker0 interfaces, and that both
// appear before the terminal DROP rule.
func assertBridgeReturnBeforeDrop(t *testing.T, ruleset, label string) {
	t.Helper()
	brPlus := "-A DOCKER-USER -i br+ -j RETURN"
	docker0 := "-A DOCKER-USER -i docker0 -j RETURN"
	drop := "-A DOCKER-USER -j DROP"

	brPlusIdx := strings.Index(ruleset, brPlus)
	docker0Idx := strings.Index(ruleset, docker0)
	dropIdx := strings.Index(ruleset, drop)

	if brPlusIdx < 0 {
		t.Errorf("%s: expected %q in DOCKER-USER chain", label, brPlus)
	}
	if docker0Idx < 0 {
		t.Errorf("%s: expected %q in DOCKER-USER chain", label, docker0)
	}
	if dropIdx < 0 {
		t.Errorf("%s: expected %q in DOCKER-USER chain", label, drop)
		return // ordering checks below require drop to be present
	}
	if brPlusIdx >= 0 && brPlusIdx > dropIdx {
		t.Errorf("%s: %q must appear before %q", label, brPlus, drop)
	}
	if docker0Idx >= 0 && docker0Idx > dropIdx {
		t.Errorf("%s: %q must appear before %q", label, docker0, drop)
	}
}

// assertMDNSPresent verifies that the mDNS allow rule for the given destination
// multicast address is present in the ruleset's INPUT chain.
func assertMDNSPresent(t *testing.T, ruleset, dest, label string) {
	t.Helper()
	rule := fmt.Sprintf("-A INPUT -d %s -p udp --dport 5353 -j ACCEPT", dest)
	if !strings.Contains(ruleset, rule) {
		t.Errorf("%s: expected mDNS rule %q in INPUT chain", label, rule)
	}
}

func TestGenerateIPv4Ruleset_MDNSPresent_NoPorts(t *testing.T) {
	assertMDNSPresent(t, generateIPv4Ruleset(nil), "224.0.0.251", "IPv4 (no ports)")
}

func TestGenerateIPv4Ruleset_MDNSPresent_WithPorts(t *testing.T) {
	ports := []PublicPort{{Protocol: "tcp", Port: 443}}
	assertMDNSPresent(t, generateIPv4Ruleset(ports), "224.0.0.251", "IPv4 (with ports)")
}

func TestGenerateIPv6Ruleset_MDNSPresent_NoPorts(t *testing.T) {
	assertMDNSPresent(t, generateIPv6Ruleset(nil), "ff02::fb", "IPv6 (no ports)")
}

func TestGenerateIPv6Ruleset_MDNSPresent_WithPorts(t *testing.T) {
	ports := []PublicPort{{Protocol: "tcp", Port: 443}}
	assertMDNSPresent(t, generateIPv6Ruleset(ports), "ff02::fb", "IPv6 (with ports)")
}

// ── empty-ports comment tests ─────────────────────────────────────────────────
//
// The generator receives nil (configy unreachable → fallback) or a non-nil
// empty slice (configy reachable, zero ports declared → healthy steady state).
// These tests assert each path emits its own distinct comment.

func TestGenerateIPv4Ruleset_FallbackComment_NilPorts(t *testing.T) {
	ruleset := generateIPv4Ruleset(nil)
	if !strings.Contains(ruleset, "fallback — configy unreachable") {
		t.Error("IPv4 nil-ports: expected fallback comment (configy unreachable)")
	}
	if strings.Contains(ruleset, "No service ports declared for this host") {
		t.Error("IPv4 nil-ports: must not emit healthy-zero-ports comment for fallback path")
	}
}

func TestGenerateIPv4Ruleset_HealthyZeroPortsComment_EmptySlice(t *testing.T) {
	ruleset := generateIPv4Ruleset([]PublicPort{})
	if !strings.Contains(ruleset, "No service ports declared for this host") {
		t.Error("IPv4 empty-slice: expected healthy-zero-ports comment")
	}
	if strings.Contains(ruleset, "configy unreachable") {
		t.Error("IPv4 empty-slice: must not emit fallback/unreachable comment for healthy zero-ports path")
	}
}

func TestGenerateIPv6Ruleset_FallbackComment_NilPorts(t *testing.T) {
	ruleset := generateIPv6Ruleset(nil)
	if !strings.Contains(ruleset, "fallback — configy unreachable") {
		t.Error("IPv6 nil-ports: expected fallback comment (configy unreachable)")
	}
	if strings.Contains(ruleset, "No service ports declared for this host") {
		t.Error("IPv6 nil-ports: must not emit healthy-zero-ports comment for fallback path")
	}
}

func TestGenerateIPv6Ruleset_HealthyZeroPortsComment_EmptySlice(t *testing.T) {
	ruleset := generateIPv6Ruleset([]PublicPort{})
	if !strings.Contains(ruleset, "No service ports declared for this host") {
		t.Error("IPv6 empty-slice: expected healthy-zero-ports comment")
	}
	if strings.Contains(ruleset, "configy unreachable") {
		t.Error("IPv6 empty-slice: must not emit fallback/unreachable comment for healthy zero-ports path")
	}
}

// ── FORWARD-chain absent tests ────────────────────────────────────────────────
//
// Since we switched to --noflush, FORWARD must NOT be declared in the generated
// ruleset. Docker owns FORWARD; whole-table restore would delete Docker's chains
// (DOCKER-FORWARD, DOCKER-ISOLATION-*) causing docker network create to fail.
// The FORWARD → DOCKER-USER jump is now managed by prepareChains at apply time.

func TestGenerateIPv4Ruleset_NoFORWARDChain(t *testing.T) {
	for _, label := range []string{"nil ports", "empty ports", "with ports"} {
		var ports []PublicPort
		switch label {
		case "empty ports":
			ports = []PublicPort{}
		case "with ports":
			ports = []PublicPort{{Protocol: "tcp", Port: 443}}
		}
		ruleset := generateIPv4Ruleset(ports)
		if strings.Contains(ruleset, ":FORWARD") {
			t.Errorf("IPv4 (%s): generated ruleset must not declare :FORWARD chain", label)
		}
		if strings.Contains(ruleset, "-A FORWARD") {
			t.Errorf("IPv4 (%s): generated ruleset must not append rules to FORWARD chain", label)
		}
	}
}

func TestGenerateIPv6Ruleset_NoFORWARDChain(t *testing.T) {
	for _, label := range []string{"nil ports", "empty ports", "with ports"} {
		var ports []PublicPort
		switch label {
		case "empty ports":
			ports = []PublicPort{}
		case "with ports":
			ports = []PublicPort{{Protocol: "tcp", Port: 443}}
		}
		ruleset := generateIPv6Ruleset(ports)
		if strings.Contains(ruleset, ":FORWARD") {
			t.Errorf("IPv6 (%s): generated ruleset must not declare :FORWARD chain", label)
		}
		if strings.Contains(ruleset, "-A FORWARD") {
			t.Errorf("IPv6 (%s): generated ruleset must not append rules to FORWARD chain", label)
		}
	}
}

func TestGenerateIPv4Ruleset_BridgeReturnBeforeDrop_NoPorts(t *testing.T) {
	assertBridgeReturnBeforeDrop(t, generateIPv4Ruleset(nil), "IPv4 (no ports)")
}

func TestGenerateIPv4Ruleset_BridgeReturnBeforeDrop_WithPorts(t *testing.T) {
	ports := []PublicPort{{Protocol: "tcp", Port: 443}}
	assertBridgeReturnBeforeDrop(t, generateIPv4Ruleset(ports), "IPv4 (with ports)")
}

func TestGenerateIPv6Ruleset_BridgeReturnBeforeDrop_NoPorts(t *testing.T) {
	assertBridgeReturnBeforeDrop(t, generateIPv6Ruleset(nil), "IPv6 (no ports)")
}

func TestGenerateIPv6Ruleset_BridgeReturnBeforeDrop_WithPorts(t *testing.T) {
	ports := []PublicPort{{Protocol: "tcp", Port: 443}}
	assertBridgeReturnBeforeDrop(t, generateIPv6Ruleset(ports), "IPv6 (with ports)")
}
