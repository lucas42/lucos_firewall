package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
