// lucos_firewall — Host firewall manager for the lucOS estate.
//
// Fetches public_ports configuration from lucos_configy and applies an
// iptables/ip6tables ruleset: default DROP on inbound, with explicit ACCEPT
// rules for declared ports + host SSH + ICMP + connection tracking.
//
// See ADR-0007: https://github.com/lucas42/lucos/blob/main/docs/adr/0007-estate-wide-default-deny-port-policy.md
// Implementation tracked in: https://github.com/lucas42/lucos_firewall/issues/1
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	defaultConfigyOrigin         = "https://configy.l42.eu"
	defaultPollIntervalSeconds   = 60
	defaultConfirmTimeoutSeconds = 30
	httpTimeoutSeconds           = 10
	// heartbeatPath is touched on every successful poll loop iteration.
	// The Docker healthcheck verifies this file is fresh (< 2 min old).
	heartbeatPath = "/tmp/lucos-firewall-ok"
)

// PublicPort represents one entry from the configy /systems/host/{host}/public-ports endpoint.
type PublicPort struct {
	System   string `json:"system"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp" or "udp"
	Purpose  string `json:"purpose"`
}

// HostConfig holds the per-host configuration returned by configy /hosts/{host}.
// Only the fields consumed by lucos_firewall are decoded here.
type HostConfig struct {
	FirewallEnforce bool `json:"firewall_enforce"`
}

// appConfig holds runtime configuration read once at startup.
type appConfig struct {
	hostname       string
	configyOrigin  string
	// dryRunOverride is true when DRY_RUN env var is set.
	// When true it beats configy — the firewall always runs in dry-run mode
	// regardless of configy's firewall_enforce value. Retained as a transition
	// fallback while configy becomes the primary source of truth (ADR-0007).
	dryRunOverride bool
	pollInterval   time.Duration
	confirmTimeout time.Duration
}

func main() {
	cfg := readConfig()

	if cfg.dryRunOverride {
		log.Println("DRY_RUN override active — rulesets will always be logged but not applied (overrides configy firewall_enforce)")
	} else {
		log.Printf("Enforce mode will be read per-poll from configy /hosts/%s (initial state: dry-run until first successful fetch)", cfg.hostname)
	}
	log.Printf("Host: %s, Configy: %s, Poll interval: %s", cfg.hostname, cfg.configyOrigin, cfg.pollInterval)

	var lastIPv4Hash, lastIPv6Hash string
	var lastKnownEnforce *bool // nil = no successful configy fetch yet (cold start)

	for {
		// Step 1: determine enforce mode from configy (per-host, per-poll).
		fetchedEnforce, enforceErr := fetchEnforceMode(cfg)
		var effectiveDryRun bool
		effectiveDryRun, lastKnownEnforce = resolveEnforceMode(enforceErr, fetchedEnforce, lastKnownEnforce, cfg.dryRunOverride)
		if enforceErr != nil {
			if lastKnownEnforce == nil {
				log.Printf("WARNING: Cold start — configy enforce-mode fetch failed (%v), defaulting to dry-run", enforceErr)
			} else {
				heldMode := "dry-run"
				if *lastKnownEnforce {
					heldMode = "enforce"
				}
				log.Printf("WARNING: Failed to fetch enforce mode from configy (%v) — holding last-known-good (%s)", enforceErr, heldMode)
			}
		} else {
			effectiveMode := "dry-run"
			if !effectiveDryRun {
				effectiveMode = "enforce"
			}
			log.Printf("Enforce mode from configy: firewall_enforce=%v (effective: %s)", fetchedEnforce, effectiveMode)
		}

		// Step 2: fetch public ports from configy.
		ports, err := fetchPublicPorts(cfg)
		if err != nil {
			log.Printf("WARNING: Failed to fetch public ports from configy: %v", err)
			log.Println("Applying fallback ruleset (base rules only — SSH, ICMP, loopback, connection tracking; no service ports)")
			// nil ports → base ruleset only (fails closed on service ports)
			ports = nil
		} else {
			log.Printf("Fetched %d public port(s) from configy for host %s", len(ports), cfg.hostname)
			// Validate and filter ports before passing to the ruleset generator.
			// Any entry with an invalid protocol is rejected here to prevent
			// injection of arbitrary iptables rules via crafted configy responses.
			ports = filterValidPorts(ports)
		}

		ipv4Ruleset := generateIPv4Ruleset(ports)
		ipv6Ruleset := generateIPv6Ruleset(ports)

		ipv4Hash := hashString(ipv4Ruleset)
		ipv6Hash := hashString(ipv6Ruleset)

		rulesetChanged := ipv4Hash != lastIPv4Hash || ipv6Hash != lastIPv6Hash

		if !rulesetChanged {
			log.Println("Ruleset unchanged — skipping apply")
		} else if effectiveDryRun {
			// Dry-run: log rulesets, don't touch iptables.
			// Hashes are NOT updated here — nothing has been applied, so there is
			// no "current" state to track. If mode later flips to enforce, the hash
			// will still be empty/stale and rulesetChanged will be true, ensuring
			// the first enforce-mode poll actually applies the rules.
			log.Println("Ruleset changed (DRY-RUN mode)")
			logRuleset(ipv4Ruleset, "iptables-restore")
			logRuleset(ipv6Ruleset, "ip6tables-restore")
		} else {
			// Enforce mode: save → apply → confirm → revert-if-needed
			confirmed, applyErr := applyWithRollback(ipv4Ruleset, ipv6Ruleset, cfg)
			if applyErr != nil {
				log.Printf("ERROR applying ruleset: %v", applyErr)
			}
			if confirmed {
				lastIPv4Hash = ipv4Hash
				lastIPv6Hash = ipv6Hash
				log.Println("Rules confirmed and active")
			} else {
				// Rolled back or apply failed — don't update hashes so we retry next poll
				log.Println("Rules NOT confirmed — will retry on next poll")
			}
		}

		// Touch the heartbeat file so the Docker healthcheck knows the loop
		// is alive. Written on every iteration regardless of whether rules
		// changed — the file's modification time is what the check reads.
		touchHeartbeat()

		time.Sleep(cfg.pollInterval)
	}
}

func readConfig() appConfig {
	// HOSTDOMAIN is injected by the deploy orb per-host
	// (e.g. "avalon.s.l42.eu", "xwing-v4.s.l42.eu", "salvare-v4.s.l42.eu").
	// Derive the configy host identifier by taking the first DNS label and
	// stripping any trailing -vN version suffix — matching the same strip
	// used by lucos_router's update-domains.sh.
	// Examples: "avalon.s.l42.eu" → "avalon"
	//           "xwing-v4.s.l42.eu" → "xwing"
	//           "salvare-v4.s.l42.eu" → "salvare"
	hostdomain := os.Getenv("HOSTDOMAIN")
	if hostdomain == "" {
		log.Fatal("HOSTDOMAIN environment variable is not set. " +
			"It is injected automatically by the deploy orb per-host. " +
			"In development, set it to e.g. \"avalon.s.l42.eu\".")
	}
	hostname := strings.SplitN(hostdomain, ".", 2)[0]
	if idx := strings.Index(hostname, "-v"); idx >= 0 && idx+2 < len(hostname) && hostname[idx+2] >= '0' && hostname[idx+2] <= '9' {
		hostname = hostname[:idx]
	}

	configyOrigin := os.Getenv("CONFIGY_ORIGIN")
	if configyOrigin == "" {
		configyOrigin = defaultConfigyOrigin
	}
	// Strip trailing slash so we can safely append paths
	configyOrigin = strings.TrimRight(configyOrigin, "/")

	dryRunOverride := os.Getenv("DRY_RUN") == "true" || os.Getenv("DRY_RUN") == "1"

	pollInterval := time.Duration(defaultPollIntervalSeconds) * time.Second
	if raw := os.Getenv("POLL_INTERVAL_SECONDS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pollInterval = time.Duration(n) * time.Second
		} else {
			log.Printf("WARNING: Invalid POLL_INTERVAL_SECONDS=%q — using default %ds", raw, defaultPollIntervalSeconds)
		}
	}

	confirmTimeout := time.Duration(defaultConfirmTimeoutSeconds) * time.Second
	if raw := os.Getenv("CONFIRM_TIMEOUT_SECONDS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			confirmTimeout = time.Duration(n) * time.Second
		} else {
			log.Printf("WARNING: Invalid CONFIRM_TIMEOUT_SECONDS=%q — using default %ds", raw, defaultConfirmTimeoutSeconds)
		}
	}

	return appConfig{
		hostname:       hostname,
		configyOrigin:  configyOrigin,
		dryRunOverride: dryRunOverride,
		pollInterval:   pollInterval,
		confirmTimeout: confirmTimeout,
	}
}

func fetchPublicPorts(cfg appConfig) ([]PublicPort, error) {
	url := fmt.Sprintf("%s/systems/host/%s/public-ports", cfg.configyOrigin, cfg.hostname)
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeoutSeconds*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request to %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("configy returned HTTP %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var ports []PublicPort
	if err := json.Unmarshal(body, &ports); err != nil {
		return nil, fmt.Errorf("parsing JSON response: %w", err)
	}
	return ports, nil
}

// fetchEnforceMode fetches the per-host firewall_enforce flag from configy /hosts/{host}.
// Returns (enforce=true, nil) when enforce mode is active, (false, nil) for dry-run, or
// (false, err) when the request fails (caller uses last-known-good or cold-start default).
// A 404 response (host not yet in configy) is treated as firewall_enforce: false (dry-run),
// consistent with configy's absent-field default.
func fetchEnforceMode(cfg appConfig) (bool, error) {
	url := fmt.Sprintf("%s/hosts/%s", cfg.configyOrigin, cfg.hostname)
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeoutSeconds*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("building request for %s: %w", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("HTTP request to %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Host not yet in configy — treat as firewall_enforce: false (dry-run default)
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("configy returned HTTP %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("reading response body from %s: %w", url, err)
	}

	var hc HostConfig
	if err := json.Unmarshal(body, &hc); err != nil {
		return false, fmt.Errorf("parsing JSON response from %s: %w", url, err)
	}
	return hc.FirewallEnforce, nil
}

// resolveEnforceMode determines the effective dry-run/enforce mode and the updated
// last-known-good state from the configy fetch result.
//
// It is a pure function with no side effects — all logging is the caller's responsibility.
//
//   fetchErr:       non-nil if the configy fetch failed this poll iteration
//   fetchedEnforce: the firewall_enforce value returned by configy (valid only when fetchErr == nil)
//   lastKnown:      pointer to the last successfully fetched enforce value (nil = cold start)
//   dryRunOverride: true when the DRY_RUN env var forces dry-run regardless of configy
//
// Returns:
//   effectiveDryRun:    true  → run in dry-run mode; false → run in enforce mode
//   updatedLastKnown:   new last-known-good (set on successful fetch; unchanged on error)
func resolveEnforceMode(fetchErr error, fetchedEnforce bool, lastKnown *bool, dryRunOverride bool) (effectiveDryRun bool, updatedLastKnown *bool) {
	if fetchErr == nil {
		// Successful fetch — update last-known-good
		v := fetchedEnforce
		updatedLastKnown = &v
	} else {
		// Failed fetch — hold last-known-good unchanged
		updatedLastKnown = lastKnown
	}

	if dryRunOverride {
		// DRY_RUN env var wins unconditionally
		return true, updatedLastKnown
	}
	if updatedLastKnown == nil {
		// Cold start with no successful fetch yet — default to dry-run (safe)
		return true, nil
	}
	return !*updatedLastKnown, updatedLastKnown
}

// validateProtocol returns an error if proto is not a known safe iptables protocol keyword.
// Only "tcp" and "udp" are accepted — anything else (including values containing whitespace
// or newlines) is rejected to prevent injection into the generated ruleset.
func validateProtocol(proto string) error {
	switch proto {
	case "tcp", "udp":
		return nil
	default:
		return fmt.Errorf("invalid protocol %q: must be \"tcp\" or \"udp\"", proto)
	}
}

// filterValidPorts returns only the port entries that pass validateProtocol.
// Entries with invalid protocols are logged and dropped; they never reach the
// ruleset generator. This prevents a compromised or tampered configy response
// from injecting arbitrary iptables rules via the protocol field.
func filterValidPorts(ports []PublicPort) []PublicPort {
	valid := make([]PublicPort, 0, len(ports))
	for _, p := range ports {
		if err := validateProtocol(p.Protocol); err != nil {
			log.Printf("WARNING: Dropping port entry (system=%q port=%d): %v", p.System, p.Port, err)
			continue
		}
		valid = append(valid, p)
	}
	return valid
}

// applyWithRollback implements the iptables-apply safety pattern:
//  1. Save the current iptables/ip6tables state.
//  2. Apply the new rulesets.
//  3. Wait for the confirmation window (cfg.confirmTimeout).
//  4. Re-check configy to confirm the host still has network connectivity.
//  5. If the check fails, revert to the saved state and return (false, err).
//  6. If the check succeeds, return (true, nil).
//
// This ensures a bad ruleset self-heals without manual intervention. If a new
// ruleset were to drop connectivity (e.g., a bug removing the ESTABLISHED/RELATED
// rule), the configy check would fail and the previous known-good rules are restored.
//
// NOTE: SSH port 22 is unconditionally hardcoded in every generated ruleset
// (guardrail 1). applyWithRollback is guardrail 2 — a belt-and-suspenders defence.
func applyWithRollback(ipv4Ruleset, ipv6Ruleset string, cfg appConfig) (confirmed bool, err error) {
	// Step 1: save current state
	savedIPv4, err := saveRules("iptables-save")
	if err != nil {
		return false, fmt.Errorf("saving IPv4 rules before apply: %w", err)
	}
	savedIPv6, err := saveRules("ip6tables-save")
	if err != nil {
		return false, fmt.Errorf("saving IPv6 rules before apply: %w", err)
	}

	// Step 2: flush owned chains, then apply new IPv4 rules via --noflush restore.
	// Docker-managed chains (FORWARD, DOCKER-FORWARD, DOCKER-ISOLATION-*) are
	// untouched; prepareChains also ensures the FORWARD → DOCKER-USER jump exists.
	log.Println("Preparing owned chains (IPv4)")
	if err := prepareChains("iptables"); err != nil {
		// prepareChains may have partially flushed INPUT or DOCKER-USER before
		// failing. Revert to restore a clean state.
		log.Printf("prepareChains (iptables) failed (%v) — reverting IPv4 rules", err)
		if revertErr := runRestore("iptables-restore", savedIPv4, false); revertErr != nil {
			log.Printf("ERROR reverting IPv4 rules: %v", revertErr)
		}
		return false, fmt.Errorf("prepareChains (iptables): %w", err)
	}
	log.Println("Applying IPv4 ruleset via iptables-restore --noflush")
	if err := runRestore("iptables-restore", ipv4Ruleset, true); err != nil {
		// prepareChains already flushed INPUT and DOCKER-USER — revert to restore them.
		log.Printf("iptables-restore failed (%v) — reverting IPv4 rules", err)
		if revertErr := runRestore("iptables-restore", savedIPv4, false); revertErr != nil {
			log.Printf("ERROR reverting IPv4 rules: %v", revertErr)
		}
		return false, fmt.Errorf("iptables-restore failed: %w", err)
	}

	// Step 2b: apply new IPv6 rules — revert IPv4 if this fails.
	// Full restore (noflush=false) for the revert so Docker's chains are also restored.
	log.Println("Preparing owned chains (IPv6)")
	if err := prepareChains("ip6tables"); err != nil {
		// prepareChains may have partially flushed ip6tables chains — revert both tables.
		log.Printf("prepareChains (ip6tables) failed (%v) — reverting both tables", err)
		if revertErr := runRestore("iptables-restore", savedIPv4, false); revertErr != nil {
			log.Printf("ERROR reverting IPv4 rules: %v", revertErr)
		}
		if revertErr := runRestore("ip6tables-restore", savedIPv6, false); revertErr != nil {
			log.Printf("ERROR reverting IPv6 rules: %v", revertErr)
		}
		return false, fmt.Errorf("prepareChains (ip6tables): %w", err)
	}
	log.Println("Applying IPv6 ruleset via ip6tables-restore --noflush")
	if err := runRestore("ip6tables-restore", ipv6Ruleset, true); err != nil {
		// prepareChains("ip6tables") flushed ip6tables INPUT and DOCKER-USER — revert both tables.
		log.Printf("ip6tables-restore failed (%v) — reverting both tables", err)
		if revertErr := runRestore("iptables-restore", savedIPv4, false); revertErr != nil {
			log.Printf("ERROR reverting IPv4 rules: %v", revertErr)
		}
		if revertErr := runRestore("ip6tables-restore", savedIPv6, false); revertErr != nil {
			log.Printf("ERROR reverting IPv6 rules: %v", revertErr)
		}
		return false, fmt.Errorf("ip6tables-restore failed: %w", err)
	}

	// Step 3: confirmation window — wait before verifying
	log.Printf("Rules applied — waiting %s for confirmation window", cfg.confirmTimeout)
	time.Sleep(cfg.confirmTimeout)

	// Step 4: verify configy is reachable (proves outbound connectivity is intact)
	log.Println("Confirmation window elapsed — verifying configy reachability")
	if _, verifyErr := fetchPublicPorts(cfg); verifyErr != nil {
		log.Printf("WARNING: Confirmation failed — configy unreachable after %s: %v", cfg.confirmTimeout, verifyErr)
		log.Println("Auto-reverting to previous ruleset (iptables-apply safety pattern)")

		if revertErr := runRestore("iptables-restore", savedIPv4, false); revertErr != nil {
			log.Printf("ERROR reverting IPv4 rules: %v", revertErr)
		}
		if revertErr := runRestore("ip6tables-restore", savedIPv6, false); revertErr != nil {
			log.Printf("ERROR reverting IPv6 rules: %v", revertErr)
		}
		return false, fmt.Errorf("auto-reverted after %s: configy unreachable", cfg.confirmTimeout)
	}

	return true, nil
}

// saveRules runs iptables-save or ip6tables-save and returns the output.
func saveRules(command string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(command)
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s failed: %w", command, err)
	}
	return out.String(), nil
}

// runRestore pipes the given ruleset into iptables-restore or ip6tables-restore.
// When noflush is true the --noflush flag is passed so only the chains declared
// in the ruleset are touched; Docker-managed chains (FORWARD, DOCKER-FORWARD,
// DOCKER-ISOLATION-*) are left intact. When noflush is false (rollback path)
// the full table is replaced, restoring Docker's chains from the saved snapshot.
func runRestore(command, ruleset string, noflush bool) error {
	args := []string{}
	if noflush {
		args = []string{"--noflush"}
	}
	cmd := exec.Command(command, args...)
	cmd.Stdin = strings.NewReader(ruleset)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// prepareChains flushes the two chains owned by lucos_firewall (INPUT and
// DOCKER-USER) before a --noflush restore, and ensures the FORWARD →
// DOCKER-USER jump exists. The iptablesCmd argument is "iptables" or
// "ip6tables".
//
// Only INPUT and DOCKER-USER are touched. FORWARD is left under Docker's
// control except for the idempotent jump guard, which ensures DOCKER-USER
// is reachable on cold starts before Docker has initialised its own chains.
func prepareChains(iptablesCmd string) error {
	// Ensure DOCKER-USER exists — on cold start Docker may not have created
	// it yet. Ignore errors (chain already exists).
	exec.Command(iptablesCmd, "-N", "DOCKER-USER").Run()

	// Flush our two owned chains so the --noflush restore appends a clean set.
	if err := exec.Command(iptablesCmd, "-F", "DOCKER-USER").Run(); err != nil {
		return fmt.Errorf("%s -F DOCKER-USER: %w", iptablesCmd, err)
	}
	// Brief gap: INPUT is empty under DROP policy until the restore completes.
	// This is sub-millisecond; established sessions survive via TCP retransmit.
	if err := exec.Command(iptablesCmd, "-F", "INPUT").Run(); err != nil {
		return fmt.Errorf("%s -F INPUT: %w", iptablesCmd, err)
	}

	// Idempotent guard: ensure FORWARD → DOCKER-USER jump is present.
	// -C returns exit code 1 if the rule is absent — not an error here.
	// -I 1 inserts at position 1 so DOCKER-USER is first in FORWARD.
	check := exec.Command(iptablesCmd, "-C", "FORWARD", "-j", "DOCKER-USER")
	if err := check.Run(); err != nil {
		if insertErr := exec.Command(iptablesCmd, "-I", "FORWARD", "1", "-j", "DOCKER-USER").Run(); insertErr != nil {
			return fmt.Errorf("%s -I FORWARD 1 -j DOCKER-USER: %w", iptablesCmd, insertErr)
		}
	}
	return nil
}

// logRuleset logs what would be applied in dry-run mode.
func logRuleset(ruleset, command string) {
	log.Printf("[DRY-RUN] Would apply via %s:\n%s", command, ruleset)
}

// touchHeartbeat creates or updates the heartbeat file so the Docker
// healthcheck can verify the poll loop is alive. The healthcheck reads the
// file's modification time; a stale or missing file signals an unhealthy
// container. Errors are logged but do not abort the poll loop.
func touchHeartbeat() {
	if err := os.WriteFile(heartbeatPath, nil, 0644); err != nil {
		log.Printf("WARNING: Failed to update heartbeat file %s: %v", heartbeatPath, err)
	}
}

// generateIPv4Ruleset builds the iptables (IPv4) rules for the given host.
// If ports is nil, a fallback base ruleset is generated (no service ports).
//
// Safety guardrail 1: SSH port 22 is unconditionally accepted, independent of
// the configy-derived public_ports list. It is visibly present in dry-run output
// and can be verified before any host is flipped to enforce mode.
//
// Only INPUT and DOCKER-USER chains are managed. FORWARD is left entirely
// under Docker's control — prepareChains adds the idempotent FORWARD →
// DOCKER-USER jump before each --noflush restore without touching other
// FORWARD rules that Docker manages (DOCKER-FORWARD, DOCKER-ISOLATION-*).
func generateIPv4Ruleset(ports []PublicPort) string {
	var sb strings.Builder

	sb.WriteString("*filter\n")
	// INPUT: default DROP — only explicitly declared traffic is accepted.
	sb.WriteString(":INPUT DROP [0:0]\n")
	// DOCKER-USER: flushed and populated with our allow-list + final DROP.
	// FORWARD is NOT declared here — Docker owns it and manages DOCKER-FORWARD
	// and DOCKER-ISOLATION chains; a whole-table replace would delete them.
	sb.WriteString(":DOCKER-USER - [0:0]\n")
	sb.WriteString("\n")

	// --- INPUT chain ---
	sb.WriteString("# Loopback\n")
	sb.WriteString("-A INPUT -i lo -j ACCEPT\n")
	sb.WriteString("\n")

	sb.WriteString("# Connection tracking\n")
	sb.WriteString("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	sb.WriteString("\n")

	// Safety guardrail 1: SSH is hardcoded, NOT derived from configy.
	// This rule is unconditional and present in every generated ruleset,
	// including the fallback. Dry-run output can be inspected to confirm
	// this rule is present before any host is flipped to enforce mode.
	sb.WriteString("# Host SSH — unconditional, independent of configy (safety guardrail)\n")
	sb.WriteString("-A INPUT -p tcp --dport 22 -j ACCEPT\n")
	sb.WriteString("\n")

	sb.WriteString("# Conservative ICMP\n")
	sb.WriteString("-A INPUT -p icmp --icmp-type echo-request -j ACCEPT\n")
	sb.WriteString("-A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT\n")
	sb.WriteString("-A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT\n")
	sb.WriteString("-A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT\n")
	sb.WriteString("\n")

	// mDNS: destination-scoped to the IPv4 link-local multicast group 224.0.0.251.
	// This group is within 224.0.0.0/24 (Local Network Control Block, RFC 5771) —
	// never forwarded by routers, so this opens nothing internet-reachable.
	// mDNS is link-local infrastructure (RFC 6762) and belongs in the base allow-list
	// alongside ICMP, not in configy public_ports (ADR-0007 Amendment 3).
	sb.WriteString("# mDNS — link-local multicast only (never internet-routable, RFC 6762)\n")
	sb.WriteString("-A INPUT -d 224.0.0.251 -p udp --dport 5353 -j ACCEPT\n")
	sb.WriteString("\n")

	if len(ports) > 0 {
		sb.WriteString("# Per-service public ports (from configy)\n")
		for _, p := range ports {
			// p.Protocol is pre-validated (tcp/udp only); p.Port is an int (%d).
			// System/Purpose labels are NOT included in the iptables output —
			// they come from an external source and could contain newlines that
			// would inject arbitrary rules. Labels appear in application logs only.
			sb.WriteString(fmt.Sprintf("-A INPUT -p %s --dport %d -j ACCEPT\n", p.Protocol, p.Port))
		}
		sb.WriteString("\n")
	} else if ports == nil {
		// nil means the configy fetch failed; the caller logged a warning and
		// substituted nil to generate a base-only fallback ruleset.
		sb.WriteString("# No service ports (fallback — configy unreachable; base rules only)\n\n")
	} else {
		// Non-nil empty slice: configy was reachable but declared zero public ports
		// for this host. This is the correct steady state for hosts with no
		// internet-facing services (e.g. salvare).
		sb.WriteString("# No service ports declared for this host\n\n")
	}

	// --- DOCKER-USER chain ---
	// Polices externally-originating traffic to Docker-published ports.
	// Traffic ingressing from Docker bridge interfaces (-i br+ or -i docker0)
	// hits RETURN and falls back to Docker's own FORWARD/ICC rules, matching
	// ADR-0007's scope exclusion of intra-stack inter-container traffic.
	// ESTABLISHED/RELATED is accepted first so in-flight sessions survive
	// a ruleset re-apply.
	sb.WriteString("# DOCKER-USER: external-origin traffic only — bridge ICC is returned to FORWARD chain\n")
	sb.WriteString("-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	sb.WriteString("-A DOCKER-USER -i br+ -j RETURN\n")
	sb.WriteString("-A DOCKER-USER -i docker0 -j RETURN\n")

	if len(ports) > 0 {
		for _, p := range ports {
			// Use --ctorigdstport (conntrack original destination port) rather than
			// --dport. In the FORWARD chain Docker's DNAT has already rewritten the
			// destination port (nat PREROUTING runs before filter FORWARD), so --dport
			// sees the post-DNAT container port, not the host port the client connected
			// to. --ctorigdstport reads the pre-DNAT original destination stored in the
			// conntrack entry — the actual host port — which is what should be matched
			// against the declared public_ports allow-list. The xt_conntrack module is
			// already in use above (--ctstate ESTABLISHED,RELATED). Fixes #21.
			sb.WriteString(fmt.Sprintf("-A DOCKER-USER -p %s -m conntrack --ctorigdstport %d -j ACCEPT\n", p.Protocol, p.Port))
		}
	}
	sb.WriteString("-A DOCKER-USER -j DROP\n")
	sb.WriteString("\n")

	sb.WriteString("COMMIT\n")
	return sb.String()
}

// generateIPv6Ruleset builds the ip6tables (IPv6) rules for the given host.
// Includes ICMPv6 Neighbour Discovery Protocol types required for IPv6 to function.
// If ports is nil, a fallback base ruleset is generated (no service ports).
func generateIPv6Ruleset(ports []PublicPort) string {
	var sb strings.Builder

	sb.WriteString("*filter\n")
	sb.WriteString(":INPUT DROP [0:0]\n")
	// FORWARD is NOT declared here — see generateIPv4Ruleset for rationale.
	sb.WriteString(":DOCKER-USER - [0:0]\n")
	sb.WriteString("\n")

	// --- INPUT chain ---
	sb.WriteString("# Loopback\n")
	sb.WriteString("-A INPUT -i lo -j ACCEPT\n")
	sb.WriteString("\n")

	sb.WriteString("# Connection tracking\n")
	sb.WriteString("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	sb.WriteString("\n")

	// Safety guardrail 1: SSH unconditional — see generateIPv4Ruleset for rationale
	sb.WriteString("# Host SSH — unconditional, independent of configy (safety guardrail)\n")
	sb.WriteString("-A INPUT -p tcp --dport 22 -j ACCEPT\n")
	sb.WriteString("\n")

	// ICMPv6: conservative types plus NDP (required for IPv6 host operation)
	sb.WriteString("# Conservative ICMPv6 + Neighbour Discovery Protocol (required for IPv6)\n")
	sb.WriteString("-A INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT\n")
	sb.WriteString("-A INPUT -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT\n")
	sb.WriteString("-A INPUT -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT\n")
	sb.WriteString("-A INPUT -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT\n")
	sb.WriteString("-A INPUT -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT\n")
	sb.WriteString("-A INPUT -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT\n")
	sb.WriteString("-A INPUT -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT\n")
	sb.WriteString("-A INPUT -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT\n")
	sb.WriteString("\n")

	// mDNS: destination-scoped to the IPv6 link-local multicast group ff02::fb.
	// ff02::/16 is link-local scope (RFC 4291) — never forwarded by routers,
	// so this opens nothing internet-reachable. Same class as the IPv4 rule above.
	sb.WriteString("# mDNS — link-local multicast only (never internet-routable, RFC 6762)\n")
	sb.WriteString("-A INPUT -d ff02::fb -p udp --dport 5353 -j ACCEPT\n")
	sb.WriteString("\n")

	if len(ports) > 0 {
		sb.WriteString("# Per-service public ports (from configy)\n")
		for _, p := range ports {
			// System/Purpose labels are omitted from iptables output — external
			// strings that could contain newlines are kept out of the ruleset.
			sb.WriteString(fmt.Sprintf("-A INPUT -p %s --dport %d -j ACCEPT\n", p.Protocol, p.Port))
		}
		sb.WriteString("\n")
	} else if ports == nil {
		// nil means the configy fetch failed; see generateIPv4Ruleset for rationale.
		sb.WriteString("# No service ports (fallback — configy unreachable; base rules only)\n\n")
	} else {
		// Non-nil empty slice: configy reachable, zero public ports declared.
		sb.WriteString("# No service ports declared for this host\n\n")
	}

	// --- DOCKER-USER chain ---
	// Polices externally-originating traffic to Docker-published ports.
	// Traffic ingressing from Docker bridge interfaces (-i br+ or -i docker0)
	// hits RETURN and falls back to Docker's own FORWARD/ICC rules, matching
	// ADR-0007's scope exclusion of intra-stack inter-container traffic.
	// ESTABLISHED/RELATED is accepted first so in-flight sessions survive
	// a ruleset re-apply.
	sb.WriteString("# DOCKER-USER: external-origin traffic only — bridge ICC is returned to FORWARD chain\n")
	sb.WriteString("-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	sb.WriteString("-A DOCKER-USER -i br+ -j RETURN\n")
	sb.WriteString("-A DOCKER-USER -i docker0 -j RETURN\n")

	if len(ports) > 0 {
		for _, p := range ports {
			// Same fix as generateIPv4Ruleset: use --ctorigdstport (pre-DNAT host port
			// from conntrack) instead of --dport (post-DNAT container port). IPv6 DNAT
			// follows the same nat PREROUTING → filter FORWARD ordering. Fixes #21.
			sb.WriteString(fmt.Sprintf("-A DOCKER-USER -p %s -m conntrack --ctorigdstport %d -j ACCEPT\n", p.Protocol, p.Port))
		}
	}
	sb.WriteString("-A DOCKER-USER -j DROP\n")
	sb.WriteString("\n")

	sb.WriteString("COMMIT\n")
	return sb.String()
}

// hashString returns the hex-encoded SHA-256 hash of s.
// Used to detect ruleset changes between poll iterations.
func hashString(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}
