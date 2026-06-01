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
	defaultConfigyEndpoint       = "https://configy.l42.eu"
	defaultPollIntervalSeconds   = 60
	defaultConfirmTimeoutSeconds = 30
)

// PublicPort represents one entry from the configy /systems/host/{host}/public-ports endpoint.
type PublicPort struct {
	System   string `json:"system"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp" or "udp"
	Purpose  string `json:"purpose"`
}

// appConfig holds runtime configuration read once at startup.
type appConfig struct {
	hostname       string
	configyEndpoint string
	dryRun         bool
	pollInterval   time.Duration
	confirmTimeout time.Duration
}

func main() {
	cfg := readConfig()

	if cfg.dryRun {
		log.Println("Starting in DRY-RUN mode — rulesets will be logged but not applied")
	} else {
		log.Printf("Starting in ENFORCE mode — rulesets applied via iptables-restore / ip6tables-restore (auto-rollback after %s if configy unreachable)", cfg.confirmTimeout)
	}
	log.Printf("Host: %s, Configy: %s, Poll interval: %s", cfg.hostname, cfg.configyEndpoint, cfg.pollInterval)

	var lastIPv4Hash, lastIPv6Hash string

	for {
		ports, err := fetchPublicPorts(cfg)
		if err != nil {
			log.Printf("WARNING: Failed to fetch public ports from configy: %v", err)
			log.Println("Applying fallback ruleset (base rules only — SSH, ICMP, loopback, connection tracking; no service ports)")
			// nil ports → base ruleset only (fails closed on service ports)
			ports = nil
		} else {
			log.Printf("Fetched %d public port(s) from configy for host %s", len(ports), cfg.hostname)
		}

		ipv4Ruleset := generateIPv4Ruleset(ports)
		ipv6Ruleset := generateIPv6Ruleset(ports)

		ipv4Hash := hashString(ipv4Ruleset)
		ipv6Hash := hashString(ipv6Ruleset)

		rulesetChanged := ipv4Hash != lastIPv4Hash || ipv6Hash != lastIPv6Hash

		if !rulesetChanged {
			log.Println("Ruleset unchanged — skipping apply")
		} else if cfg.dryRun {
			// Dry-run: log rulesets, don't touch iptables
			log.Println("Ruleset changed (DRY-RUN mode)")
			logRuleset(ipv4Ruleset, "iptables-restore")
			logRuleset(ipv6Ruleset, "ip6tables-restore")
			lastIPv4Hash = ipv4Hash
			lastIPv6Hash = ipv6Hash
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

		time.Sleep(cfg.pollInterval)
	}
}

func readConfig() appConfig {
	hostname := os.Getenv("SYSTEM")
	if hostname == "" {
		hostname = os.Getenv("HOSTNAME")
	}
	if hostname == "" {
		log.Fatal("Neither SYSTEM nor HOSTNAME environment variable is set")
	}

	configyEndpoint := os.Getenv("CONFIGY_ENDPOINT")
	if configyEndpoint == "" {
		configyEndpoint = defaultConfigyEndpoint
	}
	// Strip trailing slash so we can safely append paths
	configyEndpoint = strings.TrimRight(configyEndpoint, "/")

	dryRun := os.Getenv("DRY_RUN") == "true" || os.Getenv("DRY_RUN") == "1"

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
		hostname:        hostname,
		configyEndpoint: configyEndpoint,
		dryRun:          dryRun,
		pollInterval:    pollInterval,
		confirmTimeout:  confirmTimeout,
	}
}

func fetchPublicPorts(cfg appConfig) ([]PublicPort, error) {
	url := fmt.Sprintf("%s/systems/host/%s/public-ports", cfg.configyEndpoint, cfg.hostname)
	resp, err := http.Get(url) //nolint:noctx
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

	// Step 2: apply new IPv4 rules
	log.Println("Applying IPv4 ruleset via iptables-restore")
	if err := runRestore("iptables-restore", ipv4Ruleset); err != nil {
		// Nothing to revert — IPv4 apply failed before any change was committed
		return false, fmt.Errorf("iptables-restore failed: %w", err)
	}

	// Step 2b: apply new IPv6 rules — revert IPv4 if this fails
	log.Println("Applying IPv6 ruleset via ip6tables-restore")
	if err := runRestore("ip6tables-restore", ipv6Ruleset); err != nil {
		log.Printf("ip6tables-restore failed (%v) — reverting IPv4 rules", err)
		if revertErr := runRestore("iptables-restore", savedIPv4); revertErr != nil {
			log.Printf("ERROR reverting IPv4 rules: %v", revertErr)
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

		if revertErr := runRestore("iptables-restore", savedIPv4); revertErr != nil {
			log.Printf("ERROR reverting IPv4 rules: %v", revertErr)
		}
		if revertErr := runRestore("ip6tables-restore", savedIPv6); revertErr != nil {
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
func runRestore(command, ruleset string) error {
	cmd := exec.Command(command)
	cmd.Stdin = strings.NewReader(ruleset)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// logRuleset logs what would be applied in dry-run mode.
func logRuleset(ruleset, command string) {
	log.Printf("[DRY-RUN] Would apply via %s:\n%s", command, ruleset)
}

// generateIPv4Ruleset builds the iptables (IPv4) rules for the given host.
// If ports is nil, a fallback base ruleset is generated (no service ports).
//
// Safety guardrail 1: SSH port 22 is unconditionally accepted, independent of
// the configy-derived public_ports list. It is visibly present in dry-run output
// and can be verified before any host is flipped to enforce mode.
//
// Only INPUT and DOCKER-USER chains are managed. FORWARD is left under
// Docker's control so container networking is not disrupted.
func generateIPv4Ruleset(ports []PublicPort) string {
	var sb strings.Builder

	sb.WriteString("*filter\n")
	// INPUT: default DROP — only explicitly declared traffic is accepted
	sb.WriteString(":INPUT DROP [0:0]\n")
	// DOCKER-USER: flushed and populated with our rules.
	// Docker's FORWARD chain jumps here for published-port traffic.
	// FORWARD itself is intentionally left under Docker's management.
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

	if len(ports) > 0 {
		sb.WriteString("# Per-service public ports (from configy)\n")
		for _, p := range ports {
			sb.WriteString(fmt.Sprintf(
				"-A INPUT -p %s --dport %d -j ACCEPT  # %s: %s\n",
				p.Protocol, p.Port, p.System, p.Purpose,
			))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("# No service ports (fallback mode — configy unreachable or no ports declared)\n\n")
	}

	// --- DOCKER-USER chain ---
	// Mirrors the INPUT allow-list for Docker-published container traffic.
	// A final DROP blocks any published port not explicitly declared.
	// ESTABLISHED/RELATED is accepted first so in-flight sessions survive
	// a ruleset re-apply.
	sb.WriteString("# DOCKER-USER: mirror allow-list for Docker-published port traffic\n")
	sb.WriteString("-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")

	if len(ports) > 0 {
		for _, p := range ports {
			sb.WriteString(fmt.Sprintf(
				"-A DOCKER-USER -p %s --dport %d -j ACCEPT  # %s\n",
				p.Protocol, p.Port, p.System,
			))
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

	if len(ports) > 0 {
		sb.WriteString("# Per-service public ports (from configy)\n")
		for _, p := range ports {
			sb.WriteString(fmt.Sprintf(
				"-A INPUT -p %s --dport %d -j ACCEPT  # %s: %s\n",
				p.Protocol, p.Port, p.System, p.Purpose,
			))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("# No service ports (fallback mode — configy unreachable or no ports declared)\n\n")
	}

	// --- DOCKER-USER chain ---
	sb.WriteString("# DOCKER-USER: mirror allow-list for Docker-published port traffic\n")
	sb.WriteString("-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")

	if len(ports) > 0 {
		for _, p := range ports {
			sb.WriteString(fmt.Sprintf(
				"-A DOCKER-USER -p %s --dport %d -j ACCEPT  # %s\n",
				p.Protocol, p.Port, p.System,
			))
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
