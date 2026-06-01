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
	defaultConfigyEndpoint    = "https://configy.l42.eu"
	defaultPollIntervalSeconds = 60
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
	hostname        string
	configyEndpoint string
	dryRun          bool
	pollInterval    time.Duration
}

func main() {
	cfg := readConfig()

	if cfg.dryRun {
		log.Println("Starting in DRY-RUN mode — rulesets will be logged but not applied")
	} else {
		log.Println("Starting in ENFORCE mode — rulesets will be applied via iptables-restore / ip6tables-restore")
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

		if ipv4Hash != lastIPv4Hash {
			log.Println("IPv4 ruleset changed — applying via iptables-restore")
			if err := applyRuleset(ipv4Ruleset, "iptables-restore", cfg.dryRun); err != nil {
				log.Printf("ERROR: iptables-restore failed: %v", err)
				// Don't update hash — we'll retry next poll
			} else {
				lastIPv4Hash = ipv4Hash
				log.Printf("IPv4 ruleset applied (sha256: %s)", ipv4Hash[:12])
			}
		} else {
			log.Println("IPv4 ruleset unchanged — skipping apply")
		}

		if ipv6Hash != lastIPv6Hash {
			log.Println("IPv6 ruleset changed — applying via ip6tables-restore")
			if err := applyRuleset(ipv6Ruleset, "ip6tables-restore", cfg.dryRun); err != nil {
				log.Printf("ERROR: ip6tables-restore failed: %v", err)
				// Don't update hash — we'll retry next poll
			} else {
				lastIPv6Hash = ipv6Hash
				log.Printf("IPv6 ruleset applied (sha256: %s)", ipv6Hash[:12])
			}
		} else {
			log.Println("IPv6 ruleset unchanged — skipping apply")
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

	return appConfig{
		hostname:        hostname,
		configyEndpoint: configyEndpoint,
		dryRun:          dryRun,
		pollInterval:    pollInterval,
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

// generateIPv4Ruleset builds the iptables (IPv4) rules for the given host.
// If ports is nil, a fallback base ruleset is generated (no service ports).
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

	// Port 22 is hardcoded — it's a host OS service, not a lucos service
	sb.WriteString("# Host SSH (hardcoded — not a lucos service)\n")
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
	// Connection tracking is included so that established connections to
	// allowed ports are not disrupted mid-session during a ruleset re-apply.
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

	sb.WriteString("# Host SSH (hardcoded — not a lucos service)\n")
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

// applyRuleset pipes the given ruleset into the specified restore command
// (iptables-restore or ip6tables-restore). In dry-run mode, the ruleset
// is logged instead of applied.
func applyRuleset(ruleset, command string, dryRun bool) error {
	if dryRun {
		log.Printf("[DRY-RUN] Would apply via %s:\n%s", command, ruleset)
		return nil
	}
	cmd := exec.Command(command)
	cmd.Stdin = strings.NewReader(ruleset)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// hashString returns the hex-encoded SHA-256 hash of s.
// Used to detect ruleset changes between poll iterations.
func hashString(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}
