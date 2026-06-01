# lucos_firewall

Configures firewall on lucOS hosts dynamically based on data from [lucos_configy](https://github.com/lucas42/lucos_configy).

Implements the host-level default-deny firewall described in [ADR-0007](https://github.com/lucas42/lucos/blob/main/docs/adr/0007-estate-wide-default-deny-port-policy.md).

## How it works

`lucos_firewall` runs as a container on each internet-facing lucos host (`avalon`, `xwing`, `salvare`). It:

1. Fetches the `public_ports` configuration from `lucos_configy` for the current host.
2. Generates an `iptables` + `ip6tables` ruleset: default DROP on inbound, with explicit ACCEPT rules only for ports declared in `public_ports`, plus host SSH (22), ICMP/ICMPv6, and ESTABLISHED/RELATED connection tracking.
3. Applies the ruleset via `iptables-restore` / `ip6tables-restore`.
4. Polls for configy changes and re-applies when the declared port list changes.

The container requires `cap_add: NET_ADMIN` and runs with `network_mode: host` — the only legitimate use of host networking in the lucos estate (it needs the host's netfilter to apply rules). See ADR-0007 for the written justification.

## Ruleset shape

Only the `INPUT` and `DOCKER-USER` chains are managed. The `FORWARD` chain is intentionally left under Docker's control so that container-to-container and container-to-external networking is not disrupted.

- **`INPUT`** — catches host-network traffic (services running with `network_mode: host`).
- **`DOCKER-USER`** — catches Docker-forwarded (port-published) traffic. Docker's own `FORWARD` chain jumps here before any Docker-managed chains.

Base rules (always present, regardless of configy data):
- Loopback (`-i lo`) ACCEPT
- ESTABLISHED/RELATED ACCEPT (connection tracking)
- SSH port 22 ACCEPT (host access — hardcoded, not a lucos service)
- Conservative ICMP (IPv4): echo-request, destination-unreachable, time-exceeded, parameter-problem
- Conservative ICMPv6 (IPv6): same types plus Neighbour Discovery Protocol (NDP) entries required for IPv6 host operation

Per-service entries: one ACCEPT rule per `public_ports` entry returned by configy for the current host, added to both `INPUT` and `DOCKER-USER`.

## Safety guardrails

Two mandatory guardrails protect against a bad ruleset locking administrators out of a remote host:

### Guardrail 1 — SSH always allowed

Host SSH (port 22) is unconditionally accepted in every generated ruleset, independent of the `public_ports` data from configy. The rule is present in:
- The full ruleset (when configy is reachable)
- The fallback ruleset (when configy is unreachable)
- Dry-run log output, where it can be verified before any host is flipped to enforce mode

A host with a broken configy-derived ruleset still has SSH accessible.

### Guardrail 2 — Timed auto-rollback on enforce (`iptables-apply` pattern)

When applying a new ruleset in enforce mode, the service:
1. Saves the current iptables/ip6tables state with `iptables-save` / `ip6tables-save`
2. Applies the new ruleset
3. Waits for the confirmation window (`CONFIRM_TIMEOUT_SECONDS`, default 30s)
4. After the window, verifies connectivity by re-fetching from configy
5. If configy is **reachable**: rules confirmed and kept
6. If configy is **not reachable**: previous state is restored via `iptables-restore` and the rules are retried on the next poll

This means a bad ruleset that disrupts network connectivity self-heals within `CONFIRM_TIMEOUT_SECONDS` + one configy round-trip, without manual intervention.

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `HOSTDOMAIN` | **Yes** | — | SSH hostname of this host (e.g. `avalon.s.l42.eu`). Set automatically by the deploy orb per-host. In development, set to the host whose `public_ports` you want to test against. The configy host identifier is derived from this: first DNS label, `-vN` suffix stripped (`xwing-v4.s.l42.eu` → `xwing`). |
| `CONFIGY_ORIGIN` | No | `https://configy.l42.eu` | Base URL of the lucos_configy API. |
| `DRY_RUN` | No | `false` | Set to `true` or `1` to log rulesets without applying them. Use for initial deployment. |
| `POLL_INTERVAL_SECONDS` | No | `60` | How often to poll configy for changes. |
| `CONFIRM_TIMEOUT_SECONDS` | No | `30` | Confirmation window for the auto-rollback guardrail (enforce mode only). |
| `SYSTEM` | No | — | lucos service name (auto-provided). Not used for host identification. |
| `ENVIRONMENT` | No | — | Passed through for logging / `/_info` purposes. |

**Why `HOSTDOMAIN` and not `SYSTEM` or `HOSTNAME`?** `SYSTEM` is the lucos service name (`lucos_firewall`), not a host — querying configy with it returns zero ports. `HOSTNAME` inside a container may reflect the container ID rather than the actual machine hostname. `HOSTDOMAIN` is the established lucos pattern: injected by the deploy orb at deploy time, it carries the correct per-host identity without a lucos_creds entry.

## Fallback behaviour when configy is unreachable

If configy cannot be reached at startup (or on any subsequent poll), the container applies a **base ruleset with no service ports** — SSH, ICMP/ICMPv6, loopback, and connection tracking only.

This is a "fails closed" stance on service ports (all are blocked if configy is unavailable) while preserving basic host accessibility (SSH on port 22 remains open so the host can be reached for diagnosis).

The container continues polling on the configured interval and will apply the full ruleset as soon as configy becomes reachable again.

## Deployment

### Dry-run mode (first step)

Set `DRY_RUN=true` in the host's `.env` file. In this mode the container logs what it _would_ apply but makes no iptables changes. Run for ~a week on `avalon` before flipping to enforce mode.

### Enforce mode

Remove or set `DRY_RUN=false`. The container will apply rules via `iptables-restore` / `ip6tables-restore` on startup and whenever configy changes.

## References

- [ADR-0007: Estate-wide default-deny port policy](https://github.com/lucas42/lucos/blob/main/docs/adr/0007-estate-wide-default-deny-port-policy.md)
- [Design discussion: lucas42/lucos#169](https://github.com/lucas42/lucos/issues/169)
- [Bootstrap issue: lucas42/lucos#181](https://github.com/lucas42/lucos/issues/181)
