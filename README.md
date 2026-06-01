# lucos_firewall

Configures firewall on lucOS hosts dynamically based on data from [lucos_configy](https://github.com/lucas42/lucos_configy).

Implements the host-level default-deny firewall described in [ADR-0007](https://github.com/lucas42/lucos/blob/main/docs/adr/0007-estate-wide-default-deny-port-policy.md).

## How it works

`lucos_firewall` runs as a container on each internet-facing lucos host (`avalon`, `xwing`, `salvare`). It:

1. Fetches the `public_ports` configuration from `lucos_configy` for the current host.
2. Generates an `iptables` + `ip6tables` ruleset: default DROP on inbound, with explicit ACCEPT rules only for ports declared in `public_ports`, plus host SSH (22), ICMP, and ESTABLISHED/RELATED tracking.
3. Applies the ruleset via `iptables-restore` / `ip6tables-restore`.
4. Polls for configy changes and re-applies when the declared port list changes.

The container requires `cap_add: NET_ADMIN` and runs with `network_mode: host` — the only legitimate use of host networking in the lucos estate (it needs the host's netfilter).

## References

- [ADR-0007: Estate-wide default-deny port policy](https://github.com/lucas42/lucos/blob/main/docs/adr/0007-estate-wide-default-deny-port-policy.md)
- [Design discussion: lucas42/lucos#169](https://github.com/lucas42/lucos/issues/169)
- [Bootstrap issue: lucas42/lucos#181](https://github.com/lucas42/lucos/issues/181)
