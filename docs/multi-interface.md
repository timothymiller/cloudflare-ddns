# Multiple interfaces and detection groups

By default every domain shares one detected IPv4 and one detected IPv6
address, and IP detection goes out through the default route. On multi-homed
hosts, such as Oracle Cloud instances with several VNICs or dual-WAN routers,
two features let each domain follow a different interface:

- **Interface-bound providers** send the detection request out through a
  specific interface.
- **Detection groups** give different domains their own providers.

They work independently and can be combined.

## Interface-bound providers

Add `@<interface>` to any HTTP-based provider: `cloudflare.trace`,
`cloudflare.doh`, `ipify` or `url:`.

```ini
IP4_PROVIDER=cloudflare.trace@ens5
IP6_PROVIDER=ipify@eth1
IP4_PROVIDER=url:https://ip.example.com@wg0
```

The request leaves through that interface, so the endpoint sees, and reports
back, the public address of that interface. This works even when the
interface itself only holds a private, NATed address.

| Platform | Mechanism |
|---|---|
| Linux, Android | `SO_BINDTODEVICE` |
| macOS, iOS, Solaris, illumos | `IP_BOUND_IF` / `IPV6_BOUND_IF` |
| Others (e.g. Windows) | Binds the interface's address as the source address. This only works with source-based routing. |

Notes:

- The binding picks the interface used for the detection request; it does
  not configure routing. A secondary interface still needs policy routing so
  that replies come back through it.
- On Linux kernels older than 5.7, `SO_BINDTODEVICE` needs `CAP_NET_RAW`.
  Run the container with `--cap-add NET_RAW` there; root containers are
  unaffected.
- The interface name must contain only letters, digits, `.`, `_` and `-`.
  The suffix is split on the last `@`, so a `url:` provider with credentials
  in it (`user:pass@host`) is not supported.
- Local providers already read a specific interface; use
  `local.iface:<name>` or `local.iface.stable:<name>` for those, not `@`.
- If the interface doesn't exist, detection fails for that cycle and existing
  records are left unchanged.

## Detection groups

The unsuffixed variables (`DOMAINS`, `IP4_PROVIDER`, …) make up the default
group. Adding a numeric suffix, starting at `_2`, defines another group:

| Variable | Meaning |
|---|---|
| `DOMAINS_N` | Domains updated with both the IPv4 and IPv6 of group N |
| `IP4_DOMAINS_N` / `IP6_DOMAINS_N` | Domains updated with only one family |
| `IP4_PROVIDER_N` / `IP6_PROVIDER_N` | Providers for group N |

Rules:

- A group with no provider for a family uses the default group's provider
  for that family. Set it to `none` to disable the family in that group.
- A group with providers but no domains is ignored, and a warning is logged.
- A domain and record type can belong to only one group. Defining it in two
  groups is a startup error.
- `_1` is rejected: the unsuffixed variables are the first group.
- When several groups use the same provider for the same family, detection
  runs once per update cycle and the result is shared.
- WAF lists (`WAF_LISTS`) receive the addresses detected by all groups. They
  are left unchanged in any cycle where a group's detection fails.
- Detection groups exist only in environment-variable mode, not in legacy
  `config.json` mode.

### Example: Oracle Cloud with a secondary VNIC

The secondary VNIC's IPv4 is NATed, so it has to be detected through the
interface. Its IPv6 is set directly on the interface and can be read locally.

```ini
# Default group: primary interface, unchanged
DOMAINS=a.example.com
IP4_PROVIDER=cloudflare.trace

# Group 2: secondary VNIC
DOMAINS_2=b.example.com
IP4_PROVIDER_2=cloudflare.trace@ens5
IP6_PROVIDER_2=local.iface:ens5
```

### Example: dual WAN

```ini
IP4_DOMAINS=wan1.example.com
IP4_PROVIDER=cloudflare.trace@eth0

IP4_DOMAINS_2=wan2.example.com
IP4_PROVIDER_2=cloudflare.trace@eth1
```

Each WAN keeps its own A record up to date. Putting both addresses on one
name (round-robin) is not supported yet, because a record can belong to only
one group. Automatic failover is not part of this feature either.
