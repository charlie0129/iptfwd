# iptfwd

`iptfwd` manages IPv4 and IPv6 outbound NAT plus inbound port forwarding from a YAML or JSON file.

It is intended for small gateway hosts, such as a Proxmox server with:

- public interface: `eno1`
- private bridge: `vmbr0`
- private IPv4 subnet routed through IPv4 NAT
- private IPv6 ULA subnet routed through NAT66

NAT66 is usually not the preferred IPv6 design. If you have a routed IPv6 prefix, route that prefix to your private network instead. `iptfwd` supports NAT66 for constrained setups where you only have one usable public IPv6 address, such as a host with a single `/128` address but VMs that still need outbound IPv6 connectivity.

## How NAT Works

NAT rewrites packet addresses as traffic crosses the gateway. Linux conntrack records each translation so reply packets can be translated back automatically.

Outbound NAT changes the source address after routing, in `nat/POSTROUTING`:

```text
VM sends:
src=10.9.14.100:51514       dst=1.1.1.1:443

After SNAT/MASQUERADE on the gateway:
src=203.0.113.10:51514      dst=1.1.1.1:443

Reply reaches the gateway:
src=1.1.1.1:443             dst=203.0.113.10:51514

Conntrack reverses the NAT before forwarding to the VM:
src=1.1.1.1:443             dst=10.9.14.100:51514
```

Inbound port forwarding changes the destination address before routing, in `nat/PREROUTING`:

```text
Client connects:
src=198.51.100.20:41000     dst=203.0.113.10:2222

After DNAT on the gateway:
src=198.51.100.20:41000     dst=10.9.14.100:22

Reply from VM:
src=10.9.14.100:22          dst=198.51.100.20:41000

Conntrack makes the reply look like it came from the public listener:
src=203.0.113.10:2222       dst=198.51.100.20:41000
```

`iptfwd` manages both sides that are needed for forwarding:

- NAT table rules that rewrite packet addresses.
- Optional filter table rules that allow the forwarded traffic through `filter/FORWARD`.
- Optional runtime IP forwarding sysctls so Linux is allowed to route packets between interfaces.

## SNAT vs MASQUERADE

`snat` and `masquerade` both do source NAT. The difference is how the new source address is chosen.

Use `snat` when you know the exact translated source address:

```yaml
nat:
  - source: fd10:9:14::/64
    outbound_iface: eno1
    type: snat
    to_source: 2001:db8::1
```

```text
Before:
src=fd10:9:14::100          dst=2606:4700:4700::1111

After SNAT:
src=2001:db8::1             dst=2606:4700:4700::1111
```

Use `masquerade` when the gateway should use the current address on the outgoing interface:

```yaml
nat:
  - source: 10.9.14.0/24
    outbound_iface: eno1
    type: masquerade
```

```text
Before:
src=10.9.14.100             dst=1.1.1.1

After MASQUERADE, if eno1 currently has 203.0.113.10:
src=203.0.113.10            dst=1.1.1.1
```

For NAT66, prefer `snat` with an explicit `to_source`. IPv6 interfaces often have more than one address, such as link-local, stable global, temporary privacy, or addresses from multiple prefixes. NAT66 also tends to be a deliberate workaround for a specific public IPv6 address. Explicit SNAT makes the external source address predictable and avoids relying on whatever address `MASQUERADE` selects from the outgoing interface.

Rule of thumb:


- IPv4 with dynamic WAN address: masquerade is convenient
- IPv4 with fixed WAN address: snat is explicit
- IPv6 NAT66: prefer snat with `to_source`

## Config

Config files can be YAML (`.yaml`, `.yml`) or JSON (`.json`). A typical YAML config:

```yaml
defaults:
  public_iface: eno1 # public-side interface for outbound NAT and inbound port forwards
  private_iface: vmbr0 # private-side interface for inbound port forwards, e.g. a bridge with VMs
  manage_filter: true
  enable_ip_forwarding: true

nat:
  - name: intranet-v4
    source: 10.9.14.0/24 # private subnet
    type: masquerade

  - name: intranet-v6
    source: fd10:9:14::/64 # private ULA subnet
    type: snat
    to_source: 2001:db8::1 # public IPv6 address on eno1

rules:
  - name: vm100-ssh-v4
    proto: tcp
    public_port: 2222 # port on public address
    target: 10.9.14.100 # private VM IP
    target_port: 22 # private VM SSH port

  - name: vm100-ssh-v6
    proto: tcp
    public_port: 2222
    target: fd10:9:14::100
    target_port: 22

  - name: vm100-wireguard-v4
    proto: udp
    public_port: 51820
    target: 10.9.14.100
```

Top-level sections:

- `defaults`: shared defaults used by entries in `nat` and `rules`.
- `nat`: outbound source NAT rules for traffic leaving the private network.
- `rules`: inbound DNAT port-forward rules for traffic entering from the public network.

### `defaults`

```yaml
defaults:
  public_iface: eno1
  private_iface: vmbr0
  manage_filter: true
  enable_ip_forwarding: true
```

`public_iface` is the default public-side interface. For `rules`, it becomes the default `public_iface`. For `nat`, it becomes the default `outbound_iface`.

`private_iface` is the default private-side interface. When `manage_filter` is enabled, `iptfwd` needs it so it can generate `filter/FORWARD` accept rules in the right direction.

`manage_filter` defaults to `true` when omitted. When true, `iptfwd` creates forwarding allow rules in `filter/IPTFWD-FORWARD`. When false, `iptfwd` only creates NAT rules, and your existing firewall must already allow the forwarded traffic.

`enable_ip_forwarding` defaults to `true` when omitted. When true, `iptfwd` writes runtime `/proc/sys` settings for the IP families present in the config:

- IPv4 rules enable `net.ipv4.ip_forward`.
- IPv6 rules enable `net.ipv6.conf.all.forwarding` and `net.ipv6.conf.default.forwarding`.

These are runtime sysctls. Use `install-service` or your own sysctl config if you need them applied after reboot.

### `nat` Entries

Each `nat` entry creates outbound source NAT in `nat/IPTFWD-POSTROUTING`.

```yaml
nat:
  - name: intranet-v6
    source: fd10:9:14::/64
    outbound_iface: eno1
    private_iface: vmbr0
    type: snat
    to_source: 2001:db8::1
    manage_filter: true
```

Fields:

- `name`: optional label used in logs and validation errors. It does not change packet handling.
- `source`: required source prefix for private traffic that should be NATed, for example `10.9.14.0/24` or `fd10:9:14::/64`. The IP family is inferred from this prefix.
- `outbound_iface`: public-side egress interface. Defaults to `defaults.public_iface`. The NAT rule only matches packets leaving through this interface.
- `private_iface`: private-side ingress interface. Defaults to `defaults.private_iface`. Required only when `manage_filter` is true.
- `type`: either `masquerade` or `snat`. If omitted, it becomes `snat` when `to_source` is set, otherwise `masquerade`.
- `to_source`: required for `type: snat`, and must be omitted for `type: masquerade`. It must use the same IP family as `source`.
- `manage_filter`: optional per-entry override for `defaults.manage_filter`.

For `type: snat`, `iptfwd` creates a rule equivalent to:

```sh
ip6tables -t nat -A IPTFWD-POSTROUTING \
  -s fd10:9:14::/64 -o eno1 \
  -j SNAT --to-source 2001:db8::1
```

Traffic effect:

```text
Before:
src=fd10:9:14::100          dst=2606:4700:4700::1111

After:
src=2001:db8::1             dst=2606:4700:4700::1111
```

For `type: masquerade`, `iptfwd` creates a rule equivalent to:

```sh
iptables -t nat -A IPTFWD-POSTROUTING \
  -s 10.9.14.0/24 -o eno1 \
  -j MASQUERADE
```

Traffic effect:

```text
Before:
src=10.9.14.100             dst=1.1.1.1

After, assuming eno1 has 203.0.113.10:
src=203.0.113.10            dst=1.1.1.1
```

When `manage_filter` is true, each `nat` entry also allows outbound forwarding and established return traffic:

```sh
# private -> public
-i vmbr0 -o eno1 -s fd10:9:14::/64 -j ACCEPT

# public -> private replies only
-i eno1 -o vmbr0 -d fd10:9:14::/64 \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

`iptfwd` rejects overlapping `source` prefixes on the same `outbound_iface` and IP family, because two matching source NAT rules would make translation order ambiguous.

### `rules` Entries

Each `rules` entry creates an inbound port forward in `nat/IPTFWD-PREROUTING`.

```yaml
rules:
  - name: vm100-ssh-v4
    proto: tcp
    public_iface: eno1
    private_iface: vmbr0
    public_ip: 203.0.113.10
    public_port: 2222
    target: 10.9.14.100
    target_port: 22
    manage_filter: true
```

Fields:

- `name`: optional label used in logs and validation errors. It does not change packet handling.
- `proto`: required protocol, either `tcp` or `udp`.
- `public_iface`: public-side ingress interface. Defaults to `defaults.public_iface`. The DNAT rule only matches packets arriving on this interface.
- `private_iface`: private-side egress interface. Defaults to `defaults.private_iface`. Required only when `manage_filter` is true.
- `public_ip`: optional public listener address. Use it when the public interface has multiple addresses and this forward should match only one of them. It must use the same IP family as `target`.
- `public_port`: required public listener port.
- `target`: required private target address. The rule IP family is inferred from this address.
- `target_port`: private target port. Defaults to `public_port` when omitted.
- `manage_filter`: optional per-entry override for `defaults.manage_filter`.

For this rule:

```yaml
rules:
  - proto: tcp
    public_iface: eno1
    public_ip: 203.0.113.10
    public_port: 2222
    target: 10.9.14.100
    target_port: 22
```

`iptfwd` creates a DNAT rule equivalent to:

```sh
iptables -t nat -A IPTFWD-PREROUTING \
  -p tcp -i eno1 -d 203.0.113.10 --dport 2222 \
  -j DNAT --to-destination 10.9.14.100:22
```

Traffic effect:

```text
Before:
src=198.51.100.20:41000     dst=203.0.113.10:2222

After:
src=198.51.100.20:41000     dst=10.9.14.100:22
```

For IPv6 targets, the generated DNAT destination uses bracket syntax:

```sh
ip6tables -t nat -A IPTFWD-PREROUTING \
  -p tcp -i eno1 --dport 2222 \
  -j DNAT --to-destination '[fd10:9:14::100]:22'
```

When `manage_filter` is true, each port forward also allows new inbound traffic to the translated target and established return traffic back out:

```sh
# public -> private
-p tcp -i eno1 -o vmbr0 -d 10.9.14.100 --dport 22 \
  -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

# private -> public replies
-p tcp -i vmbr0 -o eno1 -s 10.9.14.100 --sport 22 \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

`iptfwd` rejects duplicate public listeners. A conflict is the same IP family, protocol, public interface, and public port where either rule has no `public_ip`, or both rules use the same `public_ip`. If you want the same port on different public addresses, set `public_ip` on every rule that shares that port.

## Managed Chains

`iptfwd` creates app-owned custom chains instead of mixing per-port rules directly into the main chains:

- `nat/IPTFWD-PREROUTING` for DNAT port forwards.
- `nat/IPTFWD-POSTROUTING` for outbound NAT/NAT66.
- `filter/IPTFWD-FORWARD` for forwarding accepts.

It installs jump rules from:

- `nat/PREROUTING` to `nat/IPTFWD-PREROUTING`.
- `nat/POSTROUTING` to `nat/IPTFWD-POSTROUTING`.
- `filter/FORWARD` to `filter/IPTFWD-FORWARD`.

The jump rules are inserted near the top of the base chains. Non-`iptfwd` rules are left alone.

## Apply

```sh
iptfwd forward --config forward.yaml --sync
```

Without `--sync`, missing managed chains, jumps, and rules are added, but stale managed rules are left alone.

With `--sync`, the config passed to `forward --sync` is treated as the complete desired state for all `iptfwd`-managed rules on the host. `iptfwd` clears and replaces rules inside `IPTFWD-*` chains, and removes managed chains and jumps that have no rules in the current config. Use one config per host. To remove a specific rule, edit that config and rerun `forward --sync`.

Useful flags:

- `--config`, `-c`: config file path. Defaults to `forward.yaml`.
- `--sync`, `-s`: make managed rules match the config exactly.
- `--timeout`: timeout in seconds for iptables commands. Defaults to `20`.
- `--skip-checks`: skip interface existence checks.
- `--log-level debug`: print normalized config details and exact iptables rule specs.

## Cleanup

Delete all `iptfwd`-managed state:

```sh
iptfwd cleanup
```

`cleanup` does not read a config file. It removes all `IPTFWD-*` chains and their jumps for IPv4 and IPv6, and leaves non-`iptfwd` rules untouched.

## Boot Service

Install `iptfwd` as a oneshot boot service:

```sh
sudo iptfwd install-service --config /etc/iptfwd/forward.yaml
```

The installer auto-detects systemd or OpenRC, copies the current binary to `/usr/local/bin/iptfwd`, writes the native service file, and enables it at boot. The service runs:

```sh
/usr/local/bin/iptfwd --log-level info forward --config /etc/iptfwd/forward.yaml --sync
```

Use `--start` to apply rules immediately after installation, or `--dry-run` to print the generated service file and commands without writing anything. Override detection with `--init systemd` or `--init openrc`.
