# iptfwd

`iptfwd` manages IPv4 and IPv6 outbound NAT plus port forwarding from a YAML or JSON file.

It is intended for small NAT/NAT66 gateway hosts, such as a Proxmox server with:

- public interface: `eno1`
- private bridge: `vmbr0`
- private IPv4 subnet routed through NAT
- private IPv6 ULA subnet routed through NAT66. Before criticizing me: yeah I know NAT66 is not recommended, but sometimes you only have a /128 IP address (like Kimsufi bare metal servers) and you want your VMs to have IPv6 connectivity. This is a simple way to do it.

## Config

```yaml
defaults:
  public_iface: eno1
  private_iface: vmbr0
  manage_filter: true
  enable_ip_forwarding: true

nat:
  - name: intranet-v4
    source: 10.9.14.0/24
    type: masquerade

  - name: intranet-v6
    source: fd10:9:14::/64
    type: snat
    to_source: 2001:da8::1

rules:
  - name: vm100-ssh-v4
    proto: tcp
    public_port: 2222
    target: 10.9.14.100
    target_port: 22

  - name: vm100-ssh-v6
    proto: tcp
    public_port: 2222
    target: fd10:9:14::100
    target_port: 22
```

`target_port` defaults to `public_port` when omitted. The rule IP family is inferred from `target`.

`public_ip` is optional. Use it when the public interface has multiple public addresses and the forward should bind only one address.

`nat` entries configure outbound gateway NAT. `source` determines the IP family. `outbound_iface` defaults to `defaults.public_iface`, and `private_iface` defaults to `defaults.private_iface`. When `type` is omitted, it defaults to `snat` if `to_source` is set, otherwise `masquerade`.

## Apply

```sh
iptfwd forward --config forward.yaml --sync
```

Without `--sync`, missing rules are added and stale rules are left alone. With `--sync`, app-owned rules are made to match the config.

`iptfwd` treats the config passed to `forward --sync` as the complete desired state for all iptfwd-managed rules on the host. It clears and replaces rules inside `IPTFWD-*` chains, and removes managed chains/jumps that have no rules in the current config. Use one config per host. To remove a specific rule, edit that config and rerun `forward --sync`.

## Cleanup

Delete all iptfwd-managed state:

```sh
iptfwd cleanup
```

`cleanup` does not read a config file. It removes all `IPTFWD-*` chains and their jumps for IPv4 and IPv6, and leaves non-iptfwd rules untouched.

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

## Behavior

`iptfwd` creates app-owned custom chains instead of mixing per-port rules directly into the main chains:

- `nat/IPTFWD-PREROUTING` for DNAT
- `nat/IPTFWD-POSTROUTING` for outbound NAT/NAT66
- `filter/IPTFWD-FORWARD` for forwarding accepts

It installs jumps from `nat/PREROUTING`, `nat/POSTROUTING`, and `filter/FORWARD` when corresponding rules exist. If `manage_filter` is enabled, outbound NAT gets private-to-public accept rules plus established/related return-path accepts; port forwards get public-to-private accepts plus established/related return-path accepts.

When `enable_ip_forwarding` is true, `iptfwd` tries to enable the runtime sysctls needed by the configured rule families:

- `net.ipv4.ip_forward`
- `net.ipv6.conf.all.forwarding`
- `net.ipv6.conf.default.forwarding`
