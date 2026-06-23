package forward

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/charlie0129/iptfwd/pkg/fw"
)

func TestConfigNormalizeDualStack(t *testing.T) {
	var config Config
	err := yaml.Unmarshal([]byte(`
defaults:
  public_iface: eno1
  private_iface: vmbr0
nat:
  - name: intranet-v4
    source: 10.9.14.0/24
  - name: intranet-v6
    source: fd10:9:14::/64
    type: snat
    to_source: 2001:da8::1
rules:
  - name: vm4-ssh
    proto: tcp
    public_port: 2222
    target: 10.9.14.100
    target_port: 22
  - name: vm6-ssh
    proto: tcp
    public_port: 2222
    target: fd10:9:14::100
    target_port: 22
`), &config)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	normalized, err := config.Normalize([]string{"eno1", "vmbr0"}, true)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(normalized.NAT) != 2 {
		t.Fatalf("len(normalized.NAT) = %d, want 2", len(normalized.NAT))
	}
	if len(normalized.Rules) != 2 {
		t.Fatalf("len(normalized.Rules) = %d, want 2", len(normalized.Rules))
	}
	if normalized.NAT[0].Family != fw.FamilyIPv4 {
		t.Fatalf("normalized.NAT[0].Family = %s, want ipv4", normalized.NAT[0].Family)
	}
	if normalized.NAT[1].Family != fw.FamilyIPv6 {
		t.Fatalf("normalized.NAT[1].Family = %s, want ipv6", normalized.NAT[1].Family)
	}
	if normalized.Rules[0].Family != fw.FamilyIPv4 {
		t.Fatalf("normalized.Rules[0].Family = %s, want ipv4", normalized.Rules[0].Family)
	}
	if normalized.Rules[1].Family != fw.FamilyIPv6 {
		t.Fatalf("normalized.Rules[1].Family = %s, want ipv6", normalized.Rules[1].Family)
	}
}

func TestConfigRejectsDuplicateListener(t *testing.T) {
	var config Config
	err := yaml.Unmarshal([]byte(`
defaults:
  public_iface: eno1
  private_iface: vmbr0
rules:
  - proto: tcp
    public_port: 443
    target: 10.9.14.10
  - proto: tcp
    public_port: 443
    target: 10.9.14.11
`), &config)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	_, err = config.Normalize([]string{"eno1", "vmbr0"}, true)
	if err == nil {
		t.Fatal("Normalize() error = nil, want duplicate listener error")
	}
	if !strings.Contains(err.Error(), "same public listener") {
		t.Fatalf("Normalize() error = %v, want same public listener", err)
	}
}

func TestEnableIPForwardingCanBeDisabled(t *testing.T) {
	var config Config
	err := yaml.Unmarshal([]byte(`
defaults:
  public_iface: eno1
  private_iface: vmbr0
  enable_ip_forwarding: false
rules:
  - proto: udp
    public_port: 51820
    target: fd10:9:14::100
`), &config)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if config.EnableIPForwarding() {
		t.Fatal("EnableIPForwarding() = true, want false")
	}
	normalized, err := config.Normalize([]string{"eno1", "vmbr0"}, true)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if normalized.Rules[0].PublicIface != "eno1" || normalized.Rules[0].PrivateIface != "vmbr0" {
		t.Fatalf("defaults not applied: %+v", normalized.Rules[0])
	}
}

func TestConfigRejectsOverlappingNATSource(t *testing.T) {
	var config Config
	err := yaml.Unmarshal([]byte(`
defaults:
  public_iface: eno1
  private_iface: vmbr0
nat:
  - source: 10.9.14.0/24
  - source: 10.9.14.128/25
`), &config)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	_, err = config.Normalize([]string{"eno1", "vmbr0"}, true)
	if err == nil {
		t.Fatal("Normalize() error = nil, want overlapping NAT source error")
	}
	if !strings.Contains(err.Error(), "overlapping source") {
		t.Fatalf("Normalize() error = %v, want overlapping source", err)
	}
}
