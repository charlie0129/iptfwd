package outboundnat

import (
	"slices"
	"testing"

	"github.com/charlie0129/iptfwd/pkg/fw"
)

func TestIPv4MasqueradeRule(t *testing.T) {
	spec, err := (Spec{
		Source: "10.9.14.0/24",
	}).Normalize(Defaults{
		OutboundIface: "eno1",
		PrivateIface:  "vmbr0",
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if spec.Family != fw.FamilyIPv4 {
		t.Fatalf("Family = %s, want %s", spec.Family, fw.FamilyIPv4)
	}
	if spec.Type != TypeMasquerade {
		t.Fatalf("Type = %s, want %s", spec.Type, TypeMasquerade)
	}

	rules := spec.Rules()
	if rules[0].Table != "nat" || rules[0].Chain != fw.PostroutingChain {
		t.Fatalf("NAT rule table/chain = %s/%s, want nat/%s", rules[0].Table, rules[0].Chain, fw.PostroutingChain)
	}
	if !slices.Contains(rules[0].Spec, "MASQUERADE") {
		t.Fatalf("NAT rule spec = %v, want MASQUERADE", rules[0].Spec)
	}
}

func TestIPv6SNATRule(t *testing.T) {
	spec, err := (Spec{
		Source:   "fd10:9:14::/64",
		ToSource: "2001:da8::1",
	}).Normalize(Defaults{
		OutboundIface: "eno1",
		PrivateIface:  "vmbr0",
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if spec.Family != fw.FamilyIPv6 {
		t.Fatalf("Family = %s, want %s", spec.Family, fw.FamilyIPv6)
	}
	if spec.Type != TypeSNAT {
		t.Fatalf("Type = %s, want %s", spec.Type, TypeSNAT)
	}

	nat := spec.Rules()[0]
	if !slices.Contains(nat.Spec, "SNAT") {
		t.Fatalf("NAT rule spec = %v, want SNAT", nat.Spec)
	}
	if !slices.Contains(nat.Spec, "2001:da8::1") {
		t.Fatalf("NAT rule spec = %v, want to_source", nat.Spec)
	}
}

func TestSNATRequiresMatchingToSourceFamily(t *testing.T) {
	_, err := (Spec{
		Source:   "fd10:9:14::/64",
		ToSource: "37.187.140.154",
	}).Normalize(Defaults{
		OutboundIface: "eno1",
		PrivateIface:  "vmbr0",
	})
	if err == nil {
		t.Fatal("Normalize() error = nil, want family mismatch error")
	}
}

func TestManageFilterFalseDoesNotRequirePrivateIface(t *testing.T) {
	manageFilter := false
	spec, err := (Spec{
		Source:       "10.9.14.0/24",
		ManageFilter: &manageFilter,
	}).Normalize(Defaults{OutboundIface: "eno1"})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	rules := spec.Rules()
	if len(rules) != 1 {
		t.Fatalf("len(Rules()) = %d, want 1", len(rules))
	}
}
