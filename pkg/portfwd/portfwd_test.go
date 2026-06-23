package portfwd

import (
	"slices"
	"testing"

	"github.com/charlie0129/iptfwd/pkg/fw"
)

func TestIPv6DNATUsesBracketedDestination(t *testing.T) {
	spec, err := (Spec{
		Proto:        ProtoTCP,
		PublicIface:  "eno1",
		PrivateIface: "vmbr0",
		PublicPort:   443,
		Target:       "fd10:9:14::100",
		TargetPort:   8443,
	}).Normalize(Defaults{})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if spec.Family != fw.FamilyIPv6 {
		t.Fatalf("family = %s, want %s", spec.Family, fw.FamilyIPv6)
	}

	dnat := spec.Rules()[0]
	if dnat.Table != "nat" || dnat.Chain != fw.PreroutingChain {
		t.Fatalf("DNAT rule table/chain = %s/%s, want nat/%s", dnat.Table, dnat.Chain, fw.PreroutingChain)
	}
	if !slices.Contains(dnat.Spec, "[fd10:9:14::100]:8443") {
		t.Fatalf("DNAT spec = %v, want bracketed IPv6 destination", dnat.Spec)
	}
}

func TestTargetPortDefaultsToPublicPort(t *testing.T) {
	spec, err := (Spec{
		Proto:        ProtoUDP,
		PublicIface:  "eno1",
		PrivateIface: "vmbr0",
		PublicPort:   51820,
		Target:       "10.9.14.100",
	}).Normalize(Defaults{})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if spec.TargetPort != 51820 {
		t.Fatalf("TargetPort = %d, want 51820", spec.TargetPort)
	}
}

func TestManageFilterFalseDoesNotRequirePrivateIface(t *testing.T) {
	manageFilter := false
	spec, err := (Spec{
		Proto:        ProtoTCP,
		PublicIface:  "eno1",
		PublicPort:   2222,
		Target:       "10.9.14.100",
		TargetPort:   22,
		ManageFilter: &manageFilter,
	}).Normalize(Defaults{})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	rules := spec.Rules()
	if len(rules) != 1 {
		t.Fatalf("len(Rules()) = %d, want 1", len(rules))
	}
	if rules[0].Table != "nat" {
		t.Fatalf("only rule table = %s, want nat", rules[0].Table)
	}
}

func TestPublicIPMustMatchTargetFamily(t *testing.T) {
	_, err := (Spec{
		Proto:        ProtoTCP,
		PublicIface:  "eno1",
		PrivateIface: "vmbr0",
		PublicIP:     "2001:db8::1",
		PublicPort:   443,
		Target:       "10.9.14.100",
	}).Normalize(Defaults{})
	if err == nil {
		t.Fatal("Normalize() error = nil, want family mismatch error")
	}
}
