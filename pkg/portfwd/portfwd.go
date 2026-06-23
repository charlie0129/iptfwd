package portfwd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/charlie0129/iptfwd/pkg/fw"
)

type Defaults struct {
	PublicIface  string
	PrivateIface string
	ManageFilter *bool
}

type Spec struct {
	Name         string `json:"name,omitempty"`
	Proto        Proto  `json:"proto"`
	PublicIface  string `json:"public_iface,omitempty"`
	PrivateIface string `json:"private_iface,omitempty"`
	PublicIP     string `json:"public_ip,omitempty"`
	PublicPort   uint16 `json:"public_port,omitempty"`
	Target       string `json:"target,omitempty"`
	TargetPort   uint16 `json:"target_port,omitempty"`
	ManageFilter *bool  `json:"manage_filter,omitempty"`
}

type NormalizedSpec struct {
	Name         string
	Proto        Proto
	Family       fw.Family
	PublicIface  string
	PrivateIface string
	PublicIP     netip.Addr
	PublicPort   uint16
	Target       netip.Addr
	TargetPort   uint16
	ManageFilter bool
}

func (s Spec) Normalize(defaults Defaults) (NormalizedSpec, error) {
	var err error

	proto, err := NewProto(string(s.Proto))
	if err != nil {
		return NormalizedSpec{}, err
	}

	publicIface := firstNonEmpty(s.PublicIface, defaults.PublicIface)
	if publicIface == "" {
		return NormalizedSpec{}, errors.New("public_iface is required")
	}

	publicPort := s.PublicPort
	if publicPort == 0 {
		return NormalizedSpec{}, errors.New("public_port is required and must be greater than 0")
	}

	target := strings.TrimSpace(s.Target)
	if target == "" {
		return NormalizedSpec{}, errors.New("target is required")
	}
	targetIP, err := parseAddr("target", target)
	if err != nil {
		return NormalizedSpec{}, err
	}

	family := fw.FamilyIPv6
	if targetIP.Is4() {
		family = fw.FamilyIPv4
	}

	var publicIP netip.Addr
	if strings.TrimSpace(s.PublicIP) != "" {
		publicIP, err = parseAddr("public_ip", s.PublicIP)
		if err != nil {
			return NormalizedSpec{}, err
		}
		if publicIP.Is4() != targetIP.Is4() {
			return NormalizedSpec{}, fmt.Errorf("public_ip and target must use the same IP family")
		}
	}

	targetPort := s.TargetPort
	if targetPort == 0 {
		targetPort = publicPort
	}

	manageFilter := true
	if defaults.ManageFilter != nil {
		manageFilter = *defaults.ManageFilter
	}
	if s.ManageFilter != nil {
		manageFilter = *s.ManageFilter
	}

	privateIface := firstNonEmpty(s.PrivateIface, defaults.PrivateIface)
	if manageFilter && privateIface == "" {
		return NormalizedSpec{}, errors.New("private_iface is required when manage_filter is enabled")
	}

	return NormalizedSpec{
		Name:         s.Name,
		Proto:        proto,
		Family:       family,
		PublicIface:  publicIface,
		PrivateIface: privateIface,
		PublicIP:     publicIP,
		PublicPort:   publicPort,
		Target:       targetIP,
		TargetPort:   targetPort,
		ManageFilter: manageFilter,
	}, nil
}

func (s NormalizedSpec) ValidateIfaces(ifaces []string) error {
	if !slices.Contains(ifaces, s.PublicIface) {
		return fmt.Errorf("public_iface %s does not exist", s.PublicIface)
	}
	if s.ManageFilter && !slices.Contains(ifaces, s.PrivateIface) {
		return fmt.Errorf("private_iface %s does not exist", s.PrivateIface)
	}
	return nil
}

func (s NormalizedSpec) ListenerConflicts(other NormalizedSpec) bool {
	if s.Family != other.Family ||
		s.Proto != other.Proto ||
		s.PublicIface != other.PublicIface ||
		s.PublicPort != other.PublicPort {
		return false
	}

	if !s.PublicIP.IsValid() || !other.PublicIP.IsValid() {
		return true
	}
	return s.PublicIP == other.PublicIP
}

func (s NormalizedSpec) Rules() []fw.Rule {
	rules := []fw.Rule{s.dnatRule()}
	if s.ManageFilter {
		rules = append(rules, s.filterInRule(), s.filterOutRule())
	}
	return rules
}

func (s NormalizedSpec) String() string {
	name := ""
	if s.Name != "" {
		name = s.Name + ": "
	}
	return fmt.Sprintf("%s%s/%s %s:%d -> %s:%d",
		name, s.Family, s.Proto, s.PublicIface, s.PublicPort, s.Target, s.TargetPort)
}

func (s NormalizedSpec) SlogAttr() []any {
	attrs := []any{
		"family", s.Family,
		"proto", s.Proto,
		"public_iface", s.PublicIface,
		"public_port", s.PublicPort,
		"target", s.Target.String(),
		"target_port", s.TargetPort,
		"manage_filter", s.ManageFilter,
	}
	if s.Name != "" {
		attrs = append(attrs, "name", s.Name)
	}
	if s.PrivateIface != "" {
		attrs = append(attrs, "private_iface", s.PrivateIface)
	}
	if s.PublicIP.IsValid() {
		attrs = append(attrs, "public_ip", s.PublicIP.String())
	}
	return attrs
}

func (s NormalizedSpec) dnatRule() fw.Rule {
	spec := []string{
		"-p", string(s.Proto),
		"-i", s.PublicIface,
	}
	if s.PublicIP.IsValid() {
		spec = append(spec, "-d", s.PublicIP.String())
	}
	spec = append(spec,
		"--dport", portString(s.PublicPort),
		"-m", "comment",
		"--comment", s.ruleComment("dnat"),
		"-j", "DNAT",
		"--to-destination", s.dnatDestination(),
	)

	return fw.Rule{
		Table: "nat",
		Chain: fw.PreroutingChain,
		Spec:  spec,
	}
}

func (s NormalizedSpec) filterInRule() fw.Rule {
	spec := []string{
		"-p", string(s.Proto),
		"-i", s.PublicIface,
		"-o", s.PrivateIface,
		"-d", s.Target.String(),
		"--dport", portString(s.TargetPort),
		"-m", "conntrack",
		"--ctstate", "NEW,ESTABLISHED,RELATED",
		"-m", "comment",
		"--comment", s.ruleComment("filter-in"),
		"-j", "ACCEPT",
	}

	return fw.Rule{
		Table: "filter",
		Chain: fw.ForwardChain,
		Spec:  spec,
	}
}

func (s NormalizedSpec) filterOutRule() fw.Rule {
	spec := []string{
		"-p", string(s.Proto),
		"-i", s.PrivateIface,
		"-o", s.PublicIface,
		"-s", s.Target.String(),
		"--sport", portString(s.TargetPort),
		"-m", "conntrack",
		"--ctstate", "ESTABLISHED,RELATED",
		"-m", "comment",
		"--comment", s.ruleComment("filter-out"),
		"-j", "ACCEPT",
	}

	return fw.Rule{
		Table: "filter",
		Chain: fw.ForwardChain,
		Spec:  spec,
	}
}

func (s NormalizedSpec) dnatDestination() string {
	if s.Family == fw.FamilyIPv6 {
		return "[" + s.Target.String() + "]:" + portString(s.TargetPort)
	}
	return s.Target.String() + ":" + portString(s.TargetPort)
}

func (s NormalizedSpec) ruleComment(kind string) string {
	sum := sha256.Sum256([]byte(s.identity() + "|" + kind))
	shortHash := hex.EncodeToString(sum[:6])
	return fmt.Sprintf("%s%s:%s:%s:%d:%s",
		fw.CommentPrefix, s.Family.Short(), kind, s.Proto, s.PublicPort, shortHash)
}

func (s NormalizedSpec) identity() string {
	publicIP := "*"
	if s.PublicIP.IsValid() {
		publicIP = s.PublicIP.String()
	}
	return strings.Join([]string{
		string(s.Family),
		string(s.Proto),
		s.PublicIface,
		publicIP,
		portString(s.PublicPort),
		s.PrivateIface,
		s.Target.String(),
		portString(s.TargetPort),
		strconv.FormatBool(s.ManageFilter),
	}, "|")
}

func parseAddr(field, value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("%s must not be unspecified", field)
	}
	if addr.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("%s must not be multicast", field)
	}
	return addr, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func portString(port uint16) string {
	return strconv.FormatUint(uint64(port), 10)
}
