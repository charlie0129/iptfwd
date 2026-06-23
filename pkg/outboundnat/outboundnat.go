package outboundnat

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/pkg/errors"

	"github.com/charlie0129/iptfwd/pkg/fw"
)

type Type string

const (
	TypeMasquerade Type = "masquerade"
	TypeSNAT       Type = "snat"
)

type Defaults struct {
	OutboundIface string
	PrivateIface  string
	ManageFilter  *bool
}

type Spec struct {
	Name          string `json:"name,omitempty"`
	Source        string `json:"source"`
	OutboundIface string `json:"outbound_iface,omitempty"`
	PrivateIface  string `json:"private_iface,omitempty"`
	Type          Type   `json:"type,omitempty"`
	ToSource      string `json:"to_source,omitempty"`
	ManageFilter  *bool  `json:"manage_filter,omitempty"`
}

type NormalizedSpec struct {
	Name          string
	Family        fw.Family
	Source        netip.Prefix
	OutboundIface string
	PrivateIface  string
	Type          Type
	ToSource      netip.Addr
	ManageFilter  bool
}

func (s Spec) Normalize(defaults Defaults) (NormalizedSpec, error) {
	source, err := parsePrefix("source", s.Source)
	if err != nil {
		return NormalizedSpec{}, err
	}

	family := fw.FamilyIPv6
	if source.Addr().Is4() {
		family = fw.FamilyIPv4
	}

	outboundIface := firstNonEmpty(s.OutboundIface, defaults.OutboundIface)
	if outboundIface == "" {
		return NormalizedSpec{}, errors.New("outbound_iface is required")
	}

	natType := s.Type
	if natType == "" {
		if strings.TrimSpace(s.ToSource) != "" {
			natType = TypeSNAT
		} else {
			natType = TypeMasquerade
		}
	}

	var toSource netip.Addr
	switch natType {
	case TypeMasquerade:
		if strings.TrimSpace(s.ToSource) != "" {
			return NormalizedSpec{}, errors.New("to_source must be empty when type is masquerade")
		}
	case TypeSNAT:
		toSource, err = parseAddr("to_source", s.ToSource)
		if err != nil {
			return NormalizedSpec{}, err
		}
		if toSource.Is4() != source.Addr().Is4() {
			return NormalizedSpec{}, errors.New("to_source and source must use the same IP family")
		}
	default:
		return NormalizedSpec{}, fmt.Errorf("invalid nat type %q, expected masquerade or snat", natType)
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
		Name:          s.Name,
		Family:        family,
		Source:        source,
		OutboundIface: outboundIface,
		PrivateIface:  privateIface,
		Type:          natType,
		ToSource:      toSource,
		ManageFilter:  manageFilter,
	}, nil
}

func (s NormalizedSpec) ValidateIfaces(ifaces []string) error {
	if !slices.Contains(ifaces, s.OutboundIface) {
		return fmt.Errorf("outbound_iface %s does not exist", s.OutboundIface)
	}
	if s.ManageFilter && !slices.Contains(ifaces, s.PrivateIface) {
		return fmt.Errorf("private_iface %s does not exist", s.PrivateIface)
	}
	return nil
}

func (s NormalizedSpec) Conflicts(other NormalizedSpec) bool {
	return s.Family == other.Family &&
		s.OutboundIface == other.OutboundIface &&
		s.Source.Overlaps(other.Source)
}

func (s NormalizedSpec) Rules() []fw.Rule {
	rules := []fw.Rule{s.natRule()}
	if s.ManageFilter {
		rules = append(rules, s.filterOutRule(), s.filterInRule())
	}
	return rules
}

func (s NormalizedSpec) String() string {
	name := ""
	if s.Name != "" {
		name = s.Name + ": "
	}
	return fmt.Sprintf("%s%s %s -> %s/%s",
		name, s.Family, s.Source, s.OutboundIface, s.Type)
}

func (s NormalizedSpec) SlogAttr() []any {
	attrs := []any{
		"family", s.Family,
		"source", s.Source.String(),
		"outbound_iface", s.OutboundIface,
		"type", s.Type,
		"manage_filter", s.ManageFilter,
	}
	if s.Name != "" {
		attrs = append(attrs, "name", s.Name)
	}
	if s.PrivateIface != "" {
		attrs = append(attrs, "private_iface", s.PrivateIface)
	}
	if s.ToSource.IsValid() {
		attrs = append(attrs, "to_source", s.ToSource.String())
	}
	return attrs
}

func (s NormalizedSpec) natRule() fw.Rule {
	spec := []string{
		"-s", s.Source.String(),
		"-o", s.OutboundIface,
		"-m", "comment",
		"--comment", s.ruleComment("nat"),
	}
	if s.Type == TypeSNAT {
		spec = append(spec,
			"-j", "SNAT",
			"--to-source", s.ToSource.String(),
		)
	} else {
		spec = append(spec,
			"-j", "MASQUERADE",
		)
	}

	return fw.Rule{
		Table: "nat",
		Chain: fw.PostroutingChain,
		Spec:  spec,
	}
}

func (s NormalizedSpec) filterOutRule() fw.Rule {
	return fw.Rule{
		Table: "filter",
		Chain: fw.ForwardChain,
		Spec: []string{
			"-i", s.PrivateIface,
			"-o", s.OutboundIface,
			"-s", s.Source.String(),
			"-m", "comment",
			"--comment", s.ruleComment("filter-out"),
			"-j", "ACCEPT",
		},
	}
}

func (s NormalizedSpec) filterInRule() fw.Rule {
	return fw.Rule{
		Table: "filter",
		Chain: fw.ForwardChain,
		Spec: []string{
			"-i", s.OutboundIface,
			"-o", s.PrivateIface,
			"-d", s.Source.String(),
			"-m", "conntrack",
			"--ctstate", "ESTABLISHED,RELATED",
			"-m", "comment",
			"--comment", s.ruleComment("filter-in"),
			"-j", "ACCEPT",
		},
	}
}

func (s NormalizedSpec) ruleComment(kind string) string {
	sum := sha256.Sum256([]byte(s.identity() + "|" + kind))
	shortHash := hex.EncodeToString(sum[:6])
	return fmt.Sprintf("%s%s:outbound:%s:%s",
		fw.CommentPrefix, s.Family.Short(), kind, shortHash)
}

func (s NormalizedSpec) identity() string {
	toSource := ""
	if s.ToSource.IsValid() {
		toSource = s.ToSource.String()
	}
	return strings.Join([]string{
		string(s.Family),
		s.Source.String(),
		s.OutboundIface,
		s.PrivateIface,
		string(s.Type),
		toSource,
		fmt.Sprintf("%t", s.ManageFilter),
	}, "|")
}

func parsePrefix(field, value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	prefix = prefix.Masked()
	if prefix.Addr().IsMulticast() {
		return netip.Prefix{}, fmt.Errorf("%s must not be multicast", field)
	}
	return prefix, nil
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
