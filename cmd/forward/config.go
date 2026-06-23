package forward

import (
	"fmt"
	"slices"

	"github.com/charlie0129/iptfwd/pkg/fw"
	"github.com/charlie0129/iptfwd/pkg/outboundnat"
	"github.com/charlie0129/iptfwd/pkg/portfwd"
)

type Config struct {
	Defaults Defaults           `json:"defaults,omitempty"`
	NAT      []outboundnat.Spec `json:"nat,omitempty"`
	Rules    []portfwd.Spec     `json:"rules,omitempty"`
}

type Defaults struct {
	PublicIface        string `json:"public_iface,omitempty"`
	PrivateIface       string `json:"private_iface,omitempty"`
	ManageFilter       *bool  `json:"manage_filter,omitempty"`
	EnableIPForwarding *bool  `json:"enable_ip_forwarding,omitempty"`
}

type NormalizedConfig struct {
	NAT   []outboundnat.NormalizedSpec
	Rules []portfwd.NormalizedSpec
}

func (c Config) Normalize(ifaces []string, checkIfaces bool) (NormalizedConfig, error) {
	portDefaults := portfwd.Defaults{
		PublicIface:  c.Defaults.PublicIface,
		PrivateIface: c.Defaults.PrivateIface,
		ManageFilter: c.Defaults.ManageFilter,
	}
	natDefaults := outboundnat.Defaults{
		OutboundIface: c.Defaults.PublicIface,
		PrivateIface:  c.Defaults.PrivateIface,
		ManageFilter:  c.Defaults.ManageFilter,
	}

	normalized := NormalizedConfig{
		NAT:   make([]outboundnat.NormalizedSpec, 0, len(c.NAT)),
		Rules: make([]portfwd.NormalizedSpec, 0, len(c.Rules)),
	}

	for idx, nat := range c.NAT {
		spec, err := nat.Normalize(natDefaults)
		if err != nil {
			return NormalizedConfig{}, fmt.Errorf("nat[%d]: %w", idx, err)
		}
		if checkIfaces {
			if err := spec.ValidateIfaces(ifaces); err != nil {
				return NormalizedConfig{}, fmt.Errorf("nat[%d] (%s): %w", idx, spec.String(), err)
			}
		}
		normalized.NAT = append(normalized.NAT, spec)
	}

	for idx, rule := range c.Rules {
		spec, err := rule.Normalize(portDefaults)
		if err != nil {
			return NormalizedConfig{}, fmt.Errorf("rules[%d]: %w", idx, err)
		}
		if checkIfaces {
			if err := spec.ValidateIfaces(ifaces); err != nil {
				return NormalizedConfig{}, fmt.Errorf("rules[%d] (%s): %w", idx, spec.String(), err)
			}
		}
		normalized.Rules = append(normalized.Rules, spec)
	}

	for i := range normalized.NAT {
		for j := i + 1; j < len(normalized.NAT); j++ {
			if normalized.NAT[i].Conflicts(normalized.NAT[j]) {
				return NormalizedConfig{}, fmt.Errorf("nat[%d] (%s) conflicts with nat[%d] (%s): overlapping source on the same outbound interface",
					i, normalized.NAT[i].String(), j, normalized.NAT[j].String())
			}
		}
	}

	for i := range normalized.Rules {
		for j := i + 1; j < len(normalized.Rules); j++ {
			if normalized.Rules[i].ListenerConflicts(normalized.Rules[j]) {
				return NormalizedConfig{}, fmt.Errorf("rules[%d] (%s) conflicts with rules[%d] (%s): same public listener",
					i, normalized.Rules[i].String(), j, normalized.Rules[j].String())
			}
		}
	}

	return normalized, nil
}

func (c Config) EnableIPForwarding() bool {
	if c.Defaults.EnableIPForwarding == nil {
		return true
	}
	return *c.Defaults.EnableIPForwarding
}

func (c NormalizedConfig) Families() []fw.Family {
	var families []fw.Family
	for _, spec := range c.NAT {
		if !slices.Contains(families, spec.Family) {
			families = append(families, spec.Family)
		}
	}
	for _, spec := range c.Rules {
		if !slices.Contains(families, spec.Family) {
			families = append(families, spec.Family)
		}
	}
	return families
}

func (c NormalizedConfig) RulesByFamily() map[fw.Family][]fw.Rule {
	grouped := make(map[fw.Family][]fw.Rule)
	for _, spec := range c.NAT {
		grouped[spec.Family] = append(grouped[spec.Family], spec.Rules()...)
	}
	for _, spec := range c.Rules {
		grouped[spec.Family] = append(grouped[spec.Family], spec.Rules()...)
	}
	return grouped
}
