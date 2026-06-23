package fw

import (
	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
)

const (
	PreroutingChain  = "IPTFWD-PREROUTING"
	PostroutingChain = "IPTFWD-POSTROUTING"
	ForwardChain     = "IPTFWD-FORWARD"

	CommentPrefix = "iptfwd:v1:"
)

type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

func AllFamilies() []Family {
	return []Family{FamilyIPv4, FamilyIPv6}
}

func (f Family) IptablesProtocol() iptables.Protocol {
	if f == FamilyIPv6 {
		return iptables.ProtocolIPv6
	}
	return iptables.ProtocolIPv4
}

func (f Family) Short() string {
	if f == FamilyIPv6 {
		return "6"
	}
	return "4"
}

type Rule struct {
	Table string
	Chain string
	Spec  []string
}

type ManagedChain struct {
	Table       string
	BaseChain   string
	UserChain   string
	JumpComment string
}

func ManagedChains() []ManagedChain {
	return []ManagedChain{
		{
			Table:       "nat",
			BaseChain:   "PREROUTING",
			UserChain:   PreroutingChain,
			JumpComment: CommentPrefix + "jump:nat-prerouting",
		},
		{
			Table:       "nat",
			BaseChain:   "POSTROUTING",
			UserChain:   PostroutingChain,
			JumpComment: CommentPrefix + "jump:nat-postrouting",
		},
		{
			Table:       "filter",
			BaseChain:   "FORWARD",
			UserChain:   ForwardChain,
			JumpComment: CommentPrefix + "jump:filter-forward",
		},
	}
}

func Apply(ipt *iptables.IPTables, chains []ManagedChain, rules []Rule, sync bool) error {
	for _, chain := range chains {
		if err := applyManagedChain(ipt, chain, RulesForChain(rules, chain.Table, chain.UserChain), sync); err != nil {
			return err
		}
	}
	return nil
}

func RulesForChain(rules []Rule, table, chain string) []Rule {
	var filtered []Rule
	for _, rule := range rules {
		if rule.Table == table && rule.Chain == chain {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

func applyManagedChain(ipt *iptables.IPTables, chain ManagedChain, rules []Rule, sync bool) error {
	if len(rules) == 0 && sync {
		exists, err := ipt.ChainExists(chain.Table, chain.UserChain)
		if err != nil {
			return errors.Wrapf(err, "failed to check %s/%s", chain.Table, chain.UserChain)
		}
		if !exists {
			return nil
		}
		if err := deleteJump(ipt, chain); err != nil {
			return err
		}
		return ipt.ClearAndDeleteChain(chain.Table, chain.UserChain)
	}
	if len(rules) == 0 {
		return nil
	}

	if sync {
		if err := ipt.ClearChain(chain.Table, chain.UserChain); err != nil {
			return errors.Wrapf(err, "failed to clear %s/%s", chain.Table, chain.UserChain)
		}
	} else if err := ensureChain(ipt, chain.Table, chain.UserChain); err != nil {
		return errors.Wrapf(err, "failed to create %s/%s", chain.Table, chain.UserChain)
	}

	if err := ensureJump(ipt, chain); err != nil {
		return err
	}

	for _, rule := range rules {
		if err := ipt.AppendUnique(rule.Table, rule.Chain, rule.Spec...); err != nil {
			return errors.Wrapf(err, "failed to append %s/%s rule %s", rule.Table, rule.Chain, rule.Spec)
		}
	}

	return nil
}

func ensureChain(ipt *iptables.IPTables, table, chain string) error {
	exists, err := ipt.ChainExists(table, chain)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return ipt.NewChain(table, chain)
}

func ensureJump(ipt *iptables.IPTables, chain ManagedChain) error {
	if err := ipt.InsertUnique(chain.Table, chain.BaseChain, 1, jumpSpec(chain)...); err != nil {
		return errors.Wrapf(err, "failed to install %s/%s jump to %s", chain.Table, chain.BaseChain, chain.UserChain)
	}
	return nil
}

func deleteJump(ipt *iptables.IPTables, chain ManagedChain) error {
	if err := ipt.DeleteIfExists(chain.Table, chain.BaseChain, jumpSpec(chain)...); err != nil {
		return errors.Wrapf(err, "failed to delete %s/%s jump to %s", chain.Table, chain.BaseChain, chain.UserChain)
	}
	return nil
}

func jumpSpec(chain ManagedChain) []string {
	return []string{
		"-m", "comment",
		"--comment", chain.JumpComment,
		"-j", chain.UserChain,
	}
}
