package fw

import (
	"log/slog"

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
	slog.Debug("Applying managed rules", "managed_chains", len(chains), "rules", len(rules), "sync", sync)
	for _, chain := range chains {
		if err := applyManagedChain(ipt, chain, RulesForChain(rules, chain.Table, chain.UserChain), sync); err != nil {
			return err
		}
	}
	return nil
}

func Cleanup(ipt *iptables.IPTables, chains []ManagedChain) error {
	slog.Debug("Cleaning up managed chains", "managed_chains", len(chains))
	for _, chain := range chains {
		if err := cleanupManagedChain(ipt, chain); err != nil {
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
	logger := slog.With(
		"table", chain.Table,
		"base_chain", chain.BaseChain,
		"chain", chain.UserChain,
		"rules", len(rules),
	)
	logger.Debug("Checking managed chain", "sync", sync)

	if len(rules) == 0 && sync {
		return cleanupManagedChain(ipt, chain)
	}
	if len(rules) == 0 {
		logger.Debug("No configured rules for managed chain")
		return nil
	}

	if sync {
		if err := resetChain(ipt, chain.Table, chain.UserChain); err != nil {
			return err
		}
	} else if err := ensureChain(ipt, chain.Table, chain.UserChain); err != nil {
		return errors.Wrapf(err, "failed to create %s/%s", chain.Table, chain.UserChain)
	}

	if err := ensureJump(ipt, chain); err != nil {
		return err
	}

	for _, rule := range rules {
		if err := appendRule(ipt, rule); err != nil {
			return err
		}
	}

	return nil
}

func cleanupManagedChain(ipt *iptables.IPTables, chain ManagedChain) error {
	logger := slog.With(
		"table", chain.Table,
		"base_chain", chain.BaseChain,
		"chain", chain.UserChain,
	)

	if err := deleteJump(ipt, chain); err != nil {
		return err
	}

	exists, err := ipt.ChainExists(chain.Table, chain.UserChain)
	if err != nil {
		return errors.Wrapf(err, "failed to check %s/%s", chain.Table, chain.UserChain)
	}
	if !exists {
		logger.Debug("Managed chain does not exist; nothing to delete")
		return nil
	}

	if err := ipt.ClearAndDeleteChain(chain.Table, chain.UserChain); err != nil {
		return errors.Wrapf(err, "failed to delete %s/%s", chain.Table, chain.UserChain)
	}
	logger.Info("Deleted managed chain")
	return nil
}

func resetChain(ipt *iptables.IPTables, table, chain string) error {
	exists, err := ipt.ChainExists(table, chain)
	if err != nil {
		return errors.Wrapf(err, "failed to check %s/%s", table, chain)
	}
	if !exists {
		if err := ipt.NewChain(table, chain); err != nil {
			return errors.Wrapf(err, "failed to create %s/%s", table, chain)
		}
		slog.Info("Created managed chain", "table", table, "chain", chain)
		return nil
	}

	if err := ipt.ClearChain(table, chain); err != nil {
		return errors.Wrapf(err, "failed to clear %s/%s", table, chain)
	}
	slog.Info("Cleared managed chain", "table", table, "chain", chain)
	return nil
}

func ensureChain(ipt *iptables.IPTables, table, chain string) error {
	exists, err := ipt.ChainExists(table, chain)
	if err != nil {
		return errors.Wrapf(err, "failed to check %s/%s", table, chain)
	}
	if exists {
		slog.Debug("Managed chain already exists", "table", table, "chain", chain)
		return nil
	}
	if err := ipt.NewChain(table, chain); err != nil {
		return errors.Wrapf(err, "failed to create %s/%s", table, chain)
	}
	slog.Info("Created managed chain", "table", table, "chain", chain)
	return nil
}

func ensureJump(ipt *iptables.IPTables, chain ManagedChain) error {
	spec := jumpSpec(chain)
	exists, err := ipt.Exists(chain.Table, chain.BaseChain, spec...)
	if err != nil {
		return errors.Wrapf(err, "failed to check %s/%s jump to %s", chain.Table, chain.BaseChain, chain.UserChain)
	}
	if exists {
		slog.Debug(
			"Jump rule already exists",
			"table", chain.Table,
			"base_chain", chain.BaseChain,
			"chain", chain.UserChain,
			"spec", spec,
		)
		return nil
	}
	if err := ipt.Insert(chain.Table, chain.BaseChain, 1, spec...); err != nil {
		return errors.Wrapf(err, "failed to install %s/%s jump to %s", chain.Table, chain.BaseChain, chain.UserChain)
	}
	slog.Info("Installed jump rule", "table", chain.Table, "base_chain", chain.BaseChain, "chain", chain.UserChain)
	slog.Debug("Installed jump rule details", "table", chain.Table, "base_chain", chain.BaseChain, "spec", spec)
	return nil
}

func deleteJump(ipt *iptables.IPTables, chain ManagedChain) error {
	spec := jumpSpec(chain)
	exists, err := ipt.Exists(chain.Table, chain.BaseChain, spec...)
	if err != nil {
		return errors.Wrapf(err, "failed to check %s/%s jump to %s", chain.Table, chain.BaseChain, chain.UserChain)
	}
	if !exists {
		slog.Debug(
			"Jump rule does not exist",
			"table", chain.Table,
			"base_chain", chain.BaseChain,
			"chain", chain.UserChain,
			"spec", spec,
		)
		return nil
	}
	if err := ipt.Delete(chain.Table, chain.BaseChain, spec...); err != nil {
		return errors.Wrapf(err, "failed to delete %s/%s jump to %s", chain.Table, chain.BaseChain, chain.UserChain)
	}
	slog.Info("Deleted jump rule", "table", chain.Table, "base_chain", chain.BaseChain, "chain", chain.UserChain)
	slog.Debug("Deleted jump rule details", "table", chain.Table, "base_chain", chain.BaseChain, "spec", spec)
	return nil
}

func appendRule(ipt *iptables.IPTables, rule Rule) error {
	exists, err := ipt.Exists(rule.Table, rule.Chain, rule.Spec...)
	if err != nil {
		return errors.Wrapf(err, "failed to check %s/%s rule %s", rule.Table, rule.Chain, rule.Spec)
	}
	if exists {
		slog.Debug("Managed rule already exists", "table", rule.Table, "chain", rule.Chain, "spec", rule.Spec)
		return nil
	}

	if err := ipt.Append(rule.Table, rule.Chain, rule.Spec...); err != nil {
		return errors.Wrapf(err, "failed to append %s/%s rule %s", rule.Table, rule.Chain, rule.Spec)
	}
	slog.Info("Added managed rule", "table", rule.Table, "chain", rule.Chain)
	slog.Debug("Added managed rule details", "table", rule.Table, "chain", rule.Chain, "spec", rule.Spec)
	return nil
}

func jumpSpec(chain ManagedChain) []string {
	return []string{
		"-m", "comment",
		"--comment", chain.JumpComment,
		"-j", chain.UserChain,
	}
}
