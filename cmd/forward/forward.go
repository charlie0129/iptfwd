package forward

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/charlie0129/iptfwd/pkg/fw"
	"github.com/charlie0129/iptfwd/pkg/sysctl"
	"github.com/charlie0129/iptfwd/pkg/utils"
)

var (
	sync           = false
	timeoutSeconds = 20
	configFile     = "forward.yaml"
	skipChecks     = false
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "forward",
		Aliases: []string{"fwd"},
		Short:   "Manage NAT and port forwarding",
		Long: `Manage outbound NAT and port forwarding using iptables/ip6tables.

Config model:
  iptfwd treats one config file as the desired state for this host. The config
  can contain outbound NAT/NAT66 rules in "nat:" and DNAT port forwards in
  "rules:".

Managed chains:
  nat/IPTFWD-PREROUTING   DNAT port forwards
  nat/IPTFWD-POSTROUTING  outbound NAT/NAT66
  filter/IPTFWD-FORWARD   forwarding accepts

Sync behavior:
  Without --sync, iptfwd adds missing managed chains, jumps, and rules, but
  leaves stale managed rules in place.

  With --sync, the given config is the complete desired state for all
  iptfwd-managed rules on the host. iptfwd clears and replaces rules inside
  IPTFWD-* chains, and deletes managed chains/jumps that have no rules in the
  current config. Use one config per host. To remove one rule, edit the config
  and rerun forward --sync.

Logging:
  Info logs show actual changes and high-level apply progress. Debug logs add
  normalized config details, skip decisions, and exact iptables rule specs.`,
		Example: `  iptfwd forward --config /etc/iptfwd/forward.yaml --sync
  iptfwd --log-level debug forward --config forward.yaml --sync`,
		RunE: run,
	}

	f := cmd.Flags()
	f.BoolVarP(&sync, "sync", "s", sync, "Make iptfwd-managed rules match the config exactly")
	f.IntVar(&timeoutSeconds, "timeout", timeoutSeconds, "Timeout in seconds for iptables commands")
	f.StringVarP(&configFile, "config", "c", configFile, "Use this forward config file instead of the default")
	f.BoolVar(&skipChecks, "skip-checks", skipChecks, "Skip interface existence checks")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	config, err := loadConfig(configFile)
	if err != nil {
		return err
	}
	slog.Debug("Loaded config file", "path", configFile)

	var ifaces []string
	if !skipChecks {
		ifaces, err = utils.ListIfaces()
		if err != nil {
			return errors.Wrapf(err, "failed to list interfaces")
		}
		slog.Debug("Listed network interfaces", "interfaces", ifaces)
	} else {
		slog.Debug("Skipped interface existence checks")
	}

	normalized, err := config.Normalize(ifaces, !skipChecks)
	if err != nil {
		return errors.Wrap(err, "config validation failed")
	}
	slog.Debug(
		"Normalized config",
		"nat_rules", len(normalized.NAT),
		"port_forward_rules", len(normalized.Rules),
		"enable_ip_forwarding", config.EnableIPForwarding(),
	)

	families := normalized.Families()
	if config.EnableIPForwarding() && len(families) > 0 {
		changed, err := sysctl.EnsureIPForwarding(families)
		if err != nil {
			return errors.Wrap(err, "failed to enable IP forwarding")
		}
		for _, setting := range changed {
			slog.Info("Enabled IP forwarding setting", "setting", setting)
		}
		if len(changed) == 0 {
			slog.Debug("IP forwarding settings already enabled", "families", families)
		}
	} else if !config.EnableIPForwarding() {
		slog.Debug("Skipped IP forwarding setup because it is disabled in config")
	}

	grouped := normalized.RulesByFamily()
	familiesToApply := families
	if sync {
		familiesToApply = fw.AllFamilies()
	}

	for _, family := range familiesToApply {
		rules := grouped[family]
		if len(rules) == 0 && !sync {
			continue
		}

		ipt, err := iptables.New(
			iptables.IPFamily(family.IptablesProtocol()),
			iptables.Timeout(timeoutSeconds),
		)
		if err != nil {
			if len(rules) == 0 && sync {
				slog.Debug("Skipping empty family because iptables handler is unavailable", "family", family, "error", err)
				continue
			}
			return errors.Wrapf(err, "failed to create %s iptables handler", family)
		}
		slog.Debug("Created iptables handler", "family", family, "rules", len(rules), "sync", sync)

		slog.Info("Applying managed rules", "family", family, "rules", len(rules), "sync", sync)
		logNormalizedRules(family, normalized)
		if err := fw.Apply(ipt, fw.ManagedChains(), rules, sync); err != nil {
			return errors.Wrapf(err, "failed to apply %s rules", family)
		}
		slog.Info("Applied managed rules", "family", family, "rules", len(rules), "sync", sync)
	}

	return nil
}

func logNormalizedRules(family fw.Family, normalized NormalizedConfig) {
	for idx, spec := range normalized.NAT {
		if spec.Family == family {
			attrs := append([]any{"index", idx}, spec.SlogAttr()...)
			slog.Debug("Prepared outbound NAT rule", attrs...)
		}
	}
	for idx, spec := range normalized.Rules {
		if spec.Family == family {
			attrs := append([]any{"index", idx}, spec.SlogAttr()...)
			slog.Debug("Prepared port forwarding rule", attrs...)
		}
	}
}

func loadConfig(path string) (*Config, error) {
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		yamlBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open config file")
		}
		var config Config
		if err := yaml.Unmarshal(yamlBytes, &config); err != nil {
			return nil, errors.Wrap(err, "failed to decode config file")
		}
		return &config, nil
	}

	if strings.HasSuffix(path, ".json") {
		configFd, err := os.Open(path)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open config file")
		}
		defer configFd.Close()

		var config Config
		if err := json.NewDecoder(configFd).Decode(&config); err != nil {
			return nil, errors.Wrap(err, "failed to decode config file")
		}
		return &config, nil
	}

	return nil, errors.New("unsupported config file format, only yaml and json are supported")
}
