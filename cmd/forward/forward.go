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

By default, iptfwd appends missing rules but does not delete stale rules. Use --sync to make the app-owned custom chains match the config exactly.

iptfwd owns only its IPTFWD-* chains.`,
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

	var ifaces []string
	if !skipChecks {
		ifaces, err = utils.ListIfaces()
		if err != nil {
			return errors.Wrapf(err, "failed to list interfaces")
		}
	}

	normalized, err := config.Normalize(ifaces, !skipChecks)
	if err != nil {
		return errors.Wrap(err, "config validation failed")
	}

	families := normalized.Families()
	if config.EnableIPForwarding() && len(families) > 0 {
		changed, err := sysctl.EnsureIPForwarding(families)
		if err != nil {
			return errors.Wrap(err, "failed to enable IP forwarding")
		}
		for _, setting := range changed {
			slog.Info("Enabled IP forwarding setting", "setting", setting)
		}
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

		for _, spec := range normalized.NAT {
			if spec.Family == family {
				slog.Info("Applying outbound NAT rule", spec.SlogAttr()...)
			}
		}
		for _, spec := range normalized.Rules {
			if spec.Family == family {
				slog.Info("Applying port forwarding rule", spec.SlogAttr()...)
			}
		}

		if err := fw.Apply(ipt, fw.ManagedChains(), rules, sync); err != nil {
			return errors.Wrapf(err, "failed to apply %s rules", family)
		}
	}

	return nil
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
