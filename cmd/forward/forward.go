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

	"github.com/charlie0129/iptfwd/pkg/portfwd"
	"github.com/charlie0129/iptfwd/pkg/utils"
)

var (
	// allowModifyingExternalRules = false
	sync           = false
	timeoutSeconds = 20
	configFile     = "forward.yaml"
	config         *Config
	skipChecks     = false
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "forward",
		Aliases: []string{"fwd"},
		Short:   "Forward ports",
		Long: `Forward ports using iptables.

By default, it will not delete or modify rules. If you want to make sure the rules in iptables created by iptfwd are in sync with the config, use the --sync flag.

iptfwd will only manage rules that are created by itself.`,
		RunE: run,
	}

	f := cmd.Flags()
	// f.BoolVarP(&allowModifyingExternalRules, "allow-modifying-external-rules", "a", allowModifyingExternalRules, "Allow modifying rules that are not managed by iptfwd")
	f.BoolVarP(&sync, "sync", "s", sync, "Make sure the rules that are managed by iptfwd in iptables are in sync with the config")
	f.IntVar(&timeoutSeconds, "timeout", timeoutSeconds, "Timeout in seconds for iptables commands")
	f.StringVarP(&configFile, "config", "c", configFile, "Use this forward config file instead of the default")
	f.BoolVar(&skipChecks, "skip-checks", skipChecks, "Skip checks for interfaces and rules")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	if strings.HasSuffix(configFile, ".yaml") || strings.HasSuffix(configFile, ".yml") {
		yamlBytes, err := os.ReadFile(configFile)
		if err != nil {
			return errors.Wrapf(err, "failed to open config file")
		}
		err = yaml.Unmarshal(yamlBytes, &config)
		if err != nil {
			return errors.Wrapf(err, "failed to decode config file")
		}
	} else if strings.HasSuffix(configFile, ".json") {
		configFd, err := os.Open(configFile)
		if err != nil {
			return errors.Wrapf(err, "failed to open config file")
		}
		defer configFd.Close()
		err = json.NewDecoder(configFd).Decode(&config)
		if err != nil {
			return errors.Wrapf(err, "failed to decode config file")
		}
	} else {
		return errors.New("unsupported config file format, only yaml and json are supported")
	}

	if !skipChecks {
		ifaces, err := utils.ListIfaces()
		if err != nil {
			return errors.Wrapf(err, "failed to list interfaces")
		}
		for _, rule := range config.Rules {
			err = rule.Validate(ifaces)
			if err != nil {
				return errors.Wrapf(err, "rule (%s) validation failed", rule.String())
			}
		}
	}

	// Currently, IPv4 Only.
	ipt4, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(timeoutSeconds))
	if err != nil {
		return errors.Wrapf(err, "failed to create iptables handler")
	}

	// Append rules
	for _, rule := range config.Rules {
		logger := slog.With(slog.Group("rule", rule.SlogAttr()...))

		existingRules, expectedRules, err := rule.Exists(ipt4)
		if err != nil {
			return errors.Wrapf(err, "failed to check existing rule (%s)", rule.String())
		}

		if existingRules == 0 {
			logger.Info("Appending new rule")
		} else if existingRules < expectedRules {
			logger.Info("Completing existing rule")
		} else if existingRules == expectedRules {
			logger.Debug("Rule already exists")
		} else {
			logger.Error("Unexpected state")
		}

		err = rule.AppendUnique(ipt4)
		if err != nil {
			return errors.Wrapf(err, "failed to append rule (%s)", rule.String())
		}
	}

	// Delete rules that are not in the config. (Only those that are managed by iptfwd)
	if sync {
		// TODO: move this forward-specific logic to pkg/portfwd
		preroutingRules, err := ipt4.List("nat", "PREROUTING")
		if err != nil {
			return errors.Wrapf(err, "failed to list nat chains")
		}
		postroutingRules, err := ipt4.List("nat", "POSTROUTING")
		if err != nil {
			return errors.Wrapf(err, "failed to list nat chains")
		}

		// Convert rules to portfwd.Spec
		var specs []*portfwd.Spec
		for _, chain := range append(preroutingRules, postroutingRules...) {
			comment := utils.ExtractComment(chain)
			if comment == "" {
				continue
			}
			existing, err := portfwd.NewFromComment(comment)
			if err != nil {
				continue
			}
			// Skip if already in specs. Since each Spec has two rules (PREROUTING and POSTROUTING),
			// duplications are expected.
			skip := false
			for _, spec := range specs {
				if spec.Equals(existing) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			specs = append(specs, existing)
		}

		for _, existing := range specs {
			if !config.Contains(existing) {
				logger := slog.With(slog.Group("rule", existing.SlogAttr()...))
				logger.Info("Deleting existing rule")
				err := existing.DeleteIfExists(ipt4)
				if err != nil {
					return errors.Wrapf(err, "failed to delete rule (%s)", existing.String())
				}
			}
		}
	}

	return nil
}
