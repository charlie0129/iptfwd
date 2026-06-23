package cleanup

import (
	"log/slog"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/charlie0129/iptfwd/pkg/fw"
)

var timeoutSeconds = 20

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Delete all iptfwd-managed rules",
		Long: `Delete all iptfwd-managed jumps and chains for IPv4 and IPv6.

This command does not read a config file and cannot clean only one config. It
removes all IPTFWD-* chains and their jumps:

  nat/IPTFWD-PREROUTING
  nat/IPTFWD-POSTROUTING
  filter/IPTFWD-FORWARD

Non-iptfwd rules are left untouched. To remove only one NAT or port-forward
rule, edit the host config and run "iptfwd forward --sync".`,
		Example: `  iptfwd cleanup
  iptfwd --log-level debug cleanup`,
		RunE: run,
	}

	f := cmd.Flags()
	f.IntVar(&timeoutSeconds, "timeout", timeoutSeconds, "Timeout in seconds for iptables commands")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	cleanedFamilies := 0
	for _, family := range fw.AllFamilies() {
		ipt, err := iptables.New(
			iptables.IPFamily(family.IptablesProtocol()),
			iptables.Timeout(timeoutSeconds),
		)
		if err != nil {
			slog.Warn("Skipping cleanup for unavailable iptables family", "family", family, "error", err)
			continue
		}

		slog.Info("Cleaning up managed rules", "family", family)
		if err := fw.Cleanup(ipt, fw.ManagedChains()); err != nil {
			return errors.Wrapf(err, "failed to clean up %s rules", family)
		}
		slog.Info("Cleaned up managed rules", "family", family)
		cleanedFamilies++
	}

	if cleanedFamilies == 0 {
		return errors.New("failed to create any iptables handler")
	}
	return nil
}
