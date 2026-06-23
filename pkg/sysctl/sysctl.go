package sysctl

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pkg/errors"

	"github.com/charlie0129/iptfwd/pkg/fw"
)

var procSysRoot = "/proc/sys"

func EnsureIPForwarding(families []fw.Family) ([]string, error) {
	var changed []string
	for _, setting := range forwardingSettings(families) {
		didChange, err := ensureOne(setting)
		if err != nil {
			return changed, err
		}
		if didChange {
			changed = append(changed, setting)
		}
	}
	return changed, nil
}

func forwardingSettings(families []fw.Family) []string {
	var settings []string
	if slices.Contains(families, fw.FamilyIPv4) {
		settings = append(settings, "net/ipv4/ip_forward")
	}
	if slices.Contains(families, fw.FamilyIPv6) {
		settings = append(settings,
			"net/ipv6/conf/all/forwarding",
			"net/ipv6/conf/default/forwarding",
		)
	}
	return settings
}

func ensureOne(setting string) (bool, error) {
	path := filepath.Join(procSysRoot, setting)
	current, err := os.ReadFile(path)
	if err != nil {
		return false, errors.Wrapf(err, "failed to read %s", path)
	}
	if strings.TrimSpace(string(current)) == "1" {
		return false, nil
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		return false, errors.Wrapf(err, "failed to enable %s", path)
	}
	return true, nil
}
