package sysctl

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/charlie0129/iptfwd/pkg/fw"
)

func TestEnsureIPForwarding(t *testing.T) {
	root := t.TempDir()
	oldRoot := procSysRoot
	procSysRoot = root
	t.Cleanup(func() {
		procSysRoot = oldRoot
	})

	for _, setting := range []string{
		"net/ipv4/ip_forward",
		"net/ipv6/conf/all/forwarding",
		"net/ipv6/conf/default/forwarding",
	} {
		path := filepath.Join(root, setting)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
		if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}

	changed, err := EnsureIPForwarding([]fw.Family{fw.FamilyIPv4, fw.FamilyIPv6})
	if err != nil {
		t.Fatalf("EnsureIPForwarding() error = %v", err)
	}

	for _, setting := range []string{
		"net/ipv4/ip_forward",
		"net/ipv6/conf/all/forwarding",
		"net/ipv6/conf/default/forwarding",
	} {
		if !slices.Contains(changed, setting) {
			t.Fatalf("changed = %v, want %s", changed, setting)
		}
		got, err := os.ReadFile(filepath.Join(root, setting))
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		if string(got) != "1\n" {
			t.Fatalf("%s = %q, want 1", setting, got)
		}
	}
}
