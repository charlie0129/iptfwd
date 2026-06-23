package installservice

import (
	"strings"
	"testing"
)

func TestRenderSystemdUnit(t *testing.T) {
	opts := options{
		Name:            "iptfwd",
		BinaryPath:      "/usr/local/bin/iptfwd",
		ConfigPath:      "/etc/iptfwd/forward.yaml",
		ServiceLogLevel: "info",
	}

	unit := renderSystemdUnit(opts)
	for _, want := range []string{
		"Type=oneshot",
		"RemainAfterExit=yes",
		"ExecStart=/usr/local/bin/iptfwd --log-level info forward --config /etc/iptfwd/forward.yaml --sync",
		"ExecReload=/usr/local/bin/iptfwd --log-level info forward --config /etc/iptfwd/forward.yaml --sync",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q:\n%s", want, unit)
		}
	}
}

func TestRenderOpenRCScript(t *testing.T) {
	opts := options{
		Name:            "iptfwd",
		BinaryPath:      "/usr/local/bin/iptfwd",
		ConfigPath:      "/etc/iptfwd/forward.yaml",
		ServiceLogLevel: "info",
	}

	script := renderOpenRCScript(opts)
	for _, want := range []string{
		"#!/sbin/openrc-run",
		"need net",
		"after firewall",
		"'/usr/local/bin/iptfwd' --log-level 'info' forward --config '/etc/iptfwd/forward.yaml' --sync",
		"reload()",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
}

func TestValidateRejectsUnsafeServiceName(t *testing.T) {
	err := (options{
		InitSystem:      initSystemd,
		Name:            "../iptfwd",
		BinaryPath:      "/usr/local/bin/iptfwd",
		ConfigPath:      "/etc/iptfwd/forward.yaml",
		ServiceLogLevel: "info",
	}).validate()
	if err == nil {
		t.Fatal("validate() error = nil, want unsafe name error")
	}
}

func TestQuoting(t *testing.T) {
	if got := shellArg("/path/with ' quote"); got != `'/path/with '\'' quote'` {
		t.Fatalf("shellArg() = %q", got)
	}
	if got := systemdArg(`/path/with "quote"`); got != `"/path/with \"quote\""` {
		t.Fatalf("systemdArg() = %q", got)
	}
}
