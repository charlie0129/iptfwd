package installservice

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	initAuto    = "auto"
	initSystemd = "systemd"
	initOpenRC  = "openrc"
)

type options struct {
	InitSystem      string
	Name            string
	BinaryPath      string
	ConfigPath      string
	ServiceLogLevel string
	Enable          bool
	Start           bool
	DryRun          bool
}

func NewCommand() *cobra.Command {
	opts := options{
		InitSystem:      initAuto,
		Name:            "iptfwd",
		BinaryPath:      "/usr/local/bin/iptfwd",
		ConfigPath:      "/etc/iptfwd/forward.yaml",
		ServiceLogLevel: "debug",
		Enable:          true,
	}

	cmd := &cobra.Command{
		Use:   "install-service",
		Short: "Install iptfwd as a boot service",
		Long: `Install iptfwd as a oneshot boot service.

The service runs "iptfwd forward --sync" at boot. systemd and OpenRC are supported.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.InitSystem, "init", opts.InitSystem, "Init system to install for: auto, systemd, or openrc")
	f.StringVar(&opts.Name, "name", opts.Name, "Service name")
	f.StringVar(&opts.BinaryPath, "binary", opts.BinaryPath, "Path where the current iptfwd binary should be installed")
	f.StringVar(&opts.ConfigPath, "config", opts.ConfigPath, "Config path used by the service")
	f.StringVar(&opts.ServiceLogLevel, "service-log-level", opts.ServiceLogLevel, "Log level used by the installed service")
	f.BoolVar(&opts.Enable, "enable", opts.Enable, "Enable the service at boot")
	f.BoolVar(&opts.Start, "start", opts.Start, "Start the service immediately after installation")
	f.BoolVar(&opts.DryRun, "dry-run", opts.DryRun, "Print generated service files and commands without writing or running them")

	return cmd
}

func run(opts options) error {
	if err := opts.validate(); err != nil {
		return err
	}

	initSystem, err := detectInitSystem(opts.InitSystem)
	if err != nil {
		return err
	}

	if opts.DryRun {
		return dryRun(os.Stdout, opts, initSystem)
	}

	if os.Geteuid() != 0 {
		return errors.New("install-service must be run as root")
	}

	if err := installBinary(opts.BinaryPath); err != nil {
		return err
	}

	if _, err := os.Stat(opts.ConfigPath); err != nil {
		if os.IsNotExist(err) {
			slog.Warn("Config file does not exist yet; service start will fail until it is created", "config", opts.ConfigPath)
		} else {
			return errors.Wrapf(err, "failed to stat config file %s", opts.ConfigPath)
		}
	}

	switch initSystem {
	case initSystemd:
		return installSystemd(opts)
	case initOpenRC:
		return installOpenRC(opts)
	default:
		return fmt.Errorf("unsupported init system %q", initSystem)
	}
}

func (o options) validate() error {
	switch o.InitSystem {
	case initAuto, initSystemd, initOpenRC:
	default:
		return fmt.Errorf("invalid --init %q, expected auto, systemd, or openrc", o.InitSystem)
	}
	if !validServiceName(o.Name) {
		return fmt.Errorf("invalid service name %q", o.Name)
	}
	if strings.TrimSpace(o.BinaryPath) == "" {
		return errors.New("--binary is required")
	}
	if strings.TrimSpace(o.ConfigPath) == "" {
		return errors.New("--config is required")
	}
	if strings.TrimSpace(o.ServiceLogLevel) == "" {
		return errors.New("--service-log-level is required")
	}
	return nil
}

var serviceNameRE = regexp.MustCompile(`^[A-Za-z0-9_.@-]+$`)

func validServiceName(name string) bool {
	return serviceNameRE.MatchString(name) && !strings.HasPrefix(name, ".")
}

func detectInitSystem(requested string) (string, error) {
	if requested != initAuto {
		return requested, nil
	}
	if fileExists("/run/systemd/system") && commandExists("systemctl") {
		return initSystemd, nil
	}
	if fileExists("/sbin/openrc-run") && commandExists("rc-update") && commandExists("rc-service") {
		return initOpenRC, nil
	}
	return "", errors.New("could not detect systemd or OpenRC; pass --init systemd or --init openrc")
}

func installBinary(target string) error {
	source, err := os.Executable()
	if err != nil {
		return errors.Wrap(err, "failed to locate current executable")
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return errors.Wrapf(err, "failed to resolve executable path %s", source)
	}

	target = filepath.Clean(target)
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return errors.Wrapf(err, "failed to stat executable %s", source)
	}
	if targetInfo, err := os.Stat(target); err == nil && os.SameFile(sourceInfo, targetInfo) {
		return os.Chmod(target, 0o755)
	} else if err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed to stat target binary %s", target)
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return errors.Wrapf(err, "failed to create %s", filepath.Dir(target))
	}

	tmp := target + ".tmp"
	if err := copyFile(source, tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return errors.Wrapf(err, "failed to install binary to %s", target)
	}
	return nil
}

func installSystemd(opts options) error {
	unitName := opts.Name + ".service"
	unitPath := filepath.Join("/etc/systemd/system", unitName)
	unit := renderSystemdUnit(opts)

	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return errors.Wrapf(err, "failed to write %s", unitPath)
	}
	if err := runCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if opts.Enable {
		if err := runCommand("systemctl", "enable", unitName); err != nil {
			return err
		}
	}
	if opts.Start {
		if err := runCommand("systemctl", "restart", unitName); err != nil {
			return err
		}
	}

	slog.Info("Installed systemd service", "unit", unitPath)
	return nil
}

func installOpenRC(opts options) error {
	scriptPath := filepath.Join("/etc/init.d", opts.Name)
	script := renderOpenRCScript(opts)

	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		return errors.Wrapf(err, "failed to write %s", scriptPath)
	}
	if err := os.Chmod(scriptPath, 0o755); err != nil {
		return errors.Wrapf(err, "failed to chmod %s", scriptPath)
	}
	if opts.Enable {
		if err := runCommand("rc-update", "add", opts.Name, "default"); err != nil {
			return err
		}
	}
	if opts.Start {
		if err := runCommand("rc-service", opts.Name, "start"); err != nil {
			return err
		}
	}

	slog.Info("Installed OpenRC service", "script", scriptPath)
	return nil
}

func renderSystemdUnit(opts options) string {
	return fmt.Sprintf(`[Unit]
Description=Apply iptfwd NAT and port forwarding rules
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s --log-level %s forward --config %s --sync
ExecReload=%s --log-level %s forward --config %s --sync

[Install]
WantedBy=multi-user.target
`,
		systemdArg(opts.BinaryPath),
		systemdArg(opts.ServiceLogLevel),
		systemdArg(opts.ConfigPath),
		systemdArg(opts.BinaryPath),
		systemdArg(opts.ServiceLogLevel),
		systemdArg(opts.ConfigPath),
	)
}

func renderOpenRCScript(opts options) string {
	return fmt.Sprintf(`#!/sbin/openrc-run

description="Apply iptfwd NAT and port forwarding rules"

depend() {
	need net
	after firewall
}

start() {
	ebegin "Applying iptfwd NAT and port forwarding rules"
	%s --log-level %s forward --config %s --sync
	eend $?
}

reload() {
	start
}
`,
		shellArg(opts.BinaryPath),
		shellArg(opts.ServiceLogLevel),
		shellArg(opts.ConfigPath),
	)
}

func dryRun(w io.Writer, opts options, initSystem string) error {
	fmt.Fprintf(w, "init: %s\n", initSystem)
	fmt.Fprintf(w, "install binary: %s\n", opts.BinaryPath)
	switch initSystem {
	case initSystemd:
		unitName := opts.Name + ".service"
		fmt.Fprintf(w, "write: /etc/systemd/system/%s\n\n%s\n", unitName, renderSystemdUnit(opts))
		fmt.Fprintln(w, "run: systemctl daemon-reload")
		if opts.Enable {
			fmt.Fprintf(w, "run: systemctl enable %s\n", unitName)
		}
		if opts.Start {
			fmt.Fprintf(w, "run: systemctl restart %s\n", unitName)
		}
	case initOpenRC:
		fmt.Fprintf(w, "write: /etc/init.d/%s\n\n%s\n", opts.Name, renderOpenRCScript(opts))
		if opts.Enable {
			fmt.Fprintf(w, "run: rc-update add %s default\n", opts.Name)
		}
		if opts.Start {
			fmt.Fprintf(w, "run: rc-service %s start\n", opts.Name)
		}
	default:
		return fmt.Errorf("unsupported init system %q", initSystem)
	}
	return nil
}

func copyFile(source, target string, mode os.FileMode) error {
	src, err := os.Open(source)
	if err != nil {
		return errors.Wrapf(err, "failed to open %s", source)
	}
	defer src.Close()

	dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return errors.Wrapf(err, "failed to create %s", target)
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return errors.Wrapf(copyErr, "failed to copy %s to %s", source, target)
	}
	if closeErr != nil {
		return errors.Wrapf(closeErr, "failed to close %s", target)
	}
	if err := os.Chmod(target, mode); err != nil {
		return errors.Wrapf(err, "failed to chmod %s", target)
	}
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "failed to run %s %s", name, strings.Join(args, " "))
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func systemdArg(value string) string {
	if value == "" {
		return `""`
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return r == '"' || r == '\\' || r == '#' || r == ';' || r == '$' || r == '\'' || r <= ' '
	}) == -1 {
		return value
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\', '"', '$':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func shellArg(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
