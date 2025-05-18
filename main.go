package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/charlie0129/iptfwd/cmd/forward"
)

type SlogLogLevelValue slog.Level

var LogLevel SlogLogLevelValue = SlogLogLevelValue(slog.LevelDebug)

func (v *SlogLogLevelValue) Set(s string) error {
	var l slog.Level

	if err := l.UnmarshalText([]byte(s)); err != nil {
		return err
	}

	*v = SlogLogLevelValue(l)
	return nil
}

func (v *SlogLogLevelValue) Type() string {
	return "slog.Level"
}

func (v *SlogLogLevelValue) String() string {
	l := slog.Level(*v)
	b, err := l.MarshalText()
	if err != nil {
		return ""
	}
	return string(b)
}

func SetupLogger(logLevel slog.Level) {
	var handler slog.Handler

	// Default text handler
	handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})

	// Use some colors if the output is a terminal to make it more readable
	if term.IsTerminal(int(os.Stderr.Fd())) {
		handler = tint.NewHandler(os.Stderr, &tint.Options{
			Level:      logLevel,
			TimeFormat: time.TimeOnly,
		})
	}

	slog.SetDefault(slog.New(handler))
}

func main() {
	rootCmd := cobra.Command{
		Use: "iptfwd",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			SetupLogger(slog.Level(LogLevel))
		},
	}
	rootCmd.AddCommand(forward.NewCommand())
	pf := rootCmd.PersistentFlags()
	pf.Var(&LogLevel, "log-level", "Set the log level (debug, info, warn, error)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
