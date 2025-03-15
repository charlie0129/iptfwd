package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/charlie0129/iptfwd/cmd/forward"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{})))

	rootCmd := cobra.Command{
		Use: "iptfwd",
	}
	rootCmd.AddCommand(forward.NewCommand())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
