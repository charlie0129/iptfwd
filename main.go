package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/charlie0129/iptfwd/cmd/forward"
)

func main() {
	rootCmd := cobra.Command{
		Use: "iptfwd",
	}
	rootCmd.AddCommand(forward.NewCommand())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
