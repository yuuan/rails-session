package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "rails-session",
	Short: "A CLI tool for Rails session cookie operations",
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
