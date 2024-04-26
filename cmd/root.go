package cmd

import (
	"context"
	"fmt"
	"os"
	"secretify-cli/cmd/create"
	"secretify-cli/cmd/login"
	"secretify-cli/cmd/logout"
	"secretify-cli/cmd/reveal"
	"secretify-cli/internal/config"

	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secretify",
		Short: "The safe way to share or transfer secrets.",
	}

	login.RegisterCommandsRecursive(cmd)
	logout.RegisterCommandsRecursive(cmd)
	create.RegisterCommandsRecursive(cmd)
	reveal.RegisterCommandsRecursive(cmd)

	cmd.AddCommand(version(&config.Version, &config.Date))

	return cmd
}

func Execute() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := NewRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
