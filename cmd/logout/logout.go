package logout

import (
	"fmt"

	"secretify-cli/internal/creds"

	"github.com/spf13/cobra"
)

func newLogout() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "logout",
		Short:         "Log out from a Secretify",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Delete stored credentials
			err := creds.DeleteCredentials()
			if err != nil {
				return fmt.Errorf("could not delete credentials: %v", err)
			}
			fmt.Println("Logout Succeeded")
			return nil
		},
	}
	return cmd
}

// RegisterCommandsRecursive registers the logout command.
func RegisterCommandsRecursive(parent *cobra.Command) {
	parent.AddCommand(newLogout())
}
