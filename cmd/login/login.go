package login

import (
	"fmt"

	"secretify-cli/internal"
	"secretify-cli/internal/creds"
	secretifyclient "secretify-cli/pkg/client"

	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newLogin() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "login [URL]",
		Short:         "Login with username and password",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if URL is provided
			if len(args) == 0 {
				return fmt.Errorf("no url as argument provided")
			}
			url := args[0]
			if url == "" {
				return fmt.Errorf("no url as argument provided")
			}

			// Retrieve username from flags
			username, err := cmd.Flags().GetString("username")
			if err != nil {
				return err
			}
			if username == "" {
				return fmt.Errorf("no username provided")
			}

			// Retrieve password from flags or prompt if not provided
			password, err := cmd.Flags().GetString("password")
			if err != nil {
				return err
			}
			if password == "" {
				// Prompt for password
				fmt.Print("Enter Password: ")

				bytePassword, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return fmt.Errorf("error reading password from input: %v", err)
				}
				fmt.Print("\n")

				password = string(bytePassword)
				if password == "" {
					return fmt.Errorf("no password provided")
				}
			}

			// Authenticate user
			_, err = secretifyclient.NewHTTP(fmt.Sprintf(internal.APIURL, url), "").Login(username, password)
			if err != nil {
				return fmt.Errorf("could not authenticate: %v", err)
			}

			// Store credentials
			err = creds.StoreCredentials(url, username, password)
			if err != nil {
				return fmt.Errorf("could not store credentials: %v", err)
			}
			fmt.Println("Login Succeeded")

			return nil
		},
	}
	cmd.Flags().StringP("username", "u", "", "Username")
	cmd.Flags().StringP("password", "p", "", "Password")
	cmd.Flags().String("password-stdin", "", "Password from stdin")
	return cmd
}

func RegisterCommandsRecursive(parent *cobra.Command) {
	parent.AddCommand(newLogin())
}
