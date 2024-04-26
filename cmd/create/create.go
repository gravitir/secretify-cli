package create

import (
	"encoding/base64"
	"fmt"

	"secretify-cli/internal"
	"secretify-cli/internal/creds"
	"secretify-cli/internal/util"
	secretifyclient "secretify-cli/pkg/client"
	"secretify-cli/pkg/crypto"

	"github.com/spf13/cobra"
)

func newCreate() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "create [SECRET_TYPE]",
		Short:         "Create a new secret link",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if a secret type is provided
			if len(args) == 0 || args[0] == "" {
				return fmt.Errorf("error: no secret type provided")
			}
			dataType := args[0]

			// Extract data sets from flags
			dataSets, err := cmd.Flags().GetStringArray("set")
			if err != nil {
				return fmt.Errorf("error retrieving data: %v", err)
			}
			dataMap := util.ExtractDataSets(dataSets)
			if len(dataMap) == 0 {
				return fmt.Errorf("no data provided. Use e.g. --set message=your_secret")
			}

			// Retrieve expiration duration and views count from flags
			expiresAt, err := cmd.Flags().GetString("expiresAt")
			if err != nil {
				return fmt.Errorf("error expiresAt: %v", err)
			}
			views, err := cmd.Flags().GetInt("views")
			if err != nil {
				return fmt.Errorf("error views: %v", err)
			}

			// Authenticate and get token, create newly authenticated client
			url, username, password, err := creds.GetCredentials()
			if err != nil {
				return fmt.Errorf("authentication: %v", err)
			}
			token, err := secretifyclient.NewHTTP(fmt.Sprintf(internal.APIURL, url), "").Login(username, password)
			if err != nil {
				return fmt.Errorf("could not authenticate: %v", err)
			}
			aClient := secretifyclient.NewHTTP(fmt.Sprintf(internal.APIURL, url), token)

			// Check if the provided secret type exists
			typeID, err := aClient.CheckType(dataType)
			if err != nil {
				return fmt.Errorf("error type: %v", err)
			}

			// Generate encryption key and decrypt data
			key, err := crypto.GenerateEncryptionKeyString()
			if err != nil {
				return fmt.Errorf("error key: %v", err)
			}
			encryptedDataMap, err := crypto.EncryptDataMap(dataMap, key)
			if err != nil {
				return fmt.Errorf("error encryption: %v", err)
			}

			// Create a secret link
			crateRes, err := aClient.Create(typeID, encryptedDataMap, expiresAt, views, false, false, false)
			if err != nil {
				return fmt.Errorf("error client: %v", err)
			}

			// Print the generated secret link
			fmt.Printf("%s/s/%s#%s\n", url, crateRes.Identifier, base64.RawURLEncoding.EncodeToString(key))

			return nil
		},
	}
	cmd.Flags().StringArray("set", nil, "Your secret sets")
	cmd.Flags().String("expiresAt", "24h", "Expiration duration")
	cmd.Flags().Int("views", 1, "Number of views")
	return cmd
}

// RegisterCommandsRecursive registers the create command.
func RegisterCommandsRecursive(parent *cobra.Command) {
	parent.AddCommand(newCreate())
}
