package reveal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"secretify-cli/internal"
	"secretify-cli/internal/creds"
	secretifyclient "secretify-cli/pkg/client"
	"secretify-cli/pkg/crypto"
	"strings"

	"github.com/spf13/cobra"
)

func newReveal() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "reveal",
		Short:         "Reveal a secret",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flags
			link, err := cmd.Flags().GetString("link")
			if err != nil {
				return err
			}
			identifier, err := cmd.Flags().GetString("identifier")
			if err != nil {
				return err
			}
			key, err := cmd.Flags().GetString("key")
			if err != nil {
				return err
			}
			// Check if either link or identifier with key is provided
			if link == "" && (identifier == "" || key == "") {
				return fmt.Errorf("no link nor identifier with key provided")
			}

			// If link is provided, parse it to get identifier and key
			if link != "" {
				parsedURL, err := url.Parse(link)
				if err != nil {
					return fmt.Errorf("error parsing Link %v", err)
				}

				// Extract identifier and key
				pathSegments := strings.Split(parsedURL.Path, "/")
				identifier = pathSegments[len(pathSegments)-1]
				key = parsedURL.Fragment
			}

			// Authenticate (optional)
			var token string
			url, username, password, err := creds.GetCredentials()
			if err != nil {
				return fmt.Errorf("authentication: %v", err)
			}
			token, _ = secretifyclient.NewHTTP(fmt.Sprintf(internal.APIURL, url), token).Login(username, password)

			// Reveal secret
			encryptedMap, err := secretifyclient.NewHTTP(fmt.Sprintf(internal.APIURL, url), token).Reveal(identifier)
			if err != nil {
				return err
			}

			// Decrypt values
			decodedKey, err := base64.RawURLEncoding.DecodeString(key)
			if err != nil {
				return err
			}
			var decryptedMap = make(map[string]string, len(encryptedMap))
			for k, v := range encryptedMap {
				decrypted, err := crypto.DecryptStringFromDataURL(v, decodedKey)
				if err != nil {
					return fmt.Errorf("decryption error %v", err)
				}
				decryptedMap[k] = decrypted
			}

			// Output decrypted map as JSON
			b, err := json.Marshal(decryptedMap)
			if err != nil {
				return err
			}
			fmt.Println(string(b))
			return nil
		},
	}
	cmd.Flags().String("link", "", "Link of the secret")
	cmd.Flags().String("identifier", "", "Identifier of the secret")
	cmd.Flags().String("key", "", "Key of the secret")
	return cmd
}

func RegisterCommandsRecursive(parent *cobra.Command) {
	parent.AddCommand(newReveal())
}
