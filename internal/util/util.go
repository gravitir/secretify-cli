package util

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ExtractDataSets extracts key-value pairs from an array of strings in the format "key=value".
func ExtractDataSets(dataSets []string) map[string]string {
	m := make(map[string]string)
	for _, v := range dataSets {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]

			// If there are more parts remaining, join them as part of the value
			if len(parts) > 2 {
				value = strings.Join(parts[1:], "=")
			}
			m[key] = value
		}
	}
	return m
}

// B64EncodeCredentials encodes the username and password into a base64-encoded string.
func B64EncodeCredentials(username, password string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
}

// B64DecodeCredentials decodes a base64-encoded string into its username and password components.
func B64DecodeCredentials(b64String string) (string, string, error) {
	credentials, err := base64.RawStdEncoding.DecodeString(b64String)
	if err != nil {
		return "", "", fmt.Errorf("could not decode credentials: %v", err)
	}

	parts := strings.SplitN(string(credentials), ":", 2)
	if len(parts) == 2 {
		username := parts[0]
		password := parts[1]

		// If there are more parts remaining, join them as part of the value
		if len(parts) > 2 {
			password = strings.Join(parts[1:], ":")
		}
		return username, password, nil
	}

	return "", "", fmt.Errorf("coult not decode credentials")
}
