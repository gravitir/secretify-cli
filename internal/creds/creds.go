package creds

import (
	"fmt"
)

// StoreCredentials stores credentials either in keyring if available else
// as fallback it uses a personalized ~/.secretify/.netrc file.
func StoreCredentials(service, username, password string) error {
	err := keyringSet(service, username, password)
	if err == nil {
		return nil
	}
	// Fallback .netrc
	err = netrcSet(service, username, password)
	if err != nil {
		return fmt.Errorf("could not create credentials: %v", err)

	}
	return nil
}

// GetCredentials retrieves credentials for the given service.
// It first tries to retrieve them from the keyring and falls back to the .netrc file.
func GetCredentials() (string, string, string, error) {
	service, username, password, err := keyringGet()
	if err != nil {
		// Fallback .netrc
		var err error
		service, username, password, err = netrcGet()
		if err != nil {
			return "", "", "", err
		}
	}
	return service, username, password, nil
}

// DeleteCredentials removes stored credentials from both the system keyring and the .netrc file.
func DeleteCredentials() error {
	err := keyringDelete()
	if err != nil && err.Error() != "dbus: couldn't determine address of session bus" {
		return fmt.Errorf("could not delete credentials in keyring: %v", err)
	}
	err = netrcDelete()
	if err != nil {
		return fmt.Errorf("could not delete credentials in .netrc: %v", err)
	}
	return nil
}
