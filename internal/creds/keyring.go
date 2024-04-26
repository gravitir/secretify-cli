package creds

import (
	"encoding/json"

	keyring "github.com/zalando/go-keyring"
)

// DefaultService is the default service name used for storing credentials.
const DefaultService string = "secretify"

// DefaultUsername is the default username used for storing credentials.
const DefaultUsername string = "default"

type data struct {
	APIURL   string `json:"api_url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func keyringSet(service, username, password string) error {
	// Serialize data to JSON
	b, err := json.Marshal(data{
		APIURL:   service,
		Username: username,
		Password: password,
	})
	if err != nil {
		return err
	}
	// Store serialized data in the keyring
	return keyring.Set(DefaultService, DefaultUsername, string(b))
}

func keyringGet() (string, string, string, error) {
	// Retrieve serialized data from the keyring
	jsonCreds, err := keyring.Get(DefaultService, DefaultUsername)
	if err != nil {
		return "", "", "", err
	}
	// Deserialize JSON data into struct
	var d data
	err = json.Unmarshal([]byte(jsonCreds), &d)
	if err != nil {
		return "", "", "", err
	}

	return d.APIURL, d.Username, d.Password, nil
}

func keyringDelete() error {
	// Delete credentials from keyring
	return keyring.Delete(DefaultService, DefaultUsername)
}
