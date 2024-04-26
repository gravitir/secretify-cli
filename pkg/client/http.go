package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type HTTP struct {
	APIURL      string
	AccessToken string
}

func NewHTTP(apiURL, accessToken string) *HTTP {
	return &HTTP{
		APIURL:      apiURL,
		AccessToken: accessToken,
	}
}

type CreateResponse struct {
	Identifier string `json:"identifier"`
}

func (h *HTTP) Create(typeID int, cipher map[string]string, expiresAt string, views int, isDestroyable bool, isRequest bool, hasPassphrase bool) (*CreateResponse, error) {

	// Prepare the request body
	body := map[string]interface{}{
		"type_id":        typeID,
		"cipher":         cipher,
		"expires_at":     expiresAt,
		"views":          views,
		"is_destroyable": isDestroyable,
		"is_request":     isRequest,
		"has_passphrase": hasPassphrase,
	}

	// Convert the body to JSON
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	// Prepare the request
	req, err := http.NewRequest("POST", h.APIURL+"/secret", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if h.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.AccessToken)
	}

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	// Read the response body
	var createResponse = &CreateResponse{}
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %v", err)
	}

	if val, ok := response["data"]; ok {
		if dataMap, ok := val.(map[string]interface{}); ok {
			// Create a new struct instance
			if vi, ok := dataMap["identifier"]; ok {
				createResponse.Identifier = vi.(string)
			}
		}
	}

	if createResponse.Identifier == "" {
		return nil, fmt.Errorf("could not retrieve identifier from response")
	}
	return createResponse, nil
}

type revealResponse struct {
	Data struct {
		Cipher string `json:"cipher"`
	} `json:"data"`
}

func (h *HTTP) Reveal(identifier string) (map[string]string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/secret/%s/_cipher", h.APIURL, identifier), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if h.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.AccessToken)
	}

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var revealResponse = &revealResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&revealResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %v", err)
	}

	if revealResponse.Data.Cipher == "" {
		return nil, fmt.Errorf("could not retrieve cipher")
	}

	var mapCipher map[string]string
	if err := json.Unmarshal([]byte(revealResponse.Data.Cipher), &mapCipher); err != nil {
		return nil, fmt.Errorf("could not retrieve cipher")
	}

	return mapCipher, nil
}

type typeResponse struct {
	Data struct {
		Types []struct {
			ID         int    `json:"id"`
			Identifier string `json:"identifier"`
			Name       struct {
				En string `json:"en"`
			} `json:"name"`
		} `json:"types"`
	} `json:"data"`
}

func (h *HTTP) CheckType(typeName string) (int, error) {
	// Prepare the request
	req, err := http.NewRequest("GET", h.APIURL+"/type", nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if h.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.AccessToken)
	}

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	// Read the response body
	var response typeResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0, fmt.Errorf("failed to decode response body: %v", err)
	}

	for _, v := range response.Data.Types {
		if strings.EqualFold(v.Identifier, typeName) {
			return v.ID, nil
		}
	}
	return 0, fmt.Errorf("type not found")
}

type LoginResponse struct {
	Data struct {
		AccessToken string `json:"access_token"`
	} `json:"data"`
	Error string `json:"error"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func (h *HTTP) Login(clientID, clientSecret string) (string, error) {
	loginURL := h.APIURL + "/auth/microsoftonline"

	// Prepare the request body
	loginData := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
	}
	loginBody, err := json.Marshal(loginData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal login request body: %v", err)
	}

	// Send the request
	resp, err := http.Post(loginURL, "application/json", bytes.NewBuffer(loginBody))
	if err != nil {
		return "", fmt.Errorf("failed to send login request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		// Read the response body
		var errResp ErrorResponse
		json.NewDecoder(resp.Body).Decode(&errResp)
		return "", fmt.Errorf("unexpected response status: %s with error: %v", resp.Status, errResp.Error)
	}

	// Read the response body
	var loginResp LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return "", fmt.Errorf("failed to decode login response body: %v", err)
	}

	return loginResp.Data.AccessToken, nil
}
