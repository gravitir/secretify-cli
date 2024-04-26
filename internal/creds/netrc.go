package creds

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func netrcSet(service, username, password string) error {
	// Create .secretify folder if it doesn't exist
	secretifyFolderPath := os.Getenv("HOME") + "/.secretify"
	err := os.MkdirAll(secretifyFolderPath, 0700)
	if err != nil {
		return err
	}

	// Path to .netrc file
	netrcPath := secretifyFolderPath + "/.netrc"

	// Construct the new content for the .netrc file
	newContent := fmt.Sprintf("machine %s login %s password %s\n", service, username, password)

	// TODO: add multiple credentials support instead of just rewriting it always
	// Write the new content to the .netrc file
	err = os.WriteFile(netrcPath, []byte(newContent), 0600)
	if err != nil {
		return err
	}

	return nil
}

func netrcGet() (string, string, string, error) {
	// Path to .netrc file
	netrcPath := os.Getenv("HOME") + "/.secretify/.netrc"

	// Open .netrc file
	file, err := os.Open(netrcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", "", fmt.Errorf("no .netrc file found")
		}
		return "", "", "", err
	}
	defer file.Close()

	// Scan each line of the .netrc file
	for scanner := bufio.NewScanner(file); scanner.Scan(); {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "machine" && fields[4] == "password" {
			return fields[1], fields[3], fields[5], nil // Return machine, login, password
		}
	}

	// If no matching entry is found
	return "", "", "", fmt.Errorf("no credentials found in .netrc file")
}

func netrcDelete() error {
	// Path to .netrc file
	netrcPath := os.Getenv("HOME") + "/.secretify/.netrc"

	// Check if .netrc file exists
	_, err := os.Stat(netrcPath)
	if os.IsNotExist(err) {
		// If .netrc file doesn't exist, return nil (no error)
		return nil
	} else if err != nil {
		// If there's an error other than file not found, return the error
		return err
	}

	// Delete the .netrc file
	err = os.Remove(netrcPath)
	if err != nil {
		return fmt.Errorf("could not delete .netrc file: %v", err)
	}

	return nil
}
