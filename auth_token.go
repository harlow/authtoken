package auth_token

import (
	"encoding/base64"
	"errors"
	"strings"
)

const (
	BASIC_SCHEMA  string = "Basic "
	BEARER_SCHEMA string = "Bearer "
)

// Parse takes a HTTP Authoirzation header and parses out
// a Basic or Bearer auth token
func Parse(auth_header string) (string, error) {
	var token string

	// Confirm the request is sending Basic Authentication credentials.
	if !strings.HasPrefix(auth_header, BASIC_SCHEMA) && !strings.HasPrefix(auth_header, BEARER_SCHEMA) {
		return "", errors.New("Auth type not supported")
	}

	// Get the token from the request header
	// The first six characters are skipped - e.g. "Basic ".
	if strings.HasPrefix(auth_header, BASIC_SCHEMA) {
		str, err := base64.StdEncoding.DecodeString(auth_header[len(BASIC_SCHEMA):])
		if err != nil {
			return "", errors.New("Base64 encoding issue")
		}
		creds := strings.Split(string(str), ":")
		token = creds[0]
	} else {
		token = auth_header[len(BEARER_SCHEMA):]
	}

	return token, nil
}
