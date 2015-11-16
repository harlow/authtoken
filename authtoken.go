// Package auth provides functions for extracting a user Auth token from a
// request and associating it with a Context.
package authtoken

import (
  "fmt"
  "net"
  "net/http"

  "golang.org/x/net/context"
)

// FromRequest extracts the auth token from req.
func FromRequest(req *http.Request) (string, error) {
  // Grab the raw Authoirzation header
  authHeader, err := req.Header.Get("Authorization")
  if err != nil {
    return nil, errors.New("Authorization header required")
  }

  // Confirm the request is sending Basic Authentication credentials.
  if !strings.HasPrefix(authHeader, BASIC_SCHEMA) && !strings.HasPrefix(authHeader, BEARER_SCHEMA) {
    return nil, errors.New("Authorization requires Basic/Bearer scheme")
  }

  // Get the token from the request header
  // The first six characters are skipped - e.g. "Basic ".
  if strings.HasPrefix(authHeader, BASIC_SCHEMA) {
    str, err := base64.StdEncoding.DecodeString(authHeader[len(BASIC_SCHEMA):])
    if err != nil {
      return nil, errors.New("Base64 encoding issue")
    }
    creds := strings.Split(string(str), ":")
    return creds[0], nil
  } else {
    return authHeader[len(BEARER_SCHEMA):], nil
  }
}
