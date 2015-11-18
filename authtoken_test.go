package authtoken

import (
  "testing"
  "net/http"
)

func TestBearerFromRequest(t *testing.T) {
  req, _ := http.NewRequest("GET", "", nil)
  req.Header.Set("Authorization", "Bearer TOKEN")
  result, err := FromRequest(req)

  if err != nil {
    t.Errorf("err = %v want nil", err)
  }

  if result != "TOKEN" {
    t.Errorf("FromRequest() = %v want %v", result, "TOKEN")
  }
}

func TestBasicFromRequest(t *testing.T) {
  req, _ := http.NewRequest("GET", "", nil)
  req.Header.Set("Authorization", "Basic VE9LRU4=")
  result, err := FromRequest(req)

  if err != nil {
    t.Errorf("err = %v want nil", err)
  }

  if result != "TOKEN" {
    t.Errorf("FromRequest() = %v want %v", result, "TOKEN")
  }
}

func TestEmptyFromRequest(t *testing.T) {
  req, _ := http.NewRequest("GET", "", nil)
  expected := "Authorization header required"
  _, err := FromRequest(req)

  if err.Error() != expected {
    t.Errorf("err = %v want %v", err, expected)
  }
}
