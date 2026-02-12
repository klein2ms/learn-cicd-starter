package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid header with ApiKey scheme",
			authHeader:    "ApiKey test-key-123",
			expectedKey:   "test-key-123",
			expectedError: nil,
		},
		{
			name:          "Missing authorization header",
			authHeader:    "",
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Wrong scheme - Bearer instead of ApiKey",
			authHeader:    "Bearer test-token",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Only scheme, no token",
			authHeader:    "ApiKey",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Multiple tokens separated by spaces",
			authHeader:    "ApiKey token-part-1 token-part-2",
			expectedKey:   "token-part-1",
			expectedError: nil,
		},
		{
			name:          "Lowercase scheme instead of ApiKey",
			authHeader:    "apikey test-token",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Scheme with extra whitespace before token",
			authHeader:    "ApiKey  test-token",
			expectedKey:   "",
			expectedError: nil,
		},
		{
			name:          "Empty string after scheme",
			authHeader:    "ApiKey ",
			expectedKey:   "",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			key, err := GetAPIKey(headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedError)
				} else if !errors.Is(err, tt.expectedError) && err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error %q, got %q", tt.expectedError.Error(), err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	key, err := GetAPIKey(headers)

	if key != "my-secret-key" {
		t.Errorf("expected key 'my-secret-key', got %q", key)
	}
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestGetAPIKey_MissingHeader(t *testing.T) {
	headers := http.Header{}

	key, err := GetAPIKey(headers)

	if key != "" {
		t.Errorf("expected empty key, got %q", key)
	}
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_WrongScheme(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-token")

	key, err := GetAPIKey(headers)

	if key != "" {
		t.Errorf("expected empty key, got %q", key)
	}
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected 'malformed authorization header' error, got %v", err)
	}
}

func TestGetAPIKey_MissingToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey")

	key, err := GetAPIKey(headers)

	if key != "" {
		t.Errorf("expected empty key, got %q", key)
	}
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected 'malformed authorization header' error, got %v", err)
	}
}

func TestGetAPIKey_InvalidFormat(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "InvalidScheme token")

	key, err := GetAPIKey(headers)

	if key != "" {
		t.Errorf("expected empty key, got %q", key)
	}
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected 'malformed authorization header' error, got %v", err)
	}
}

func TestGetAPIKey_MultipleTokens(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey token-one token-two")

	key, err := GetAPIKey(headers)

	if key != "token-one" {
		t.Errorf("expected key 'token-one', got %q", key)
	}
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}
