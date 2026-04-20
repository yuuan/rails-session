package rails

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type envelope struct {
	Rails struct {
		Message string `json:"message"`
	} `json:"_rails"`
}

// ExtractSession parses the decrypted envelope JSON, extracts the
// _rails.message field, Base64-decodes it, and returns the session JSON bytes.
func ExtractSession(decrypted []byte) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(decrypted, &env); err != nil {
		return nil, fmt.Errorf("failed to parse envelope JSON: %w", err)
	}

	session, err := base64.StdEncoding.DecodeString(env.Rails.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to Base64-decode session message: %w", err)
	}

	return session, nil
}

// WrapSession wraps session JSON in a _rails envelope:
// Base64-encodes the session, then wraps it as {"_rails":{"message":"..."}}.
func WrapSession(session []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(session)
	env := envelope{}
	env.Rails.Message = encoded
	return json.Marshal(env)
}
