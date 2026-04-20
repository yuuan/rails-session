package rails

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// ParseCookie URL-decodes the raw cookie string, splits it by "--",
// and Base64-decodes each segment into encrypted data, IV, and auth tag.
func ParseCookie(raw string) (encrypted, iv, authTag []byte, err error) {
	unescaped, err := url.QueryUnescape(raw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to URL-unescape cookie: %w", err)
	}
	unescaped = strings.ReplaceAll(unescaped, " ", "+")

	segments := strings.Split(unescaped, "--")
	if len(segments) != 3 {
		return nil, nil, nil, fmt.Errorf("expected 3 segments separated by '--', got %d", len(segments))
	}

	decoded := make([][]byte, 3)
	for i, seg := range segments {
		decoded[i], err = base64.StdEncoding.DecodeString(seg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to Base64-decode segment %d: %w", i+1, err)
		}
	}

	return decoded[0], decoded[1], decoded[2], nil
}

// BuildCookie Base64-encodes each segment, joins with "--", and URL-encodes.
func BuildCookie(encrypted, iv, authTag []byte) string {
	raw := base64.StdEncoding.EncodeToString(encrypted) +
		"--" + base64.StdEncoding.EncodeToString(iv) +
		"--" + base64.StdEncoding.EncodeToString(authTag)
	return url.QueryEscape(raw)
}
