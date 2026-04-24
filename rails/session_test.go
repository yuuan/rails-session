package rails_test

import (
	"encoding/json"
	"testing"

	"github.com/yuuan/rails-session/rails"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Rails 7.1 以降にできる Cookie
func TestFullDecrypt_SHA256(t *testing.T) {
	cookie := "L1rKa%2FEjOvdTc8FVmqJd2p8hDUgyR4N5LY4l5wWVkwFnnyKGUKj66t3kInndLb7N%2FDG4QHAItktGYaRag3zp0gdBSghlfaNEt49PWL%2FzSPfn4Iae4T7vULV5EsBwHogvMDdKoUy3aJ5l%2FAHSQ%2F1%2B5Wf%2FwQ3ep87fo%2BTiJewz8bqPFhy0mt0etLnbikCV9gJVnpyDRMjoIIjgYuxU06yAHNf5MuxAmXZnicJF4ns%3D--X6798baG%2F9uHzmvs--5UKJPHuh51f3CJoYzztoJQ%3D%3D"
	secretKeyBase := "fc7b8908a942f49665bf7f6df721f87752b4a1faedc93fcd21062eae5efc40d96bea93ff4742f6ca1de1c4d5ca5c5b2e7817fc725e287e8820d9666bd421d528"

	encrypted, iv, authTag, err := rails.ParseCookie(cookie)
	require.NoError(t, err)

	key, err := rails.DeriveKey(secretKeyBase, "sha256")
	require.NoError(t, err)

	decrypted, err := rails.Decrypt(key, iv, encrypted, authTag)
	require.NoError(t, err)

	session, err := rails.ExtractSession(decrypted)
	require.NoError(t, err)

	var result map[string]any
	err = json.Unmarshal(session, &result)
	require.NoError(t, err)

	assert.Equal(t, "b902d9bebbc6e470a94191dc9a733898", result["session_id"])
	assert.Equal(t, "qkBy7rNTgD-4-v8U0OOf4fSfxQnG_Qw5p0UfMRQp8qY", result["_csrf_token"])
}

// Rails 7.0 以前にできる Cookie
func TestFullDecrypt_SHA1(t *testing.T) {
	cookie := "%2B%2BNigEHSF27lmmCPrpjpfxrGiW3mkdoVK3%2BBiNw1Xg59TZEM%2FWNZGit%2BGgnmRQq7YwzYXZwC8EvQcuwCW%2BalNzgeVmZN1yUP0zPAgt3fR60IEyx%2FA%2Fw1bK%2B%2FojVPkf8NuSTzWhH5Iy1%2FoIw8%2ByvnPyHXXFXPcIjwbpYWA1vKMb6kmbwk1%2BPeyVkotgkCwh5t52TrhpirboRiWuUGnM23KY2ivN4C4NwghxVJYnA%3D--XILDjmyazA%2FtYC9Z--%2FNXnw9I%2F7t6UlZiYephpyQ%3D%3D"
	secretKeyBase := "3b8dd2ec6c277e157e271bc174f1e262610fde466c86aadc75a544ef2aa8deba1941d39d37a9bc0cc2349f64049310a3f2ffd579b31da309e16837e82fd4559b"

	encrypted, iv, authTag, err := rails.ParseCookie(cookie)
	require.NoError(t, err)

	key, err := rails.DeriveKey(secretKeyBase, "sha1")
	require.NoError(t, err)

	decrypted, err := rails.Decrypt(key, iv, encrypted, authTag)
	require.NoError(t, err)

	session, err := rails.ExtractSession(decrypted)
	require.NoError(t, err)

	var result map[string]any
	err = json.Unmarshal(session, &result)
	require.NoError(t, err)

	assert.Equal(t, "a1d9db6ba969958b74de76acc7ae7b74", result["session_id"])
	assert.Equal(t, "ppMoIJa+pchfYU32UyLgPOyvefSaEh7djQ/Ri0gGWuk=", result["_csrf_token"])
}

func TestExtractSession_InvalidJSON(t *testing.T) {
	_, err := rails.ExtractSession([]byte("not json"))
	assert.Error(t, err)
}

func TestExtractSession_InvalidBase64Message(t *testing.T) {
	_, err := rails.ExtractSession([]byte(`{"_rails":{"message":"!!!invalid!!!"}}`))
	assert.Error(t, err)
}
