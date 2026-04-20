package rails_test

import (
	"testing"

	"rails-session/rails"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveKey_SHA256(t *testing.T) {
	key, err := rails.DeriveKey("test-secret", "sha256")
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestDeriveKey_SHA1(t *testing.T) {
	key, err := rails.DeriveKey("test-secret", "sha1")
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestDeriveKey_UnsupportedHash(t *testing.T) {
	_, err := rails.DeriveKey("test-secret", "md5")
	assert.Error(t, err)
}

func TestDecrypt_WithValidData(t *testing.T) {
	// Use the Rails 7.1 cookie and key from the original test
	cookie := "L1rKa%2FEjOvdTc8FVmqJd2p8hDUgyR4N5LY4l5wWVkwFnnyKGUKj66t3kInndLb7N%2FDG4QHAItktGYaRag3zp0gdBSghlfaNEt49PWL%2FzSPfn4Iae4T7vULV5EsBwHogvMDdKoUy3aJ5l%2FAHSQ%2F1%2B5Wf%2FwQ3ep87fo%2BTiJewz8bqPFhy0mt0etLnbikCV9gJVnpyDRMjoIIjgYuxU06yAHNf5MuxAmXZnicJF4ns%3D--X6798baG%2F9uHzmvs--5UKJPHuh51f3CJoYzztoJQ%3D%3D"
	secretKeyBase := "fc7b8908a942f49665bf7f6df721f87752b4a1faedc93fcd21062eae5efc40d96bea93ff4742f6ca1de1c4d5ca5c5b2e7817fc725e287e8820d9666bd421d528"

	encrypted, iv, authTag, err := rails.ParseCookie(cookie)
	require.NoError(t, err)

	key, err := rails.DeriveKey(secretKeyBase, "sha256")
	require.NoError(t, err)

	decrypted, err := rails.Decrypt(key, iv, encrypted, authTag)
	require.NoError(t, err)
	assert.NotEmpty(t, decrypted)
}

func TestDecrypt_WithWrongKey(t *testing.T) {
	cookie := "%2B%2BNigEHSF27lmmCPrpjpfxrGiW3mkdoVK3%2BBiNw1Xg59TZEM%2FWNZGit%2BGgnmRQq7YwzYXZwC8EvQcuwCW%2BalNzgeVmZN1yUP0zPAgt3fR60IEyx%2FA%2Fw1bK%2B%2FojVPkf8NuSTzWhH5Iy1%2FoIw8%2ByvnPyHXXFXPcIjwbpYWA1vKMb6kmbwk1%2BPeyVkotgkCwh5t52TrhpirboRiWuUGnM23KY2ivN4C4NwghxVJYnA%3D--XILDjmyazA%2FtYC9Z--%2FNXnw9I%2F7t6UlZiYephpyQ%3D%3D"

	encrypted, iv, authTag, err := rails.ParseCookie(cookie)
	require.NoError(t, err)

	key, err := rails.DeriveKey("xxxxxxxxxxxx", "sha256")
	require.NoError(t, err)

	_, err = rails.Decrypt(key, iv, encrypted, authTag)
	assert.Error(t, err)
}
