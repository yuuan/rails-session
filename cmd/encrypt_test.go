package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptCmd_Basic(t *testing.T) {
	out, err := executeCmd("encrypt", "--key", testSecretKeyBase, "--values", `{"user_id":"1"}`)
	require.NoError(t, err)
	cookie := strings.TrimSpace(out)
	assert.NotEmpty(t, cookie)

	// Decrypt to verify round-trip
	out2, err := executeCmd("decrypt", "--key", testSecretKeyBase, "--cookie", cookie)
	require.NoError(t, err)
	assert.Contains(t, out2, `"user_id"`)
	assert.Contains(t, out2, `"1"`)
}

func TestEncryptCmd_InvalidJSON(t *testing.T) {
	_, err := executeCmd("encrypt", "--key", testSecretKeyBase, "--values", `not json`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--values must be valid JSON")
}

func TestEncryptCmd_WithStdin(t *testing.T) {
	resetFlags()
	out := new(bytes.Buffer)
	rootCmd.SetOut(out)
	rootCmd.SetErr(out)
	rootCmd.SetIn(strings.NewReader(`{"user_id":"1"}` + "\n"))
	rootCmd.SetArgs([]string{"encrypt", "--key", testSecretKeyBase})
	err := rootCmd.Execute()
	require.NoError(t, err)

	cookie := strings.TrimSpace(out.String())
	assert.NotEmpty(t, cookie)

	// Round-trip check
	out2, err := executeCmd("decrypt", "--key", testSecretKeyBase, "--cookie", cookie)
	require.NoError(t, err)
	assert.Contains(t, out2, `"user_id"`)
}

func TestEncryptCmd_NoValues(t *testing.T) {
	_, err := executeCmd("encrypt", "--key", testSecretKeyBase)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--values flag or stdin input is required")
}

func TestEncryptCmd_NoKey(t *testing.T) {
	t.Setenv("SECRET_KEY_BASE", "")

	dir := t.TempDir()
	chdir(t, dir)

	_, err := executeCmd("encrypt", "--values", `{"user_id":"1"}`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--key flag, SECRET_KEY_BASE env var, or SECRET_KEY_BASE in .env is required")
}

func TestEncryptCmd_WithEnvKey(t *testing.T) {
	t.Setenv("SECRET_KEY_BASE", testSecretKeyBase)
	out, err := executeCmd("encrypt", "--values", `{"user_id":"1"}`)
	require.NoError(t, err)
	assert.NotEmpty(t, strings.TrimSpace(out))
}
