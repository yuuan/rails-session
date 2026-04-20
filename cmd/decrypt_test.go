package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testCookie        = "L1rKa%2FEjOvdTc8FVmqJd2p8hDUgyR4N5LY4l5wWVkwFnnyKGUKj66t3kInndLb7N%2FDG4QHAItktGYaRag3zp0gdBSghlfaNEt49PWL%2FzSPfn4Iae4T7vULV5EsBwHogvMDdKoUy3aJ5l%2FAHSQ%2F1%2B5Wf%2FwQ3ep87fo%2BTiJewz8bqPFhy0mt0etLnbikCV9gJVnpyDRMjoIIjgYuxU06yAHNf5MuxAmXZnicJF4ns%3D--X6798baG%2F9uHzmvs--5UKJPHuh51f3CJoYzztoJQ%3D%3D"
	testSecretKeyBase = "fc7b8908a942f49665bf7f6df721f87752b4a1faedc93fcd21062eae5efc40d96bea93ff4742f6ca1de1c4d5ca5c5b2e7817fc725e287e8820d9666bd421d528"
)

func resetFlags() {
	decryptKey = ""
	decryptDigest = "sha256"
	decryptCookie = ""
	decryptEnv = ""
	encryptKey = ""
	encryptDigest = "sha256"
	encryptValues = ""
	encryptEnv = ""
}

func executeCmd(args ...string) (string, error) {
	resetFlags()
	out := new(bytes.Buffer)
	rootCmd.SetOut(out)
	rootCmd.SetErr(out)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return out.String(), err
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { os.Chdir(origDir) })
}

func TestDecryptCmd_WithFlags(t *testing.T) {
	out, err := executeCmd("decrypt", "--key", testSecretKeyBase, "--cookie", testCookie)
	require.NoError(t, err)
	assert.Contains(t, out, "b902d9bebbc6e470a94191dc9a733898")
	assert.Contains(t, out, "qkBy7rNTgD-4-v8U0OOf4fSfxQnG_Qw5p0UfMRQp8qY")
}

func TestDecryptCmd_WithEnvKey(t *testing.T) {
	t.Setenv("SECRET_KEY_BASE", testSecretKeyBase)
	out, err := executeCmd("decrypt", "--cookie", testCookie)
	require.NoError(t, err)
	assert.Contains(t, out, "b902d9bebbc6e470a94191dc9a733898")
}

func TestDecryptCmd_WithStdin(t *testing.T) {
	resetFlags()
	out := new(bytes.Buffer)
	rootCmd.SetOut(out)
	rootCmd.SetErr(out)
	rootCmd.SetIn(strings.NewReader(testCookie + "\n"))
	rootCmd.SetArgs([]string{"decrypt", "--key", testSecretKeyBase})
	err := rootCmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "b902d9bebbc6e470a94191dc9a733898")
}

func TestDecryptCmd_WithDotEnv(t *testing.T) {
	t.Setenv("SECRET_KEY_BASE", "")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	err := os.WriteFile(envFile, []byte("SECRET_KEY_BASE="+testSecretKeyBase+"\n"), 0644)
	require.NoError(t, err)
	chdir(t, dir)

	out, err := executeCmd("decrypt", "--cookie", testCookie)
	require.NoError(t, err)
	assert.Contains(t, out, "b902d9bebbc6e470a94191dc9a733898")
}

func TestDecryptCmd_WithEnvFlag(t *testing.T) {
	t.Setenv("SECRET_KEY_BASE", "")

	dir := t.TempDir()
	envFile := filepath.Join(dir, "custom.env")
	err := os.WriteFile(envFile, []byte("SECRET_KEY_BASE="+testSecretKeyBase+"\n"), 0644)
	require.NoError(t, err)

	out, err := executeCmd("decrypt", "--env", envFile, "--cookie", testCookie)
	require.NoError(t, err)
	assert.Contains(t, out, "b902d9bebbc6e470a94191dc9a733898")
}

func TestDecryptCmd_KeyFlagTakesPrecedenceOverEnvFile(t *testing.T) {
	t.Setenv("SECRET_KEY_BASE", "")

	dir := t.TempDir()
	envFile := filepath.Join(dir, "custom.env")
	err := os.WriteFile(envFile, []byte("SECRET_KEY_BASE=wrong-key\n"), 0644)
	require.NoError(t, err)

	out, err := executeCmd("decrypt", "--key", testSecretKeyBase, "--env", envFile, "--cookie", testCookie)
	require.NoError(t, err)
	assert.Contains(t, out, "b902d9bebbc6e470a94191dc9a733898")
}

func TestDecryptCmd_NoKey(t *testing.T) {
	t.Setenv("SECRET_KEY_BASE", "")
	chdir(t, t.TempDir())

	_, err := executeCmd("decrypt", "--cookie", testCookie)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--key flag, SECRET_KEY_BASE env var, or SECRET_KEY_BASE in .env is required")
}

func TestDecryptCmd_NoCookie(t *testing.T) {
	// stdin is a terminal (no pipe), no --cookie flag
	_, err := executeCmd("decrypt", "--key", testSecretKeyBase)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--cookie flag or stdin input is required")
}
