package rails_test

import (
	"testing"

	"github.com/yuuan/rails-session/rails"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCookie(t *testing.T) {
	// Rails 7.1 cookie
	cookie := "L1rKa%2FEjOvdTc8FVmqJd2p8hDUgyR4N5LY4l5wWVkwFnnyKGUKj66t3kInndLb7N%2FDG4QHAItktGYaRag3zp0gdBSghlfaNEt49PWL%2FzSPfn4Iae4T7vULV5EsBwHogvMDdKoUy3aJ5l%2FAHSQ%2F1%2B5Wf%2FwQ3ep87fo%2BTiJewz8bqPFhy0mt0etLnbikCV9gJVnpyDRMjoIIjgYuxU06yAHNf5MuxAmXZnicJF4ns%3D--X6798baG%2F9uHzmvs--5UKJPHuh51f3CJoYzztoJQ%3D%3D"

	encrypted, iv, authTag, err := rails.ParseCookie(cookie)

	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEmpty(t, iv)
	assert.NotEmpty(t, authTag)
}

func TestParseCookie_InvalidFormat(t *testing.T) {
	_, _, _, err := rails.ParseCookie("xxxxxxxxxxxx")
	assert.Error(t, err)
}

func TestParseCookie_InvalidBase64(t *testing.T) {
	_, _, _, err := rails.ParseCookie("!!!--!!!--!!!")
	assert.Error(t, err)
}
