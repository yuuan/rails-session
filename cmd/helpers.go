package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// resolveKey resolves SECRET_KEY_BASE from flag, env var, or .env file.
func resolveKey(flagValue, envPath string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if v := os.Getenv("SECRET_KEY_BASE"); v != "" {
		return v, nil
	}
	path := envPath
	if path == "" {
		path = ".env"
	}
	if v := lookupDotEnv("SECRET_KEY_BASE", path); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("--key flag, SECRET_KEY_BASE env var, or SECRET_KEY_BASE in .env is required")
}

// lookupDotEnv reads a KEY=VALUE from the given .env file path.
func lookupDotEnv(key, path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	prefix := key + "="
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

func readFromStdin(cmd *cobra.Command) (string, bool) {
	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); ok {
		stat, _ := f.Stat()
		if stat.Mode()&os.ModeCharDevice != 0 {
			return "", false
		}
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return "", false
	}
	return s, true
}
