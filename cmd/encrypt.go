package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/yuuan/rails-session/rails"

	"github.com/spf13/cobra"
)

var (
	encryptKey    string
	encryptDigest string
	encryptValues string
	encryptEnv    string
)

func init() {
	encryptCmd.Flags().StringVarP(&encryptKey, "key", "k", "", "Rails SECRET_KEY_BASE (falls back to SECRET_KEY_BASE env var)")
	encryptCmd.Flags().StringVarP(&encryptDigest, "digest", "d", "sha256", "Hash digest for PBKDF2 (sha1 or sha256)")
	encryptCmd.Flags().StringVarP(&encryptValues, "values", "v", "", "Session values as JSON (or pass via stdin)")
	encryptCmd.Flags().StringVarP(&encryptEnv, "env", "e", "", "Path to .env file containing SECRET_KEY_BASE (default: ./.env)")

	rootCmd.AddCommand(encryptCmd)
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt values into a Rails session cookie",
	RunE: func(cmd *cobra.Command, args []string) error {
		secretKey, err := resolveKey(encryptKey, encryptEnv)
		if err != nil {
			return err
		}

		if encryptValues == "" {
			if v, ok := readFromStdin(cmd); ok {
				encryptValues = v
			}
		}
		if encryptValues == "" {
			return fmt.Errorf("--values flag or stdin input is required")
		}

		if !json.Valid([]byte(encryptValues)) {
			return fmt.Errorf("--values must be valid JSON")
		}

		envelope, err := rails.WrapSession([]byte(encryptValues))
		if err != nil {
			return err
		}

		key, err := rails.DeriveKey(secretKey, encryptDigest)
		if err != nil {
			return err
		}

		iv, encrypted, authTag, err := rails.Encrypt(key, envelope)
		if err != nil {
			return err
		}

		cookie := rails.BuildCookie(encrypted, iv, authTag)
		fmt.Fprintln(cmd.OutOrStdout(), cookie)
		return nil
	},
}
