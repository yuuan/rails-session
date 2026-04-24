package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/yuuan/rails-session/rails"

	"github.com/spf13/cobra"
)

var (
	decryptKey    string
	decryptDigest string
	decryptCookie string
	decryptEnv    string
)

func init() {
	decryptCmd.Flags().StringVarP(&decryptKey, "key", "k", "", "Rails SECRET_KEY_BASE (falls back to SECRET_KEY_BASE env var)")
	decryptCmd.Flags().StringVarP(&decryptDigest, "digest", "d", "sha256", "Hash digest for PBKDF2 (sha1 or sha256)")
	decryptCmd.Flags().StringVarP(&decryptCookie, "cookie", "c", "", "Encrypted session cookie value (or pass via stdin)")
	decryptCmd.Flags().StringVarP(&decryptEnv, "env", "e", "", "Path to .env file containing SECRET_KEY_BASE (default: ./.env)")

	rootCmd.AddCommand(decryptCmd)
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a Rails session cookie",
	RunE: func(cmd *cobra.Command, args []string) error {
		secretKey, err := resolveKey(decryptKey, decryptEnv)
		if err != nil {
			return err
		}

		if decryptCookie == "" {
			if cookie, ok := readFromStdin(cmd); ok {
				decryptCookie = cookie
			}
		}
		if decryptCookie == "" {
			return fmt.Errorf("--cookie flag or stdin input is required")
		}

		encrypted, iv, authTag, err := rails.ParseCookie(decryptCookie)
		if err != nil {
			return err
		}

		key, err := rails.DeriveKey(secretKey, decryptDigest)
		if err != nil {
			return err
		}

		decrypted, err := rails.Decrypt(key, iv, encrypted, authTag)
		if err != nil {
			return err
		}

		session, err := rails.ExtractSession(decrypted)
		if err != nil {
			return err
		}

		// Pretty-print the session JSON
		var obj any
		out := cmd.OutOrStdout()
		if err := json.Unmarshal(session, &obj); err != nil {
			fmt.Fprintln(out, string(session))
			return nil
		}

		pretty, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			fmt.Fprintln(out, string(session))
			return nil
		}

		fmt.Fprintln(out, string(pretty))
		return nil
	},
}
