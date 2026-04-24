# rails-session

A CLI tool to decrypt and encrypt Rails session cookies (AES-256-GCM).

## Installation

### Homebrew (macOS / Linux)

```bash
brew install yuuan/tap/rails-session
```

### Go install

```bash
go install github.com/yuuan/rails-session@latest
```

### Build from source

```bash
git clone https://github.com/yuuan/rails-session.git
cd rails-session
go build -o rails-session .
```

## Usage

### Providing the Secret Key

The `SECRET_KEY_BASE` can be provided in three ways (checked in this order):

1. `--key` / `-k` flag
2. `SECRET_KEY_BASE` environment variable
3. `SECRET_KEY_BASE=...` in a `.env` file (defaults to `./.env`, or the path given via `--env` / `-e`)

Use `--env` / `-e` to load the key from a `.env` file at a non-default path:

```bash
rails-session decrypt --env path/to/.env -c 'ENCRYPTED_COOKIE_VALUE'
rails-session encrypt --env path/to/.env -v '{"user_id": 42}'
```

`--env` can be combined with `--key`, but `--key` still takes precedence.

### Decrypt a session cookie

```bash
# Using the --cookie flag
rails-session decrypt -k YOUR_SECRET_KEY_BASE -c 'ENCRYPTED_COOKIE_VALUE'

# Using stdin (e.g. from clipboard)
pbpaste | rails-session decrypt -k YOUR_SECRET_KEY_BASE

# Using environment variable for the key
export SECRET_KEY_BASE=YOUR_SECRET_KEY_BASE
rails-session decrypt -c 'ENCRYPTED_COOKIE_VALUE'
```

Output is pretty-printed JSON:

```json
{
  "session_id": "abc123",
  "user_id": 42,
  "_csrf_token": "..."
}
```

### Encrypt values into a session cookie

```bash
# Using the --values flag
rails-session encrypt -k YOUR_SECRET_KEY_BASE -v '{"user_id": 42}'

# Using stdin
echo '{"user_id": 42}' | rails-session encrypt -k YOUR_SECRET_KEY_BASE
```

Output is a URL-encoded cookie string ready to use in a browser or HTTP request.

### Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--key` | `-k` | Rails `SECRET_KEY_BASE` | `SECRET_KEY_BASE` env var or `.env` |
| `--env` | `-e` | Path to `.env` file containing `SECRET_KEY_BASE` | `./.env` |
| `--digest` | `-d` | PBKDF2 hash digest (`sha1` or `sha256`) | `sha256` |
| `--cookie` | `-c` | Encrypted cookie value (decrypt only) | stdin |
| `--values` | `-v` | Session values as JSON (encrypt only) | stdin |

## How it works

1. **Key derivation** - Derives a 32-byte AES key from `SECRET_KEY_BASE` using PBKDF2 with the salt `"authenticated encrypted cookie"` (1000 iterations).
2. **Cookie format** - Rails cookies are URL-encoded and contain three Base64-encoded segments separated by `--`: encrypted data, IV, and GCM auth tag.
3. **Encryption** - Uses AES-256-GCM.
4. **Session envelope** - The decrypted payload is a JSON envelope `{"_rails":{"message":"..."}}` where the message is Base64-encoded session data.

## Digest option

Rails 5.2+ defaults to SHA-256 for PBKDF2 key derivation. Older Rails versions may use SHA-1. Use `--digest sha1` if you're working with an older Rails app.
