# HRP (SSH Remote HTTP Reverse Proxy)

Small Go app that:

- Connects to an SSH server.
- Opens a remote TCP listener on that SSH server.
- Serves HTTP on that remote TCP port.
- Proxies HTTP and upgrade requests (including WebSocket handshake) to a local HTTPS target.
- Accepts self-signed localhost certificates.
- Records per-session HTTP request/response headers and bodies.

## Build

Using `xc` (task runner):

```bash
xc build
```

Or manually with Go:

```bash
go mod tidy
go build ./...
```

The `xc build` target builds with CGO disabled and outputs the binary to `bin/hrp`.

## Run

Minimal example (with smart defaults):

```bash
go run . \
  --ssh-addr 203.0.113.10 \
  --ssh-user tunnel \
  --remote-bind 18080 \
  --target-https https://localhost:8443
```

The above is equivalent to:

```bash
go run . \
  --ssh-addr 203.0.113.10:22 \
  --ssh-user tunnel \
  --remote-bind 127.0.0.1:18080 \
  --target-https https://localhost:8443
```

With explicit SSH key:

```bash
go run . \
  --ssh-addr 203.0.113.10:22 \
  --ssh-user tunnel \
  --ssh-key ~/.ssh/id_ed25519 \
  --remote-bind 127.0.0.1:18080 \
  --target-https https://localhost:8443 \
  --record-dir ./sessions
```

Or automatically use default SSH key (tries `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, `~/.ssh/id_rsa` in order):

```bash
go run . \
  --ssh-addr 203.0.113.10:22 \
  --ssh-user tunnel \
  --remote-bind 127.0.0.1:18080 \
  --target-https https://localhost:8443 \
  --record-dir ./sessions
```

Or use password auth:

```bash
go run . \
  --ssh-addr 203.0.113.10:22 \
  --ssh-user tunnel \
  --ssh-password 'secret'
```

Behind an external reverse proxy mounted on a path prefix:

```bash
go run . \
  --ssh-addr partner-test.eu.socionext.com \
  --ssh-user root \
  --remote-bind 3333 \
  --target-https https://localhost:300 \
  --public-origin https://partner-test.eu.socionext.com \
  --public-prefix /45e2383441efdf24b815a0c055227d9009a39f09
```

## Smart Defaults

- **`--ssh-addr`**: If no port is specified, defaults to port 22. Examples: `example.com` → `example.com:22`, `example.com:2222` stays as-is.
- **`--remote-bind`**: If given a bare port number (1-65535), assumes it's a port on localhost. Examples: `8080` → `127.0.0.1:8080`, `192.168.1.1:9090` stays as-is.

## SSH Authentication

- If `--ssh-key` is not specified, hrp automatically tries all available default SSH keys from `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, and `~/.ssh/id_rsa`.
- If the SSH key is encrypted (password-protected), hrp will prompt you to enter the passphrase on stdin.
- Alternatively, provide `--ssh-password` for password-based SSH authentication.

## Important Flags

- `--ssh-insecure-host-key` (default: `true`): skips SSH host key verification.
- `--ssh-known-hosts`: use when host key verification is enabled.
- `--public-origin`: external origin used when rewriting backend-generated absolute URLs in proxied HTML and redirect headers.
- `--public-prefix`: external path prefix mounted in front of hrp; also used for rewriting HTML asset paths and redirect targets.
- `--preserve-host`: forwards the incoming `Host` header upstream instead of forcing the backend target host.
- `--verbose`: logs request lifecycle and upstream round-trip diagnostics.
- `--request-body-limit` and `--response-body-limit`: max bytes captured per exchange. `0` means unlimited.

## Reverse Proxy Notes

- If an outer reverse proxy strips a prefix before forwarding to hrp, configure that prefix with `--public-prefix` or pass it as `X-Forwarded-Prefix`.
- hrp normalizes common nested asset requests such as `/connect/<server>/styles/...` back to `/styles/...` before proxying.
- HTML responses are rewritten to keep asset URLs, form targets, and redirect destinations on the public origin and prefix instead of leaking backend-only addresses.

## Tasks

### build

Build hrp with CGO disabled into bin/

```sh
mkdir -p bin
CGO_ENABLED=0 go build -o bin/hrp .
```

## Session Recording

Each incoming TCP connection gets a separate session file:

- `sessions/<session-id>.jsonl`

Each line is a JSON object containing one HTTP exchange with:

- request metadata and headers
- request body (base64)
- response status and headers
- response body (base64)
- truncation flags and byte counts

For upgraded requests, the HTTP handshake is recorded. Raw upgraded stream bytes are not decoded.
