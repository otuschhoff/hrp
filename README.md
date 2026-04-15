# HRP (SSH Remote HTTP Reverse Proxy)

Small Go app that:

- Connects to an SSH server.
- Opens a remote TCP listener on that SSH server.
- Serves HTTP on that remote TCP port.
- Proxies HTTP and upgrade requests (including WebSocket handshake) to a local HTTPS target.
- Accepts self-signed localhost certificates.
- Records per-session HTTP request/response headers and bodies.

## Build

```bash
go mod tidy
go build ./...
```

## Run

```bash
go run . \
  --ssh-addr 203.0.113.10:22 \
  --ssh-user tunnel \
  --ssh-key ~/.ssh/id_ed25519 \
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

## Important Flags

- `--ssh-insecure-host-key` (default: `true`): skips SSH host key verification.
- `--ssh-known-hosts`: use when host key verification is enabled.
- `--request-body-limit` and `--response-body-limit`: max bytes captured per exchange. `0` means unlimited.

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
