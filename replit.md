# Yopass - Secure Secret Sharing

Yopass is a secure secret sharing application. Users can encrypt and share secrets (messages or files) with automatic expiration and one-time download support.

## Architecture

- **Frontend**: React + Vite + TypeScript app in `website/` directory, running on port 5000
- **Backend**: Go HTTP server in `cmd/yopass-server/`, running on port 1337
- **Database**: Redis (only storage backend)

## Project Structure

```
website/          - React/Vite frontend (TypeScript)
cmd/
  yopass-server/  - Go backend server
pkg/
  server/         - Server package (redis, http handlers, logging)
  yopass/         - Core encryption/decryption logic
start.sh          - Startup script (starts backend + frontend)
```

## Running the App

The `start.sh` script:
1. Builds and starts the Go backend on `localhost:1337`
2. Starts the Vite dev server on `0.0.0.0:5000`

The Vite server proxies API requests (`/secret/*`, `/file/*`, `/create/*`, `/config`) to the Go backend.

## Backend Configuration

The Go backend supports flags/env vars:
- `--redis`: Redis URL (default: `redis://localhost:6379/0`)
- `--port`: listen port (default: `1337`)
- `--address`: listen address (default: `0.0.0.0`)
- `--max-length`: max encrypted secret length (default: `10000`)
- `--cors-allow-origin`: CORS origin (default: `*`)
- `--force-onetime-secrets`: require one-time download
- `--disable-upload`: disable file upload endpoints
- `--prefetch-secret`: display one-time use info (default: `true`)
- `--no-language-switcher`: disable language switcher in UI
- `--trusted-proxies`: trusted proxy IPs/CIDRs for X-Forwarded-For
- `--privacy-notice-url`: URL to privacy notice page
- `--imprint-url`: URL to imprint/legal notice page

## Refactoring Progress (Stage 1 Complete)

Removed:
- All non-English locales (only `en.json` remains; Armenian to be added later)
- Memcached support (Redis is the only storage backend)
- CLI client (`cmd/yopass/` and `pkg/yopass/client.go`)
- Prometheus metrics (server, middleware, dependencies)
- Built-in TLS support (TLS via Nginx reverse proxy only)

## Deployment

Will be migrated to self-hosted server with Docker + Nginx reverse proxy + TLS.
Current Replit setup: `bash /home/runner/workspace/start.sh`
