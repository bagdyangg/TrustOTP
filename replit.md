# Yopass - Secure Secret Sharing

Yopass is a secure secret sharing application. Users can encrypt and share secrets (messages or files) with automatic expiration and one-time download support.

## Architecture

- **Frontend**: React + Vite + TypeScript app in `website/` directory, running on port 5000
- **Backend**: Go HTTP server in `cmd/yopass-server/`, running on port 1337
- **Database**: Memcached (started automatically via `start.sh`)

## Project Structure

```
website/          - React/Vite frontend (TypeScript)
cmd/
  yopass-server/  - Go backend server
  yopass/         - CLI client
pkg/
  server/         - Server package (memcached, redis, http handlers)
  yopass/         - Core encryption/decryption logic
start.sh          - Startup script (starts memcached, backend, frontend)
```

## Running the App

The `start.sh` script:
1. Starts memcached on `localhost:11211`
2. Builds and starts the Go backend on `localhost:1337`
3. Starts the Vite dev server on `0.0.0.0:5000`

The Vite server proxies API requests (`/secret/*` and `/file/*`) to the Go backend.

## Backend Configuration

The Go backend supports flags/env vars:
- `--database`: `memcached` (default) or `redis`
- `--memcached`: memcached address (default: `localhost:11211`)
- `--redis`: Redis URL (default: `redis://localhost:6379/0`)
- `--port`: listen port (default: `1337`)
- `--max-length`: max encrypted secret length (default: `10000`)

## Deployment

Configured as a VM deployment (requires always-running memcached process).
Run command: `bash /home/runner/workspace/start.sh`
