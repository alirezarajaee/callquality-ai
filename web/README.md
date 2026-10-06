# CallQuality AI Web Dashboard

Local-first React dashboard for the CallQuality AI Go analysis API.

## Requirements

- Node.js 20.19+
- npm 10+
- CallQuality AI Go API running on `127.0.0.1:8090`

Vite 8 requires Node.js 20.19+ or 22.12+; the project is pinned to the current React 19 / Vite 8 toolchain used for this phase.

## Run

From `web/`:

```bat
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

The Vite development server proxies `/api` to `http://127.0.0.1:8090`, so the browser does not need a separate CORS configuration in development.
