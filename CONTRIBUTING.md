# Contributing to ProxyLoom

ProxyLoom welcomes focused bug fixes, protocol fixtures, compatibility improvements, documentation corrections, and tests.

## Before submitting a change

1. Open an issue for substantial behavior or data-model changes so the compatibility and lossless-output requirements can be agreed first.
2. Use synthetic or publicly documented fixtures. Never commit real subscription URLs, access tokens, proxy credentials, node secrets, databases, master keys, or private deployment addresses.
3. Preserve unknown fields and same-format bytes unless the relevant adapter contract explicitly permits a transformation.
4. Add tests for parsing, conversion, naming, health behavior, or API changes as appropriate.

## Local checks

The backend supports Go 1.18 and is also tested with the current stable Go release. The web build uses Node.js 22.

```bash
go vet ./...
go test ./...
cd web
npm ci
npm run build
npm audit --audit-level=high
```

Run `docker compose build` when changing the Dockerfile, embedded web assets, or sing-box integration.

## Pull requests

Keep commits scoped and explain user-visible behavior, compatibility implications, and verification. Contributions are licensed under AGPL-3.0-or-later, matching the project license.
