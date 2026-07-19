# Security Policy

## Supported versions

ProxyLoom is currently a deployment preview. No release is production-supported yet. Security fixes are applied to the latest `main` branch until versioned releases are available.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not open a public issue for a suspected vulnerability and do not include real subscription URLs, proxy credentials, node configurations, database files, master keys, setup tokens, or session data in any report.

Include the affected revision, impact, reproduction steps using synthetic data, and any suggested mitigation. Maintainers will acknowledge a complete report as soon as practical and coordinate disclosure after a fix is available.

## Deployment boundary

The preview management interface should only be exposed on loopback or a trusted network. Use an HTTPS reverse proxy and secure cookies before exposing it across an untrusted network. Keep `master.key` separate from the encrypted data volume and back up both independently.
