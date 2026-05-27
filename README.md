# TLS-Backed Token & SSH Certificate Authority

A lightweight, Linux-native authentication and authorization platform built on cryptographic trust. No static credentials. No long-lived secrets. Identity is derived entirely from TLS certificates, RSA-signed JWTs, and short-lived SSH certificates.

---

## Overview

The platform is split into two isolated components:

| Component | Purpose |
|---|---|
| **Token Service** | Validates mTLS client certificate fingerprints and issues scoped RSA-signed JWTs |
| **Signer Service** | Isolated signing daemon responsible for JWT signing and SSH certificate issuance |

The architecture intentionally separates public-facing validation, authorization logic, and private key operations — reducing attack surface and allowing the signer to run with tightly constrained permissions.

---

## Features

### mTLS Client Authentication & JWT Issuance

Clients authenticate using TLS client certificates — no passwords required.

The Token Service:
- Extracts the TLS client certificate fingerprint
- Validates the fingerprint against PostgreSQL
- Checks allowed permissions and scopes
- Issues a short-lived RSA-signed JWT

### SSH Certificate Authority

The Signer Service can issue:
- Short-lived SSH user certificates
- Scoped temporary access certificates
- CI/CD deployment certificates
- Emergency elevation certificates

All certificates are signed by an internal SSH CA key and expire automatically.

### Temporary CI/CD Runner Elevation

Git runners can request short-lived SSH certificates for deployment operations without holding any static credentials.

**Flow:**

```
Runner authenticates (JWT or mTLS)
  → Backend validates authorization
    → Signer issues short-lived SSH certificate
      → Certificate deployed to runner
        → Runner gains temporary SSH access
          → Certificate expires automatically
```

This eliminates:
- Static SSH keys
- Shared deployment credentials
- Persistent privileged access

---

## License

[GPL v3](LICENSE)
