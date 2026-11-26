# Security Policy

## Supported Versions

This is an educational/demonstration project. Security updates are provided on a best-effort basis.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do not** open a public issue for security vulnerabilities
2. Email security concerns to the repository maintainer via GitHub
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond to security reports within 7 days and work with you to address the issue.

## Security Considerations

**Important**: This is a demonstration/educational platform intended for learning Zero Trust concepts. 

### Demo Mode Warnings

- Demo mode uses fixed credentials and simplified crypto for ease of setup
- Do NOT deploy demo mode to production or expose it to untrusted networks
- Demo credentials (`Ztna`/`Ztna123`) are publicly documented

### Production Deployment

For production use:

1. Set `ZTNA_DEMO=0`
2. Configure strong `ZTNA_ADMIN_KEY` (32+ characters)
3. Configure strong `ZTNA_AUDIT_ANCHOR_KEY` (32+ characters)
4. Use proper OIDC/Keycloak integration instead of local auth
5. Deploy behind TLS termination (nginx, Traefik)
6. Enable `ZTNA_ADMIN_REQUIRE_MTLS=1` for admin API
7. Use PostgreSQL instead of SQLite for the enterprise audit chain
8. Configure proper firewall rules and network isolation
9. Regular security audits and penetration testing
10. Monitor audit logs and SIEM integrations

### Known Limitations

- The desktop GUI manager login does not use MFA in demo mode
- In-memory device blocks are not persistent across restarts (use enterprise API for production)
- SQLite audit chain is suitable for single-instance demos only
- File-based session storage is demo-only; use Redis or database-backed sessions for production

## Security Features

This implementation includes:

- **Tamper-evident audit chain** with HMAC-SHA256 and external anchors
- **Fail-closed design** - integrity failures refuse operations rather than bypassing audit
- **Cryptographic verification** of all audit records on startup and before mutations
- **Rate limiting and throttling** with exponential backoff
- **Device posture validation** before access decisions
- **MFA (TOTP)** with encrypted secret storage
- **Signed HTTP requests** with body integrity verification
- **Context-aware risk scoring**

## Responsible Disclosure

We appreciate security researchers and users who report vulnerabilities responsibly. Findings will be credited in release notes unless anonymity is requested.
