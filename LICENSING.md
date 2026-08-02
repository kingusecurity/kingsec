# KingSec Licensing

KingSec offers three editions: Community, Professional, and Enterprise.

> **Relationship to LICENSE:** This document describes commercial *feature
> tiers*, not a grant of rights to the software itself. All editions —
> including Community — are distributed under the terms in
> [LICENSE](LICENSE) ("Proprietary — All Rights Reserved"); using any
> edition of KingSec requires the license agreement provided with your
> download or purchase. Contact **kingusecurity@gmail.com** for licensing
> questions.

## Editions

### Community Edition (Free)

- Single organization
- Up to 5 users
- Core security scanners
- PDF reports
- Manual assessments
- No scheduling, integrations, or API keys

Activated by default when no license key is configured.

### Professional Edition

- Unlimited users and organizations
- Team collaboration and activity feed
- Scheduled scans
- Third-party integrations (Slack, Jira, email, SIEM)
- API key management
- Advanced reporting

### Enterprise Edition

- Everything in Professional
- SSO (placeholder — custom integration required)
- Priority support
- Enterprise audit trail
- Custom roles and permissions
- Data retention policies
- Custom branding

## Activation Process

1. Purchase a license key from the KingSec sales team.
2. Navigate to **Settings > License** in the KingSec UI.
3. Click **Activate License** and enter your license key.
4. The system validates the key and enables the corresponding edition features.

## Upgrade Path

- **Community → Professional**: Activate a Professional license key.
- **Professional → Enterprise**: Activate an Enterprise license key (replaces existing license).
- **Downgrade**: Deactivate the current license and activate a lower-tier license.

## License Validation

Licenses are validated on every request to feature-gated endpoints:

1. **Signature verification**: Each license is signed with a hash of its key fields to detect tampering.
2. **Expiration check**: Expired licenses enter a 30-day grace period before being restricted.
3. **Clock rollback protection**: The system detects if the system clock has been moved backward.
4. **Status enforcement**: Revoked or inactive licenses fall back to Community Edition features.

## Feature Gates

The `LicenseGate` service centralizes all edition checks:

- `can_use_integrations()`
- `can_use_scheduling()`
- `can_use_api_keys()`
- `can_use_advanced_reports()`
- `can_use_sso()`
- `can_use_enterprise_audit()`
- `can_use_custom_roles()`
- `can_use_custom_branding()`
- `can_use_team_collaboration()`
- `can_create_multiple_orgs()`

No scattered edition checks exist outside this service.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/license` | Full license info |
| GET | `/api/v1/license/features` | Features and limits |
| GET | `/api/v1/license/status` | Edition and status only |
| POST | `/api/v1/license/activate` | Activate a license key |
| POST | `/api/v1/license/deactivate` | Deactivate current license |

## Auditing

All license events are recorded in the audit trail:

- `LICENSE_ACTIVATED` — A new license was activated.
- `LICENSE_EXPIRED` — A license reached its expiration date.
- `LICENSE_RENEWED` — A license was renewed with a new key or edition.
- `LICENSE_VALIDATION_FAILED` — Signature or clock rollback detection triggered.
- `LICENSE_DEACTIVATED` — A license was manually deactivated.
- `EDITION_CHANGED` — The edition was changed (e.g. Professional → Enterprise).

## Configuration

No configuration is required for Community Edition. To use Professional or Enterprise, activate a license key through the UI or API.
