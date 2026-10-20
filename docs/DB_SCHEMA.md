# Database Schema

- `users`: username, PBKDF2 password hash, role, active state.
- `subscriptions`: registered Azure subscription identifier, display name, environment, enabled state.
- `policy_rules`: supported rule ID, severity, enabled flag, validated JSON configuration.
- `scans`: subscription, status (`queued`, `running`, `completed`, `failed`), start/end timestamps and safe error summary.
- `findings`: resource, rule, severity, status, details, scan reference.
- `remediation_requests`: requesting actor, approval state/decision actor, attempt count and result.
- `finding_exceptions`: finding reference, reason, approver and expiry timestamp.
- `audit_logs`: actor, action, entity, structured details, previous hash and current event hash.

Alembic initial migration: `migrations/versions/160337e09cab_initial_schema.py`. Local mode can use `AUTO_CREATE_SCHEMA=true`; deployed mode should use `AUTO_CREATE_SCHEMA=false` and run `alembic upgrade head` before API rollout.
