# Secrets Directory

This directory shows the structure of secrets files. Create a `secrets/` directory (gitignored) with actual values.

## Expected files:

```
secrets/
├── db-password          # Database password
├── api-key              # API key for external services
└── smtp-password        # SMTP credentials for email
```

## Usage in sysconf:

```python
from sysconf import get_secret

db_pass = get_secret("db-password")
```

Alternatively, set environment variables:
```bash
export DB_PASSWORD="your-password"
```

Environment variables take precedence over files.
