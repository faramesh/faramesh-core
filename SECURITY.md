# Security Policy

We take security seriously and appreciate responsible disclosure of vulnerabilities.

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

### Option 1: GitHub Security Advisory (Preferred)

1. Go to: https://github.com/faramesh/faramesh-core/security/advisories/new
2. Click "Report a vulnerability"
3. Fill out the security advisory form
4. Submit privately

### Option 2: Email

Email: **security@faramesh.dev** (if available)

**Note:** If the email address is not available, use GitHub Security Advisory.

---

## What to Include

When reporting a vulnerability, please include:

1. **Description**: Clear description of the issue
2. **Affected Components**: Which parts of Faramesh are affected
3. **Steps to Reproduce**: Detailed steps or proof-of-concept
4. **Impact Assessment**: Potential impact and severity
5. **Suggested Fix**: If you have ideas for a fix (optional)

---

## Response Timeline

- **Acknowledgment**: Within 3 business days
- **Initial Assessment**: Within 7 business days
- **Update**: We'll keep you informed of remediation progress
- **Resolution**: We'll work to resolve critical issues as quickly as possible

---

## Security Best Practices

### For Users

1. **Keep Updated**: Always use the latest version
2. **Use Authentication**: Set `FARAMESH_TOKEN` in production
3. **Secure Policies**: Protect policy files with proper permissions
4. **Database Security**: Use strong passwords and secure connections for PostgreSQL
5. **Network Security**: Use HTTPS in production, restrict network access
6. **Regular Audits**: Review policies and approval decisions regularly

### For Developers

1. **Input Validation**: Always validate and sanitize inputs
2. **No Hardcoded Secrets**: Never commit tokens or passwords
3. **Dependency Updates**: Keep dependencies updated
4. **Security Reviews**: Review code for security issues
5. **Follow Guidelines**: Follow security guardrails in [SECURITY-GUARDRAILS.md](docs/SECURITY-GUARDRAILS.md)

---

## Known Security Considerations

### Current Limitations

1. **No Rate Limiting**: Faramesh doesn't implement rate limiting. Use a reverse proxy (nginx) or API gateway for rate limiting in production.

2. **Policy File Security**: Policy files are not encrypted. Protect with file system permissions.

3. **Input Encryption**: Inputs are not encrypted at rest. Use database encryption for sensitive data.

4. **Shell Command Execution**: If executors use `shell=True`, command sanitization is best-effort. Real security comes from approval workflows.

5. **Single Policy File**: Currently uses a single policy file. Multi-file policies may be added in the future.

### Security Features

1. **Deny-by-Default**: Actions are denied unless explicitly allowed
2. **Input Validation**: All inputs are validated and sanitized
3. **Command Sanitization**: Shell commands are sanitized
4. **No Side Effects Until Approval**: Policy evaluation has no side effects
5. **Optimistic Locking**: Prevents race conditions
6. **Authentication**: Bearer token authentication supported

See [Security Guardrails](docs/SECURITY-GUARDRAILS.md) for detailed security mechanisms.

---

## Security Updates

Security updates will be:
- Released as patch versions (e.g., 0.2.0 → 0.2.1)
- Documented in [CHANGELOG.md](CHANGELOG.md)
- Announced via GitHub Security Advisories

---

## Responsible Disclosure

We follow responsible disclosure practices:

1. **Private Reporting**: Report vulnerabilities privately
2. **No Public Disclosure**: Don't disclose publicly until fixed
3. **Coordination**: We'll coordinate disclosure timing
4. **Credit**: We'll credit you in security advisories (if desired)

---

## See Also

- [Security Guardrails](docs/SECURITY-GUARDRAILS.md) - Security mechanisms
- [Error Handling](docs/ERROR-HANDLING.md) - Error codes and handling
- [Policy Configuration](docs/POLICIES.md) - Policy security
