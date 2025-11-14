# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it by:

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email the maintainer directly (see GitHub profile) or create a private security advisory
3. Include detailed information about the vulnerability:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Initial Response**: Within 48 hours of report
- **Status Update**: Within 7 days with assessment
- **Fix Timeline**: Critical issues within 30 days, others within 90 days
- **Public Disclosure**: After fix is released and users have time to update

## Security Considerations

### For Users

When using this integration, be aware that:

1. **Credentials Storage**: Your Neo Smart Blinds account credentials (email and password) are stored in Home Assistant's configuration. Ensure your Home Assistant instance is properly secured.

2. **Cloud Dependency**: This integration requires internet connectivity and relies entirely on the Neo Smart Blinds cloud API. If the API is unavailable, the integration will not function.

3. **Network Security**: All communication with the API uses HTTPS, but ensure your network is secure.

4. **Access Control**: Anyone with access to your Home Assistant instance can control your blinds.

### Known Security Limitations

1. **OAuth2 Password Grant**: Uses password grant flow which requires storing credentials
2. **No Local Control**: No offline functionality
3. **API Dependency**: Fully dependent on third-party cloud service
4. **Limited MFA**: No support for multi-factor authentication

### Recommendations

- Use a strong, unique password for your Neo Smart Blinds account
- Secure your Home Assistant instance with authentication
- Use HTTPS for Home Assistant access
- Keep Home Assistant and this integration updated
- Monitor Home Assistant logs for suspicious activity
- Consider network segmentation for IoT devices

## Security Updates

Security updates will be:
- Released as soon as possible after validation
- Announced in GitHub releases
- Tagged with [SECURITY] in the changelog
- Backported to supported versions when critical

## Acknowledgments

We appreciate the security research community's efforts to responsibly disclose vulnerabilities. Contributors will be acknowledged in the release notes (unless they prefer to remain anonymous).

## Contact

For security inquiries: Create a private security advisory on GitHub or contact the maintainer directly.

For general questions: Use GitHub Issues (but NOT for security vulnerabilities).
