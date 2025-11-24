# Security Policy

## Supported Versions

|------------------------------|
| Version |        Supported         |
| ------- | -------------------- |
|   3.0.x   | :white_check_mark: |
|   2.x.x   |                :x:                |
|   1.x.x   |                :x:                |
|--------|---------------------|

## Reporting a Vulnerability

We take the security of FileXray seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### **Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to **voltsparx@gmail.com**.

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

### Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Preferred Languages

We prefer all communications to be in English.

## Security Considerations for Users

### Safe Usage Practices

1. **File Sources**: Only analyze files from trusted sources
2. **Permissions**: Ensure you have legal rights to analyze files
3. **Environment**: Run FileXray in a secure, isolated environment when analyzing potentially malicious files
4. **Updates**: Keep FileXray updated to the latest version
5. **System Security**: Maintain updated antivirus and system security

### Data Handling

- FileXray may extract sensitive information from files
- Handle extracted data responsibly and in accordance with privacy laws
- Securely delete analysis outputs when no longer needed
- Be aware that extracted metadata may contain personal information

## Security Features

### Built-in Protections

1. **File Size Limits**: Configurable maximum file size to prevent resource exhaustion
2. **Input Validation**: Comprehensive validation of all file inputs
3. **Memory Management**: Careful memory handling for large files
4. **Error Handling**: Secure error messages that don't reveal sensitive information

### Dependency Security

- Regular updates of all dependencies
- Security monitoring of third-party libraries
- Vulnerability scanning in CI/CD pipeline

## Security Updates

Security updates will be released as soon as possible after vulnerability confirmation. We will:

1. Acknowledge receipt of vulnerability report
2. Investigate and confirm the vulnerability
3. Develop and test a fix
4. Release patched version
5. Publicly disclose (after allowing time for updates)

## Recognition

We believe in recognizing security researchers who help us improve FileXray's security. With your permission, we will acknowledge your contribution in our release notes.

## Legal

Please make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service.

Thank you for helping keep FileXray and its users safe!