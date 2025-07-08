# Security Policy

## Supported Versions

| Version | Supported | Notes                  |
| ------- | --------- | ---------------------- |
| 0.1.x   | ✅        | Testnet-1 pre-release  |
| < 0.1.0 | ❌        | Legacy code (no fix)   |

## Reporting a Vulnerability

If you discover a security vulnerability, please contact the Twilight security team by opening a GitHub issue in this repository and tagging the `@twilight/security-team`.

1. Open a new issue on the repository
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond promptly and provide a timeline for addressing the issue.

## Severity & Triage

We follow a four-level severity model:

| Level    | Description                 |
| -------- | --------------------------- |
| Critical | Broken key-leak, backdoor   |
| High     | Signature malleability      |
| Medium   | Missing input validation    |
| Low      | Documentation typo, outdated comments |

## Security Warning

**⚠️ SECURITY WARNING**

**This library has not been formally audited and is not recommended for production use.**

**Known Issues:**
- Uses curve25519-dalek v3.2.1 which has a timing vulnerability ([RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html))
- This will be resolved in v0.2.0 by upgrading to curve25519-dalek v4.1.3+
- Current version maintained for ecosystem compatibility

This library is intended for experimental and testnet use only. It has not been reviewed by independent security experts and should not be used in production environments where security is critical.

## Security Considerations

When using this library:

1. **Key Management**: Use secure key generation and storage practices
2. **Randomness**: Ensure your system has a good source of entropy
3. **Dependencies**: Keep dependencies updated and monitor for vulnerabilities
4. **Testing**: Thoroughly test all cryptographic operations in your specific use case
5. **Audit**: Consider professional security audit before any production use

## Dependencies

This library depends on:
- `curve25519-dalek` - Elliptic curve cryptography
- `merlin` - Transcript-based proofs
- `rand` - Random number generation

Monitor these dependencies for security updates.