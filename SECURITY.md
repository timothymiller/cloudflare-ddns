# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

Only the latest release in the `2.0.x` series receives security updates. The legacy Python codebase and all `1.x` releases are **end-of-life** and will not be patched. Users on older versions should upgrade to the latest release immediately.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities privately using one of the following methods:

1. **GitHub Private Vulnerability Reporting** — Use the [Security Advisories](https://github.com/timothymiller/cloudflare-ddns/security/advisories/new) page to submit a private report directly on GitHub.
2. **Email** — Contact the maintainer directly at the email address listed on the [GitHub profile](https://github.com/timothymiller).

### What to Include

- A clear description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected version(s)
- Any suggested fix or mitigation, if applicable

### What to Expect

- **Acknowledgment** within 72 hours of your report
- **Status updates** at least every 7 days while the issue is being investigated
- A coordinated disclosure timeline — we aim to release a fix within 30 days of a confirmed vulnerability, and will credit reporters (unless anonymity is preferred) in the release notes

If a report is declined (e.g., out of scope or not reproducible), you will receive an explanation.

## Security Considerations

This project handles **Cloudflare API tokens** that grant DNS editing privileges. Users should be aware of the following:

### API Token Handling

- **Never commit your API token** to version control or include it in Docker images.
- Use `CLOUDFLARE_API_TOKEN_FILE` or Docker secrets to inject tokens at runtime rather than passing them as plain environment variables where possible.
- Create a **scoped API token** with only "Edit DNS" permission on the specific zones you need — avoid using Global API Keys.

### Container Security

- The Docker image runs as a **static binary from scratch** with zero runtime dependencies, which minimizes the attack surface.
- Use `security_opt: no-new-privileges:true` in Docker Compose deployments.
- Pin image tags to a specific version (e.g., `timothyjmiller/cloudflare-ddns:v2.0.10`) rather than using `latest` in production.

### Network Security

- The default IP detection provider (`cloudflare.trace`) communicates directly with Cloudflare's infrastructure over HTTPS and does not log your IP.
- All Cloudflare API calls are made over HTTPS/TLS.
- `--network host` mode is required for IPv6 detection — be aware this gives the container access to the host's full network stack.

### Supply Chain

- The project is built with `cargo` and all dependencies are declared in `Cargo.lock` for reproducible builds.
- Docker images are built via GitHub Actions and published to Docker Hub. Multi-arch builds cover `linux/amd64`, `linux/arm64`, and `linux/ppc64le`.

## Scope

The following are considered **in scope** for security reports:

- Authentication or authorization flaws (e.g., token leakage, insufficient credential protection)
- Injection vulnerabilities in configuration parsing
- Vulnerabilities in DNS record handling that could lead to record hijacking or poisoning
- Dependency vulnerabilities with a demonstrable exploit path
- Container escape or privilege escalation

The following are **out of scope**:

- Denial of service against the user's own instance
- Vulnerabilities in Cloudflare's API or infrastructure (report those to [Cloudflare](https://hackerone.com/cloudflare))
- Social engineering attacks
- Issues requiring physical access to the host machine
