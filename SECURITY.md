# Security policy

Please report vulnerabilities privately through GitHub's **Report a vulnerability** feature when enabled, or contact the maintainer before posting reproduction details containing credentials. Never include real Kubernetes Secret values in issues or pull requests.

Supported development line: `main` and the latest release. Security-sensitive changes need tests for redaction, artifact provenance and isolation. Dependency updates are monitored by Dependabot.

The analyzer is not a hostile-code sandbox, a production deployment system or a complete Kubernetes security audit. Run untrusted templates on disposable, credential-free infrastructure. Do not reuse self-hosted production runners for arbitrary fork code. Never change the comment workflow to execute PR artifacts or check out a PR revision with write-capable credentials.

`render` writes unredacted resources to a private file intentionally. Other report paths redact Secret payloads, ConfigMap data, annotations, literal env values, command arguments and HTTP header values. Opaque CRD values with unknown semantics cannot be comprehensively classified; keep credentials in Secret resources/references. Diagnostics intentionally omit raw tool errors, container logs and event messages.

See [docs/architecture.md](docs/architecture.md) for precise guarantees and limitations.
