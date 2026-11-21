# Contributing

Open an issue describing the Kubernetes behavior and a minimal, non-sensitive rendered example. Changes should preserve deterministic output and credential-free local execution.

Run `make check` before opening a PR. Rendering tests use actual Helm and Kustomize; CI requires both. Run `make kind-test` for changes to validation, demo safety or integration code. Add table-driven tests for semantic rules, especially false-positive cases. Use `gofmt`, wrap actionable errors without including input values, and use structured `slog` logs.

Keep parsing/rendering, canonical diffing, policy, validation and publication separate. Do not add network-dependent AI services or production-cluster access. Follow the existing least-privilege workflow split. Document changes to the versioned JSON report contract and policy rule IDs.

By contributing, you agree that your contributions are licensed under the MIT license.
