# Verification record

The implementation was exercised locally on macOS arm64 with Docker Desktop, a downloaded Go 1.26 toolchain, Helm 4.1.1, Kustomize 5.8.1, kind 0.29.0 and Kubernetes 1.35.0. CI pins kind 0.31.0 and the same digest-pinned Kubernetes node image.

Executed successfully during implementation:

- `make check`: binary build, race-enabled Go suite, formatting, `go vet`, Staticcheck and Actionlint.
- Real Helm base/head values rendering and Kustomize patch rendering tests.
- All six scenario assertions, equivalent CPU/memory quantities, unchanged resources, added/deleted identities, namespace and CRD scope, invalid/duplicate YAML, redaction and comment idempotency.
- `scripts/kind-test.sh examples/head artifacts/local-kind`: actual API dry-run, application, three-replica rollout, live image/resource assertions, ready Service endpoints and HTTP health; cluster cleanup completed.
- CLI resource-change Markdown/JSON examples; inspected expected +100% CPU and memory values and no differences for unchanged input.
- `docker build --tag kube-impact:local .`.

Raw rendered manifests are not included in verification artifacts. Local reports and limited kind diagnostics live under the ignored `artifacts/` directory. The public example report is generated from non-sensitive fixtures.

GitHub-hosted workflow and bot verification is recorded below after publication. No statement here implies production capacity, CNI policy enforcement, cloud networking, HPA scaling behavior or availability was tested.

## GitHub-hosted evidence

- [Hosted CI](https://github.com/charalamposlamprou/kube-pr-impact-analyzer/actions/runs/44878372055) passed build, race tests, static analysis, workflow lint, real kind integration and Docker packaging.
- [Demo PR #9](https://github.com/charalamposlamprou/kube-pr-impact-analyzer/pull/9) changes the proposed deployment's resources.
- [Initial PR analysis](https://github.com/charalamposlamprou/kube-pr-impact-analyzer/actions/runs/44878446393) passed both quality and impact jobs, including the increased-resource kind deployment.
- [Bot report](https://github.com/charalamposlamprou/kube-pr-impact-analyzer/pull/9#issuecomment-7059066918) was created by `github-actions[bot]` through the separate publisher, with four +100% changes and all checks passed.
- A second local kind run with `examples/scenarios/a-resources` passed API validation, rollout and live configuration/HTTP assertions with the increased CPU/memory settings.

- [Updated PR analysis](https://github.com/charalamposlamprou/kube-pr-impact-analyzer/actions/runs/44878946276) and [publisher](https://github.com/charalamposlamprou/kube-pr-impact-analyzer/actions/runs/44879279624) passed after a second push. API inspection confirmed exactly one bot comment, unchanged ID `7059066918`, updated to `750m` and `+200.0%` CPU with the new run link.
- `make kind-failure-tests` passed two real-cluster negative cases: a valid privileged proposal passed API dry-run but failed the apply gate; a contradictory privileged/allowPrivilegeEscalation configuration failed API validation. Both reported high policy risk and skipped application/readiness as appropriate, and both clusters were removed. These checks are included in hosted CI.
- [Implementation CI after ordering safeguards](https://github.com/charalamposlamprou/kube-pr-impact-analyzer/actions/runs/44879156428) passed.
