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
