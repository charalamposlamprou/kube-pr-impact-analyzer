# Architecture and trust boundaries

## Data flow

`renderer.Render` reads each revision independently. A renderer has a command-runner interface; tests exercise both parsed objects and actual Helm/Kustomize executables. Configured targets define release/namespace/value-file context and prevent accidentally treating fixtures or unrelated repository YAML as deployable resources.

`diff.Fields` creates a canonical structural view. CPU/memory quantities use Kubernetes Quantity parsing and exact decimal normalization. Containers, environment entries, volumes and mounts use stable identities. Known set fields normalize ordering; equivalent split RBAC permission rules are merged by scope. Init-container order and env order when values use variable expansion are preserved. Generic CRD ordering is retained. Resource matching deliberately excludes API version from identity, so an API migration appears as a modification instead of unrelated add/delete operations.

Comparison happens before redaction. Equal hidden values remain unchanged; different hidden values generate a visible `[REDACTED] → [REDACTED]` field entry labeled `changed (redacted)` without exposing plaintext or a brute-forceable hash. The analyzer gives the policy engine complete proposed field presence so partially edited probes and deleted containers are not misclassified.

The policy engine classifies confirmed changes and attaches qualified runtime explanations. Static validation uses registered Kubernetes built-in schemas with strict decoding, quantity checks and selected workload/HPA invariants. Unknown schemas are explicitly identified as generic checks. Reports are deterministic and retain exact paths alongside human-readable resource labels.

## Untrusted analysis

`pull_request` has only `contents: read`, no repository secrets, no persisted checkout credentials and no cache shared with the privileged publisher. Proposed-source unit tests run in a separate job. The impact job builds analyzer/policy/scripts/demo source from the trusted base SHA and reads head manifests as data. Helm and Kustomize are subprocesses with a small environment and bounded output. Subprocess diagnostics are suppressed because they can contain values. Renderer inputs and outputs are capped at 16 MiB, with a context timeout.

Every configured target is rendered, including after deletions, rather than deciding impact from text hunks. Policy/target changes take effect after merging. This avoids a PR disabling its own gate. Contributors can still modify the PR workflow: the report is informational and must not be treated as an unforgeable attestation.

## Ephemeral Kubernetes

The harness uses a unique kind cluster name and private kubeconfig; it never uses the user's current context. The node image is pinned by digest. API dry-run precedes the apply gate. The gate only permits restricted Deployment, ConfigMap, ClusterIP Service and HPA resources in `impact-demo`, approved locally built images, fixed non-root UID, dropped capabilities and bounded demo scale/limits. Arbitrary PR RBAC, privileged workloads, host mounts, ingress and networking changes are not applied.

A trap collects limited diagnostics and removes the cluster even after failures. The ephemeral kubeconfig and unredacted temporary manifests are deleted. Readiness checks verify rollout, desired available replicas, image/resource settings, ready Service endpoints and HTTP health. Successful kind tests are not claims about production clusters. HPA behavior and NetworkPolicy enforcement are explicitly outside the demo test claims.

## Privileged comment publisher

`workflow_run` executes the default-branch publisher. The GitHub token exists only in its final invocation. The publisher uses go-github v93 and:

1. Fetches run metadata from GitHub; accepts only completed `pull_request` runs at the expected workflow path and repository.
2. Resolves the PR from API associations (with commit association fallback for fork runs).
3. Checks open status, base repository, head SHA and head repository ID; ignores stale/unrelated runs.
4. Fetches one named artifact from that exact run, capped at 2 MiB compressed and expanded.
5. Reads a ZIP in memory, accepts exactly one regular `report.json`, rejects unknown JSON fields, invalid enums, oversized collections, malformed UTF-8 and trailing data. Nothing is extracted to disk or executed.
6. Escapes report content for Markdown and inserts a run URL constructed from verified repository/run identifiers.
7. Rechecks the PR head immediately before publishing. Paginated comment lookup recognizes only the GitHub Actions bot plus the exact invisible marker. Identical content is a no-op; changed content is an update.

The workflow serializes publishers by source repository and branch to avoid simultaneous comment creation without suppressing unrelated PR reports. GitHub concurrency queues can supersede pending older runs for the same source branch; the latest completed analysis is the desired report. The PR-head recheck reduces, but cannot eliminate, an API-level commit/comment race; the next completed run corrects the comment. User comments containing the marker are never edited.

Missing or malformed artifacts produce a failure summary, not a success report. API/network failures exit nonzero, preserving any previous comment; GitHub logs show a sanitized error. The trusted workflow conclusion is appended separately from contributor-supplied report data.

## Extension points

Add a target mode through the renderer interface; introduce a policy rule with stable ID and table-driven tests; add known-list semantics only when the Kubernetes API defines the list as unordered. Keep the report schema versioned. Extend the demo safety allowlist deliberately, with negative tests. General production deployment is not a purpose of this tool.

## Upstream references

- [GitHub workflow event and workflow_run security guidance](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [GitHub secure workflow use](https://docs.github.com/en/actions/reference/security/secure-use)
- [kind node releases and image digests](https://github.com/kubernetes-sigs/kind/releases)
- [Maintained go-github client releases](https://github.com/google/go-github/releases)
