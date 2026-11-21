# Policy rule reference

Each finding contains a rule ID, severity, resource identity, changed field, safe previous/new values, explanation and recommended action. All rules can be disabled or assigned `low`, `medium` or `high` through `rules.<id>`. Defaults:

| Rule | Default | Trigger |
|---|---|---|
| privileged | high | Privileged flag becomes true |
| rbac-wildcard | high | Changed Role/ClusterRole field introduces `*` |
| network-policy-deleted | high | A NetworkPolicy disappears |
| run-as-root | high | Explicit UID becomes 0, or runAsNonRoot safeguard is removed/disabled |
| limits-removed | high | Existing container CPU/memory/etc. limit disappears while container remains, when requireLimits is enabled |
| load-balancer | high | Service type becomes LoadBalancer |
| host-network | high | hostNetwork becomes true |
| host-path | high | Host filesystem path is introduced/changed |
| security-weakened | high | allowPrivilegeEscalation false restriction is lost |
| requests-increased | medium | Nonzero CPU/memory/storage reservation increases by the configured percentage or more |
| replicas-decreased | medium | Desired replica count decreases |
| readiness-removed | medium | Readiness probe disappears from a surviving container |
| image-latest | medium | Image changes to latest or an untagged image |
| hpa-max-decreased | medium | Autoscaling maximum decreases |
| pdb-weakened | medium | minAvailable decreases, maxUnavailable increases, protection is removed, or a percentage/absolute conversion needs review |
| configuration-changed | low | Contextual review note for a changed resource, including unknown kinds |

`failOn: high` fails `analyze` for high findings. `medium` also fails for high; `low` fails for any finding; `none` disables this gate. Validation failures remain independent.

`requireLimits` is a removal policy, not proof of production enforcement. It does not audit unchanged workloads for missing limits. Percentages require a valid positive previous quantity. New/zero values show absolute differences only. A field changing on a new resource can trigger security rules; deleting a workload does not trigger rules about a container still running.

No rule asserts that a rollout will fail or a pod will OOM. Root-related findings identify lost safeguards or explicit UIDs, not image-user discovery. Full permission expansion, admission defaults and runtime identity resolution require additional cluster context. Review recommendations before changing thresholds.
