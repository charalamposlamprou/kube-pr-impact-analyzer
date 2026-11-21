<!-- kube-impact:report:v1 -->
### Kubernetes Change Impact Report

**0 added · 1 modified · 0 deleted** · **Risk level: medium**

**Validation and integration checks**

| Check | Result | Detail |
|---|---|---|
| static: /ConfigMap/impact-demo/payment-config | passed | built-in types and local invariants checked; not full Kubernetes admission validation |
| static: /Service/impact-demo/payment-api | passed | built-in types and local invariants checked; not full Kubernetes admission validation |
| static: apps/Deployment/impact-demo/payment-api | passed | built-in types and local invariants checked; not full Kubernetes admission validation |
| static: autoscaling/HorizontalPodAutoscaler/impact-demo/payment-api | passed | built-in types and local invariants checked; not full Kubernetes admission validation |

Static checks, API dry-run, application and readiness are separate results. kind does not validate production capacity, policies, networking or availability.

<details>
<summary>modified: Deployment / impact-demo / payment-api</summary>

**API group:** apps

| Configuration | Before | After | Change |
|---|---|---|---|
| CPU Limit · spec.template.spec.containers&#91;&#34;api&#34;&#93; | 1000m | 2000m | +100.0% |
| Memory Limit · spec.template.spec.containers&#91;&#34;api&#34;&#93; | 512Mi | 1Gi | +100.0% |
| CPU Request · spec.template.spec.containers&#91;&#34;api&#34;&#93; | 250m | 500m | +100.0% |
| Memory Request · spec.template.spec.containers&#91;&#34;api&#34;&#93; | 256Mi | 512Mi | +100.0% |

**Operational and security impact**

- **medium** (spec.template.spec.containers&#91;&#34;api&#34;&#93;.resources.requests.cpu): Resource reservation increased by 100.0%. Scheduling could be affected by available node capacity; this is not evidence of a scheduling failure. **Recommended action:** Check allocatable capacity, quotas and rollout surge requirements.
- **medium** (spec.template.spec.containers&#91;&#34;api&#34;&#93;.resources.requests.memory): Resource reservation increased by 100.0%. Scheduling could be affected by available node capacity; this is not evidence of a scheduling failure. **Recommended action:** Check allocatable capacity, quotas and rollout surge requirements.
- **low** (resource): Workload configuration changed. Pod-template changes can trigger replacement or rollout according to the workload strategy. **Recommended action:** Review the rendered changes and validate against the target cluster&#39;s policies.

</details>

Confirmed changes are shown above; operational consequences are possibilities, not proof of an outage. Secret data, literal environment values, ConfigMap values, command arguments and annotations are redacted.
