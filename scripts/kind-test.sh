#!/usr/bin/env bash
# Always run from trusted code. Proposed manifests are data and pass a strict apply gate.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROPOSED=${1:-"$ROOT/examples/head"}
OUT=${2:-"$ROOT/artifacts"}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
TMP=$(mktemp -d)
CLUSTER="impact-$(date +%s)-$$"
export KUBECONFIG="$TMP/kubeconfig"
export KUBE_IMPACT_CONTEXT="kind-$CLUSTER"
export KUBE_IMPACT_EXPECTED="$TMP/proposed.json"
BIN=${KUBE_IMPACT_BIN:-"$ROOT/bin/kube-impact"}
CHECKS="$OUT/kind-checks.json"
cat > "$CHECKS" <<'JSON'
[
 {"name":"kind cluster","status":"skipped","detail":"Not reached."},
 {"name":"Kubernetes API validation","status":"skipped","detail":"Not reached."},
 {"name":"Safe demo application","status":"skipped","detail":"Not reached."},
 {"name":"Workload readiness","status":"skipped","detail":"Not reached."},
 {"name":"Live integration assertions","status":"skipped","detail":"Not reached."}
]
JSON
record() {
 python3 - "$CHECKS" "$1" "$2" "$3" <<'PY'
import json,sys
p,name,status,detail=sys.argv[1:]
data=json.load(open(p))
for check in data:
    if check['name']==name: check.update(status=status,detail=detail)
with open(p,'w') as f: json.dump(data,f,indent=2)
PY
}
cleanup() {
 rc=$?
 trap - EXIT
 if [ "$rc" -ne 0 ]; then
   # Do not export manifests, container logs, env, or event messages: they may contain secrets.
   kubectl --context "$KUBE_IMPACT_CONTEXT" get nodes -o wide > "$OUT/nodes.txt" 2>/dev/null || true
   kubectl --context "$KUBE_IMPACT_CONTEXT" -n impact-demo get pods -o wide > "$OUT/pods.txt" 2>/dev/null || true
   kubectl --context "$KUBE_IMPACT_CONTEXT" -n impact-demo get events -o 'custom-columns=REASON:.reason,COUNT:.count' > "$OUT/event-reasons.txt" 2>/dev/null || true
 fi
 kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
 rm -rf "$TMP"
 exit "$rc"
}
trap cleanup EXIT
for tool in go docker kind kubectl python3; do command -v "$tool" >/dev/null || { record 'kind cluster' failed "Required tool missing: $tool"; exit 1; }; done
if [ ! -x "$BIN" ]; then (cd "$ROOT" && go build -trimpath -o "$BIN" ./cmd/kube-impact); fi
record 'kind cluster' failed 'Cluster creation or image loading did not complete.'
kind create cluster --name "$CLUSTER" --image 'kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f' --wait 180s
kubectl --context "$KUBE_IMPACT_CONTEXT" wait --for=condition=Ready nodes --all --timeout=120s
kubectl --context "$KUBE_IMPACT_CONTEXT" create namespace impact-demo >/dev/null
ARCH=$(docker info --format '{{.Architecture}}')
case "$ARCH" in aarch64|arm64) ARCH=arm64 ;; x86_64|amd64) ARCH=amd64 ;; *) exit 1 ;; esac
mkdir -p "$TMP/image"
for VERSION in 1.0.0 1.1.0; do
 (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$TMP/image/demo-$VERSION" ./cmd/demo)
 cat > "$TMP/image/Dockerfile" <<DOCKER
FROM scratch
COPY demo-$VERSION /demo
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/demo"]
DOCKER
 docker build --quiet --tag "kube-impact-demo:$VERSION" "$TMP/image" >/dev/null
 kind load docker-image "kube-impact-demo:$VERSION" --name "$CLUSTER"
done
record 'kind cluster' passed 'Disposable Kubernetes 1.35 cluster ready; locally built demo images loaded.'
record 'Kubernetes API validation' failed 'Proposed manifests failed server dry-run; details withheld to protect values.'
"$BIN" validate --manifests "$PROPOSED" --server --context "$KUBE_IMPACT_CONTEXT" --format json --output "$TMP/validation.json"
record 'Kubernetes API validation' passed 'Proposed manifests accepted by Kubernetes API dry-run. No production admission policies are installed.'
record 'Safe demo application' failed 'Proposed manifests did not pass the isolated demo safety gate or apply.'
"$BIN" render --manifests "$PROPOSED" --demo-safe --output "$KUBE_IMPACT_EXPECTED"
kubectl --context "$KUBE_IMPACT_CONTEXT" apply --validate=strict -f "$KUBE_IMPACT_EXPECTED" >/dev/null 2>&1
record 'Safe demo application' passed 'Only approved demo resource kinds and local images applied in impact-demo.'
record 'Workload readiness' failed 'Deployment rollout did not complete within the timeout.'
kubectl --context "$KUBE_IMPACT_CONTEXT" -n impact-demo rollout status deployment/payment-api --timeout=180s
record 'Workload readiness' passed 'All desired demo replicas became available in kind.'
record 'Live integration assertions' failed 'Live configuration or HTTP assertions failed.'
(cd "$ROOT" && go test -tags=integration -count=1 -timeout=120s -v ./test/integration)
record 'Live integration assertions' passed 'Verified live replicas, image, resources, Service endpoints and HTTP readiness.'
