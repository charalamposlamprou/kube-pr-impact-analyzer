#!/usr/bin/env bash
# Real-cluster negative tests: distinguish admission failure from the apply gate.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-"$ROOT/artifacts/failure-paths"}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for CASE in gate-rejection api-rejection; do
 mkdir -p "$TMP/$CASE/examples/head"
 cp "$ROOT/examples/scenarios/c-security/demo.yaml" "$TMP/$CASE/examples/head/demo.yaml"
 if [ "$CASE" = api-rejection ]; then
   # Kubernetes rejects this contradictory security context during server dry-run.
   python3 - "$TMP/$CASE/examples/head/demo.yaml" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
p.write_text(p.read_text().replace('allowPrivilegeEscalation: true','allowPrivilegeEscalation: false'))
PY
 fi
 set +e
 "$ROOT/scripts/pr-analyze.sh" "$ROOT" "$TMP/$CASE" "$OUT/$CASE"
 RESULT=$?
 set -e
 python3 - "$OUT/$CASE/report.json" "$CASE" "$RESULT" <<'PY'
import json,sys
path,case,code=sys.argv[1:]
assert code=='1',f'Expected pipeline failure, got {code}'
r=json.load(open(path));checks={c['name']:c['status'] for c in r['checks']}
assert checks['Risk policy']=='failed',checks
assert checks['Workload readiness']=='skipped',checks
assert checks['Live integration assertions']=='skipped',checks
assert any(f['rule']=='privileged' and f['severity']=='high' for f in r['findings'])
if case=='gate-rejection':
    assert checks['Kubernetes API validation']=='passed',checks
    assert checks['Safe demo application']=='failed',checks
else:
    assert checks['Kubernetes API validation']=='failed',checks
    assert checks['Safe demo application']=='skipped',checks
print(f'{case}: expected failure correctly reported; workload was not applied.')
PY
done
