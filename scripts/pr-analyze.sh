#!/usr/bin/env bash
# Invoked from the trusted base revision; head manifests are data only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=$1
HEAD=$2
OUT=$3
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
BIN=${KUBE_IMPACT_BIN:-"$ROOT/bin/kube-impact"}
set +e
"$BIN" analyze --base "$BASE" --head "$HEAD" --targets "$ROOT/config/targets.yaml" --policy "$ROOT/config/policy.yaml" --format json --output "$TMP/analysis.json"
ANALYSIS_RC=$?
set -e
if [ ! -f "$TMP/analysis.json" ]; then
 cat > "$TMP/analysis.json" <<'JSON'
{"schemaVersion":1,"changes":[],"findings":[],"checks":[{"name":"Manifest rendering / analysis","status":"failed","detail":"Rendering or analysis failed. Manifest-bearing tool diagnostics are suppressed; reproduce with the same tool versions locally."}]}
JSON
fi
KIND_RC=1
if [ "$ANALYSIS_RC" -ne 1 ]; then
 mkdir -p "$TMP/proposed"
 if "$BIN" render --manifests "$HEAD" --targets "$ROOT/config/targets.yaml" --output "$TMP/proposed/manifests.json"; then
   set +e
   "$ROOT/scripts/kind-test.sh" "$TMP/proposed" "$OUT/diagnostics"
   KIND_RC=$?
   set -e
 fi
fi
python3 - "$TMP/analysis.json" "$OUT/diagnostics/kind-checks.json" "$OUT/report.json" "$ANALYSIS_RC" "$KIND_RC" "${QUALITY_RESULT:-success}" <<'PY'
import json,pathlib,sys
source,checks,output,analysis_rc,kind_rc,quality=sys.argv[1:]
r=json.load(open(source))
if pathlib.Path(checks).exists(): r['checks'].extend(json.load(open(checks)))
else: r['checks'].append({'name':'kind integration','status':'skipped','detail':'Rendering did not complete; cluster testing was not started.'})
r['checks'].append({'name':'Risk policy','status':'failed' if analysis_rc=='3' else ('skipped' if analysis_rc=='1' else 'passed'),'detail':'Configured finding severity threshold evaluated independently from runtime readiness.'})
r['checks'].append({'name':'Go tests and static checks','status':'passed' if quality=='success' else 'failed','detail':'Separate read-only job checks the proposed source revision.'})
with open(output,'w') as f: json.dump(r,f,indent=2)
PY
if [ "$ANALYSIS_RC" -ne 0 ] || [ "$KIND_RC" -ne 0 ] || [ "${QUALITY_RESULT:-success}" != success ]; then exit 1; fi
