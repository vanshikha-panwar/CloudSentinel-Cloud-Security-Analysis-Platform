#!/usr/bin/env bash
# Smoke test a running CloudSentinel API (local, Docker or Kubernetes).
#   bash scripts/smoke_test.sh [BASE_URL]      default: http://127.0.0.1:8000
# Uses only curl and Python's standard library. Exits non-zero on any failure.
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"
DATA="$(cd "$(dirname "$0")/.." && pwd)/sample_data/demo_iam_data.json"
# First interpreter that actually runs (on Windows, "python3" may be a Store placeholder)
PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PY="$candidate"; break
  fi
done
[ -n "$PY" ] || { echo "FAIL: Python 3 is required"; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "-> GET /health"
curl -fsS "$BASE_URL/health" | "$PY" -c 'import json,sys; d=json.load(sys.stdin); assert d == {"status": "ok"}, d'

echo "-> GET /rules"
curl -fsS "$BASE_URL/rules" | "$PY" -c 'import json,sys; d=json.load(sys.stdin); assert d["total"] == 12, d["total"]'

echo "-> POST /scans (demo dataset)"
curl -fsS -D "$TMP/headers" -o "$TMP/scan.json" -X POST "$BASE_URL/scans" \
  -H "Content-Type: application/json" --data @"$DATA"
"$PY" - "$TMP/scan.json" <<'EOF'
import json, sys
summary = json.load(open(sys.argv[1]))["summary"]
expected = {"total_findings": 23, "critical": 4, "high": 8, "medium": 7, "low": 4}
assert summary == expected, summary
EOF
SCAN_ID="$(grep -i '^x-scan-id:' "$TMP/headers" | tr -d '\r' | awk '{print $2}' || true)"
if [ -z "$SCAN_ID" ]; then
  echo "FAIL: no X-Scan-Id header (scan history could not be written; check the data volume)"
  exit 1
fi

echo "-> GET /scans/$SCAN_ID"
curl -fsS "$BASE_URL/scans/$SCAN_ID" | "$PY" -c '
import json, sys
d = json.load(sys.stdin)
assert d["scan_id"] == sys.argv[1] and len(d["findings"]) == 23, d.get("scan_id")' "$SCAN_ID"

echo "-> POST /findings/{finding_id}/explain"
FINDING_ID="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["findings"][0]["finding_id"])' "$TMP/scan.json")"
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/findings/$FINDING_ID/explain" \
  -H "Content-Type: application/json" --data @"$DATA")"
# 503 = AI explanations disabled (the default); 200 = an LLM provider is configured
case "$CODE" in
  200|503) echo "   HTTP $CODE" ;;
  *) echo "FAIL: unexpected HTTP $CODE from explain endpoint"; exit 1 ;;
esac

echo "Smoke test passed (scan_id=$SCAN_ID)"
