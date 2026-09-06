#!/bin/bash
OUT="exposure_audit.txt"
: > "$OUT"
exec > >(tee -a "$OUT") 2>&1

echo "######## PRODUCTION EXPOSURE AUDIT — $(date -u '+%Y-%m-%dT%H:%M:%SZ') ########"
echo ""

echo "=== [1a] PORT 9546 EXPOSURE (yml/yaml/toml, non-test) ==="
grep -rn "9546" . --include="*.yml" --include="*.yaml" --include="*.toml" 2>/dev/null | \
  grep -viE "test|e2e/|\.json" | head -20

echo -e "\n=== [1b] AUTH OPTIONS DI API COORDINATOR ==="
echo "--- config [api] section ---"
sed -n '/^\[api\]/,/^\[/p' docker/config/coordinator/coordinator-config-v2.toml
echo "--- grep auth/jwt/apikey/bearer di source ---"
grep -rniE "auth|jwt|apikey|bearer" coordinator/app/src/main/kotlin/ 2>/dev/null | head -15

echo -e "\n=== [1c] SELF-GATING: backtesting-directory default ==="
echo "--- di source code ---"
grep -rn "backtestingDirectory\|backtesting-directory" coordinator/app/src/main/kotlin/ 2>/dev/null | head -10
echo "--- di config dev ---"
grep -rn "backtesting" docker/config/coordinator/coordinator-config-v2.toml
echo "--- semua compose: siapa yang set backtesting-directory ---"
grep -rn "backtesting" docker/compose*.yml 2>/dev/null | head -10

echo -e "\n=== [1d] DEPLOYMENT MANIFESTS (k8s/helm/terraform) ==="
find . -type d \( -name "k8s" -o -name "kubernetes" -o -name "helm" -o -name "deploy" -o -name "charts" \) 2>/dev/null | grep -v node_modules | head
echo "(kosong = tidak ada manifest production di repo)"

echo -e "\n=== [1e] IMAGE & VERSION ==="
echo "Image: $(docker inspect coordinator --format '{{.Config.Image}}' 2>/dev/null)"
echo "Git log:"
git log --oneline -5 2>/dev/null

echo -e "\n=== [BONUS 1f] konfirmasi gating dari source: apa yang terjadi kalau backtestingDirectory null? ==="
grep -rn -A5 "backtestingDirectory" coordinator/app/src/main/kotlin/lineth/coordinator/app/conflationbacktesting/ 2>/dev/null | head -30

echo -e "\n######## SELESAI — tersimpan: $OUT ########"
