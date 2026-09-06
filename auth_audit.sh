#!/bin/bash
OUT="auth_audit.txt"
: > "$OUT"
exec > >(tee -a "$OUT") 2>&1

echo "######## AUTH & EXPOSURE AUDIT (FINAL) — $(date -u '+%Y-%m-%dT%H:%M:%SZ') ########"

echo "=== [A] ROUTER: apakah ada validasi User / auth handler di layer JSON-RPC? ==="
grep -rn "JsonRpcRequestRouter\|requireAuth\|userIsAuthorised\|authenticate\|AuthorisationHandler" \
  coordinator/json-rpc/ 2>/dev/null | head -15
echo "(kosong = tidak ada enforcement di router)"

echo -e "\n=== [B] HANDLER LENGKAP: ConflationCreateProverRequestHandler ==="
cat coordinator/app/src/main/kotlin/lineth/coordinator/api/requesthandlers/ConflationCreateProverRequestHandler.kt

echo -e "\n=== [C] ROUTER SETUP: bagaimana JSON-RPC server memasang route/handler ==="
grep -rn "Router\|route(\|\.handler(" coordinator/app/src/main/kotlin/lineth/coordinator/api/ 2>/dev/null | head -10

echo -e "\n=== [D] User parameter: dipakai atau dead import? (semua handler backtesting) ==="
for f in ConflationCreateProverRequestHandler ConflationGetJobStatusRequestHandler \
         ConflationStopJobRequestHandler ConflationTargetCheckpointResumeRequestHandler; do
  echo "--- $f:"
  grep -n "User" "coordinator/app/src/main/kotlin/lineth/coordinator/api/requesthandlers/$f.kt" 2>/dev/null | head -5
done

echo -e "\n=== [E] Di mana JsonRpcServer dibuat & handler didaftarkan ==="
grep -rn "JsonRpcMessageProcessor\|JsonRpcServer\|verticle" coordinator/app/src/main/kotlin/lineth/coordinator/api/ 2>/dev/null | grep -viE "^Binary" | head -10

echo -e "\n=== [F] Vert.x auth: apakah authProvider/authenticationHandler pernah dipasang ==="
grep -rn "authProvider\|authenticationHandler\|JWTAuth\|BasicAuth\|redirectHandler" \
  coordinator/app/src/main/kotlin/ 2>/dev/null | head -10
echo "(kosong = framework di-import tapi TIDAK PERNAH dipasang = dead import)"

echo -e "\n=== [G] Interface handler: signature User di interface/abstraksi ==="
grep -rn "User" coordinator/json-rpc/src/main/kotlin/net/consensys/linea/jsonrpc/*.kt 2>/dev/null | head -10
find coordinator -name "*.kt" -path "*jsonrpc*" | head -10

echo -e "\n=== [H] Dari mana io.vertx.ext.auth.User masuk (dependency?) ==="
grep -rn "io.vertx.ext.auth" coordinator/app/build.gradle* coordinator/json-rpc/build.gradle* 2>/dev/null | head -5
grep -rn "vertx-auth" coordinator/*/build.gradle* 2>/dev/null | head -5

echo -e "\n######## SELESAI — tersimpan: $OUT ########"

echo ""
echo "=== OSINT CHECKLIST (browser, bukan terminal) ==="
echo "1. github.com/Consensys/linea-monorepo -> cari:"
echo "   - 'ConflationCreateProverRequestHandler'  (attack surface di prod?)"
echo "   - 'backtesting-directory'                  (fitur aktif di prod?)"
echo "   - 'conflation_createProverRequests'       (method RPC di prod?)"
echo "2. Immunefi -> cari 'Linea' -> baca in-scope assets"
echo "3. Shodan search UI (passive): org:Consensys port:9546"
