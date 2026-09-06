#!/bin/bash
OUT="filename_audit.txt"
: > "$OUT"
exec > >(tee -a "$OUT") 2>&1

echo "######## AUDIT: NAMA FILE REQUEST — traversal via tracesEngineVersion? — $(date -u '+%Y-%m-%dT%H:%M:%SZ') ########"

echo "=== [A] Di mana nama file request DIBANGUN? (pola etv<version>) ==="
grep -rn "etv\|getZkProof" coordinator/ --include="*.kt" 2>/dev/null | grep -viE "test|Dto" | head -15

echo -e "\n=== [B] Di mana requestsDirectory dipakai untuk MENULIS file? ==="
grep -rn "requestsDirectory" coordinator/ --include="*.kt" 2>/dev/null | grep -viE "test|conflationbacktesting/ConflationBacktestingApp" | head -15

echo -e "\n=== [C] Kode penulisan file request (full context) ==="
for f in $(grep -rln "requestsDirectory" coordinator/core/src/main/kotlin/ 2>/dev/null | head -3); do
  echo "--- $f:"
  grep -n -B5 -A15 "requestsDirectory\|fileName\|\.json" "$f" | head -50
done

echo -e "\n=== [D] Apakah tracesEngineVersion masuk ke NAMA file? ==="
grep -rn -B3 -A8 "tracesEngineVersion" coordinator/core/src/main/kotlin/ 2>/dev/null | \
  grep -iE "fileName|name|resolve|write|create" | head -10

echo -e "\n=== [E] SANITASI: adakah validasi/normalisasi path sebelum write? ==="
grep -rn "normalize\|sanitize\|isValidPath\|startsWith.*directory\|IllegalChar" \
  coordinator/core/src/main/kotlin/net/consensys/zkevm/ethereum/coordination/ 2>/dev/null | head -10
echo "(kosong = TIDAK ada sanitasi path di proofcreation)"

echo -e "\n=== [F] Bagaimana file ditulis: createDirectories parent? (menentukan traversal jalan atau tidak) ==="
grep -rn -B2 -A8 "createDirectories\|createFile\|writeString\|writeBytes\|BufferedWriter" \
  coordinator/core/src/main/kotlin/net/consensys/zkevm/ethereum/coordination/proofcreation/ 2>/dev/null | head -30

echo -e "\n=== [G] conflatedExecutionTracesFile: di mana DIBACA (arbitrary READ potential)? ==="
grep -rn -B3 -A10 "conflatedExecutionTracesFile\|conflatedTracesFile" \
  coordinator/core/src/main/kotlin/ 2>/dev/null | grep -iE "read|File|open|InputStream" | head -10

echo -e "\n######## SELESAI — tersimpan: $OUT ########"
