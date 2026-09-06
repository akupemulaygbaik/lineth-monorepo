#!/bin/bash
OUT="filename_audit2.txt"
: > "$OUT"
exec > >(tee -a "$OUT") 2>&1

echo "######## AUDIT 2: KONSTRUKSI NAMA FILE — definitive — $(date -u '+%Y-%m-%dT%H:%M:%SZ') ########"

echo "=== [1] GenericFileBasedProverClient.kt — LOGIKA WRITE LENGKAP ==="
cat coordinator/clients/prover-client/file-based-client/src/main/kotlin/lineth/coordinator/clients/prover/GenericFileBasedProverClient.kt

echo -e "\n=== [2] ProverFileNameProvider.kt — FILE LENGKAP ==="
cat coordinator/clients/prover-client/file-based-client/src/main/kotlin/lineth/coordinator/clients/prover/ProverFileNameProvider.kt

echo -e "\n=== [3] Siapa memanggil getFileName / membentuk nama? (semua pemanggil) ==="
grep -rn "getFileName\|requestFileName" coordinator/clients/ --include="*.kt" | grep -v test | head -15

echo -e "\n=== [4] Fungsi penulisan (sink) — body lengkap dari baris 92 sekitarnya ==="
sed -n '70,130p' coordinator/clients/prover-client/file-based-client/src/main/kotlin/lineth/coordinator/clients/prover/GenericFileBasedProverClient.kt

echo -e "\n=== [5] Apakah ada variable versi/string attacker di sekitar write? ==="
grep -n "version\|Version" coordinator/clients/prover-client/file-based-client/src/main/kotlin/lineth/coordinator/clients/prover/GenericFileBasedProverClient.kt

echo -e "\n=== [6] Konfirmasi isi file request — tracesEngineVersion di DALAM file (field JSON, bukan nama) ==="
grep -rn -B2 -A5 "tracesEngineVersion" coordinator/clients/prover-client/ --include="*.kt" | grep -v test | head -20

echo -e "\n######## SELESAI — tersimpan: $OUT ########"
