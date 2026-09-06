#!/bin/bash
OUT="l1_reach_audit.txt"
: > "$OUT"
exec > >(tee -a "$OUT") 2>&1
BT=coordinator/app/src/main/kotlin/lineth/coordinator/app/conflationbacktesting

echo "######## AUDIT: BISAkah POISON BACKTESTING SAMPAI L1 — $(date -u '+%Y-%m-%dT%H:%M:%SZ') ########"

echo "=== [A] JALUR A: komponen apa yang di-instantiate ConflationBacktestingApp? ==="
grep -nE "BlobSubmission|AggregationFinalization|MessageAnchoring|L1DependentApp|BlobSubmitter|submitBlob|finalizeBlocks|signer|Web3Signer|l1Submission" \
  "$BT/ConflationBacktestingApp.kt" | head -20
echo "(kosong pada submission-related = job TIDAK punya komponen L1 submission)"

echo -e "\n=== [B] PEMBANDING: komponen LIVE pipeline (L1DependentApp) ==="
grep -nE "BlobSubmissionCoordinator|AggregationFinalizationCoordinator|MessageAnchoring|BlobSubmitter|submitBlobs|finalizeBlocks" \
  coordinator/app/src/main/kotlin/lineth/coordinator/app/L1DependentApp.kt 2>/dev/null | head -15
ls coordinator/app/src/main/kotlin/lineth/coordinator/app/ | head -15

echo -e "\n=== [C] Apa saja service yang ditarik masuk oleh backtesting job (semua file di modul) ==="
ls "$BT/"
grep -nE "^import|class .*Service|class .*Coordinator" "$BT/ConflationBacktestingService.kt" | head -20

echo -e "\n=== [D] JALUR B: getUpdatedProverConfig — mana yang di-remap, mana yang tidak ==="
grep -n -A40 "fun getUpdatedProverConfig" "$BT/ConflationBacktestingApp.kt" | head -50
echo "--> cari: apakah execution/compression/aggregation di-remap TAPI invalidity TIDAK?"

echo -e "\n=== [E] Apakah backtesting MENGGUNAKAN invalidity prover? ==="
grep -rn "invalidity" "$BT/" | head -10
grep -rn "InvalidityProof\|invalidity" coordinator/app/src/main/kotlin/lineth/coordinator/core/src/main/kotlin/net/consensys/zkevm/ethereum/coordination/blob/ 2>/dev/null | head -5
echo "--> siapa yang menulis request ke invalidity/requests?"
grep -rn "invalidity" coordinator/core/src/main/kotlin/net/consensys/zkevm/ 2>/dev/null | grep -iE "request|write" | head -10

echo -e "\n=== [F] JALUR C: apakah backtesting menulis ke DB yang sama dengan live? ==="
grep -rn "DatabaseConfig\|persistence\|dataSource\|Postgres\|batch.*repository\|BlobsRepository\|BatchesRepository" \
  "$BT/" | head -10
echo "(kosong = backtesting tidak menyentuh DB → jalur C tertutup)"

echo -e "\n=== [G] RUNTIME: struktur direktori aktual (shared vs per-job) ==="
find /workspaces/lineth-monorepo/tmp/local -type d 2>/dev/null | sed 's|/workspaces/lineth-monorepo/tmp/local|<DATA>|' | head -25
echo "--> isi invalidity (shared) vs conflation-backtesting (per-job):"
ls -la /workspaces/lineth-monorepo/tmp/local/prover/v3/invalidity/requests/ 2>/dev/null | head -10
ls /workspaces/lineth-monorepo/tmp/local/conflation-backtesting/ 2>/dev/null | head -10

echo -e "\n=== [H] RUNTIME: apakah ada file yang ditulis job backtesting ke direktori LIVE? ==="
find /workspaces/lineth-monorepo/tmp/local/prover -type f -newer /tmp -mmin -180 2>/dev/null | head -10
echo "(file baru di prover/v3/ dari 3 jam terakhir = job backtesting menulis ke live dir)"

echo -e "\n=== [I] E2E TEST backtesting — apa perilaku yang di-assert oleh test resmi? ==="
ls e2e/src/ 2>/dev/null | grep -iE "backtest|reconflat|prover" | head -5
grep -rn "createProverRequests\|backtesting" e2e/src/*.ts 2>/dev/null | head -10
echo "--> test resmi menunjukkan perilaku yang EXPECTED (termasuk apakah L1 disentuh)"

echo -e "\n=== [J] Signer di backtesting job? (tanpa signer = tidak BISA kirim tx L1) ==="
grep -n "signer\|Signer" "$BT/ConflationBacktestingApp.kt" | head -10
echo "(backtesting job TANPA signer wiring = tidak mungkin submit tx L1 apa pun)"

echo -e "\n######## SELESAI — tersimpan: $OUT ########"
