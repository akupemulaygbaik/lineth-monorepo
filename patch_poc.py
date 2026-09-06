#!/usr/bin/env python3
"""Inject health-check fix into poc.sh (idempotent, with backup + syntax check)."""
import re, shutil, subprocess, sys, os

SRC = "poc.sh"
BAK = "poc.sh.bak"

if not os.path.exists(SRC):
    print(f"[-] {SRC} not found in current directory"); sys.exit(1)

with open(SRC) as f:
    content = f.read()

shutil.copy2(SRC, BAK)
print(f"[+] backup: {BAK}")
changes = 0

# ---------------------------------------------------------------------------
# PATCH 1: replace the unhealthy-exit block with informational logic
# Matches both variants:
#   (a) exit-on-unhealthy (the "fixed" version)
#   (b) bare unhealthy check without exit
# ---------------------------------------------------------------------------
NEW_BLOCK = (
    'if echo "$STATUS" | grep -q "unhealthy"; then\n'
    '  echo "[*] docker healthcheck reports unhealthy (separate probe, not the JSON-RPC API);"\n'
    '  echo "    relying on RPC reachability + batch production as authoritative signals."\n'
    'fi\n'
)

pat_exit = re.compile(
    r'if echo "\$STATUS" \| grep -q "unhealthy"; then\n'
    r'(?:[ \t]*echo "\[-\][^\n]*\n)+'      # one or more error echoes
    r'[ \t]*exit 1\n'
    r'fi\n'
)
pat_bare = re.compile(
    r'if echo "\$STATUS" \| grep -q "unhealthy"; then\n'
    r'(?:[ \t]*echo "[^\n]*\n)+'            # any echoes, no exit
    r'fi\n'
)

if "relying on RPC reachability + batch production" in content:
    print("[=] PATCH 1: already applied (skip)")
elif pat_exit.search(content):
    content = pat_exit.sub(NEW_BLOCK, content, count=1)
    print("[+] PATCH 1: replaced unhealthy-exit block -> informational")
    changes += 1
elif pat_bare.search(content):
    content = pat_bare.sub(NEW_BLOCK, content, count=1)
    print("[+] PATCH 1: replaced bare unhealthy block -> informational")
    changes += 1
else:
    print("[-] PATCH 1: unhealthy-check block not found - manual review needed")

# ---------------------------------------------------------------------------
# PATCH 2: inject batch-liveness check after the RPC-reachable echo
# ---------------------------------------------------------------------------
BATCH_CHECK = '''
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
'''

ANCHOR = 'echo "[+] RPC reachable: $RPC"'
if "batch production alive" in content or "BATCHES_3M" in content:
    print("[=] PATCH 2: already applied (skip)")
elif ANCHOR in content:
    content = content.replace(ANCHOR, ANCHOR + "\n" + BATCH_CHECK, 1)
    print("[+] PATCH 2: injected batch-liveness check after RPC probe")
    changes += 1
else:
    print("[-] PATCH 2: RPC-reachable anchor not found - manual review needed")

# ---------------------------------------------------------------------------
# write + verify
# ---------------------------------------------------------------------------
with open(SRC, "w") as f:
    f.write(content)

if changes == 0:
    print("[=] nothing changed (all patches present or anchors missing)")
else:
    print(f"[+] {changes} patch(es) written to {SRC}")

# bash syntax check (never leaves you with a broken script)
r = subprocess.run(["bash", "-n", SRC], capture_output=True, text=True)
if r.returncode == 0:
    print("[+] syntax check: OK (bash -n)")
else:
    print("[-] syntax check FAILED - restoring backup!")
    shutil.copy2(BAK, SRC)
    print(r.stderr[:500])
    sys.exit(1)

print("")
print("Verifikasi manual patch points:")
print("  grep -n 'authoritative signals' poc.sh    # PATCH 1 (health)")
print("  grep -n 'BATCHES_3M' poc.sh               # PATCH 2 (liveness)")
