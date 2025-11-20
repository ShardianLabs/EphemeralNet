# Usage scenarios

This playbook captures real-world workflows that operators keep asking for. Each scenario references the exact commands, expected responses, and the code paths that implement them so you can replicate the behaviour on eph.shardian.com or in runbooks.

## 1. Local secure drop (single workstation)

Goal: spin up a daemon on a developer laptop, store a file with a 10-minute TTL, and retrieve it from a second shell.

```powershell
# Terminal A – start the daemon in the foreground
$env:EPH_STORAGE = "$env:TEMP\eph"
mkdir $env:EPH_STORAGE -Force | Out-Null
.\eph.exe --storage-dir $env:EPH_STORAGE --persistent serve
```

```powershell
# Terminal B – upload and fetch using localhost control plane
Set-Content -Path .\handoff.txt -Value "debug bundle $(Get-Date -Format o)"
$manifest = .\eph.exe store .\handoff.txt --ttl 600 |
    Select-String 'Manifest:' | ForEach-Object { ($_ -split ':',2)[1].Trim() }

# Inspect daemon defaults and confirm TTL bounds
.\eph.exe defaults | Select-String 'TTL'

# Fetch back into a staging directory
mkdir .\downloads -Force | Out-Null
.\eph.exe fetch $manifest --out .\downloads
```

Expected output excerpt:

```
STATUS:OK
CODE:OK_STORE
MANIFEST:eph://AQAAAA...
SIZE:44
TTL:598
```

Relevant code: `src/main.cpp` (CLI flow), `src/daemon/ControlServer.cpp::handle_store`, `src/storage/ChunkStore.cpp`.

## 2. Remote relay-backed share (VPS bootstrap)

Goal: push a payload to a remote daemon over the public bootstrap endpoint documented in `ops/bootstrap/README.md` and force relay hints into the manifest.

```bash
CONTROL_HOST=bootstrap1.shardian.com
CONTROL_PORT=47777
CONTROL_TOKEN=$(cat ~/.config/eph/token)
export CONTROL_HOST CONTROL_PORT CONTROL_TOKEN

eph --control-host "$CONTROL_HOST" \
    --control-port "$CONTROL_PORT" \
    --control-token "$CONTROL_TOKEN" \
    --advertise-control $CONTROL_HOST:$CONTROL_PORT \
    defaults | sed -n '1,15p'

echo "Incident report $(date -Is)" > report.txt
MANIFEST=$(eph --control-host "$CONTROL_HOST" \
                --control-port "$CONTROL_PORT" \
                --control-token "$CONTROL_TOKEN" \
                store report.txt --ttl 1800 |
            awk -F ':' '/MANIFEST/ {print $2}' | xargs)

eph fetch "$MANIFEST" --direct-only --control-host "$CONTROL_HOST" --control-port "$CONTROL_PORT" \
    --control-token "$CONTROL_TOKEN" --out ./downloads/
```

Notes:
- The `--advertise-control` flag forces manual discovery hints so recipients behind strict firewalls can bootstrap via control-plane relays.
- `--direct-only` proves the manifest contains routable hints before falling back to the DHT.

Relevant code: `src/network/AdvertiseDiscovery.cpp`, `src/protocol/Manifest.cpp`, `tests/advertise_discovery.cpp`.

## 3. Automated log escrow (scheduled task)

Goal: add a nightly job that backs up sensitive logs for one hour and emails the manifest to responders.

```powershell
$job = @'
$manifestLine = .\eph.exe --config C:\Ops\eph.yaml store C:\Logs\triage.zip --ttl 3600 |
    Select-String 'MANIFEST'
$manifest = ($manifestLine -split ':',2)[1].Trim()
$body = @"
EphemeralNet manifest for nightly triage backup:
$manifest
This expires in one hour.
"@
Send-MailMessage -To soc@example.net -From eph@example.net -Subject "Nightly triage manifest" -Body $body
'@
Set-Content -Path C:\Ops\nightly-escrow.ps1 -Value $job
```

Schedule with Windows Task Scheduler (or cron on Linux) to run under an account that already has the control token and storage directory configured. Test locally with `powershell -File C:\Ops\nightly-escrow.ps1`.

Relevant code: `src/daemon/ControlServer.cpp::handle_store`, `docs/handbook/storage-and-ttl.md` (TTL behaviour).

## 4. TTL compliance audit (multi-node mesh)

Operators often need proof that replicas are vanishing on time. Combine `status`, `list`, and `diagnostics`:

```bash
# Query peer stats from three nodes
for host in node-a node-b node-c; do
  eph --control-host "$host" --control-token $(cat ~/.config/eph/token) status \
      | awk -v h=$host '/PEERS|CHUNKS|ADVERTISED/ {print h " " $0}'
done

# Capture local TTL audit snapshot
mkdir -p audits
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
eph list > audits/ttl-$timestamp.txt

# Export diagnostics for relay/NAT evidence
for host in node-a node-b; do
  eph --control-host "$host" --control-token $(cat ~/.config/eph/token) diagnostics > "audits/diag-$host-$timestamp.json"
done
```

Correlate the resulting files with structured logs from `docs/observability/` to show auditors the full lifecycle (manifest TTL, wipe confirmation, DHT withdrawal).

Relevant code: `src/daemon/ControlServer.cpp::handle_list`, `src/core/Node.cpp::tick`, `tests/ttl_audit.cpp`.

## 5. Manifest-only disaster recovery

When you inherit an `eph://` URI but do not trust the local daemon, restrict the CLI to discovery hints:

```bash
MANIFEST="eph://AQAA..."
mkdir -p recovered
# Attempt transport hints only (QUIC/HTTP variants will fall back gracefully)
eph fetch "$MANIFEST" --transport-only --out recovered/

# If all transport attempts fail, use control fallback with explicit PoW token
NONCE=$(python3 scripts/pow_metrics_proxy.py solve --manifest "$MANIFEST")
eph fetch "$MANIFEST" --control-fallback --bootstrap-token "$NONCE" --out recovered/
```

This demonstrates how manifests protect custodians: discovery hints include PoW requirements and fallback URIs, so even air-gapped sites can recover data long enough to rotate credentials.

Relevant code: `src/protocol/Manifest.cpp`, `src/bootstrap/TokenChallenge.cpp`, `tests/fetch_retry.cpp`.

---
