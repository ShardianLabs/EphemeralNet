# Welcome to EphemeralNet

This guide stitches together the narrative that bridges the README-driven quick start with the hands-on workflows operators run in production. Use it as the on-ramp before diving into the deeper reference guides that live elsewhere under `docs/`.

## Platform snapshot

- **What it is**: A C++20 peer-to-peer filesystem where every chunk, manifest, and DHT record expires according to its declared TTL.
- **Execution model**: A stateless CLI (`eph`) that shells commands to a long-lived daemon over a line-oriented control socket.
- **Golden path**: Operators store bytes with `eph store`, share the manifest URI (`eph://…`), and fetch via transport hints or through the daemon/DHT fallback before TTL expiration.
- **Security posture**: ChaCha20 + HMAC-SHA256 transport, multi-surface proof-of-work (handshake, announce, store), secure wiping, and relay-aware networking.
- **Observability hooks**: Structured logs, CLI snapshots (`status`, `defaults`, `list`), and a Prometheus/Grafana toolkit dedicated to proof-of-work and announce pressure.

Keep this perspective in mind while following the scenarios below—each shows how those primitives combine to solve real operational jobs.

## Golden path scenarios

### 1. Local secure drop (single workstation)

Spin up a daemon locally, store a sensitive file with a tight TTL, and fetch it back without leaving the host.

```powershell
# Terminal A – keep the daemon in the foreground for easy observation
$env:EPH_STORAGE = "$env:TEMP\eph"
mkdir $env:EPH_STORAGE -Force | Out-Null
./eph.exe --storage-dir $env:EPH_STORAGE --persistent serve
```

```powershell
# Terminal B – upload and fetch through localhost control plane
Set-Content -Path .\handoff.txt -Value "debug bundle $(Get-Date -Format o)"
$manifest = ./eph.exe store .\handoff.txt --ttl 600 |
    Select-String 'Manifest:' | ForEach-Object { ($_ -split ':',2)[1].Trim() }

./eph.exe defaults | Select-String 'TTL'
mkdir .\downloads -Force | Out-Null
./eph.exe fetch $manifest --out .\downloads
```

### 2. Remote relay-backed share (VPS bootstrap)

Push an incident payload to a hardened remote daemon while forcing manual control hints into the manifest so downstream fetchers know which relay to trust.

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

eph fetch "$MANIFEST" --direct-only \
    --control-host "$CONTROL_HOST" --control-port "$CONTROL_PORT" \
    --control-token "$CONTROL_TOKEN" --out ./downloads/
```

### 3. Automated log escrow (scheduled task)

Automate recurring uploads by wrapping the CLI in a job that mails the manifest to responders.

```powershell
$job = @'
$manifestLine = ./eph.exe --config C:\Ops\eph.yaml store C:\Logs\triage.zip --ttl 3600 |
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

Schedule it via Windows Task Scheduler or cron; the control token and storage directory live in the referenced config file.

### 4. TTL compliance audit (multi-node mesh)

Prove replicas disappear on time by sampling multiple nodes and archiving TTL snapshots + diagnostics.

```bash
for host in node-a node-b node-c; do
  eph --control-host "$host" --control-token $(cat ~/.config/eph/token) status \
      | awk -v h=$host '/PEERS|CHUNKS|ADVERTISED/ {print h " " $0}'
done

mkdir -p audits
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
eph list > audits/ttl-$timestamp.txt

for host in node-a node-b; do
  eph --control-host "$host" --control-token $(cat ~/.config/eph/token) diagnostics > "audits/diag-$host-$timestamp.json"
done
```

Cross-reference the outputs with structured logs and the observability dashboard when briefing auditors.

### 5. Manifest-only disaster recovery

Validate that manifests carry enough discovery metadata to perform restores even when you distrust the local daemon.

```bash
MANIFEST="eph://AQAA..."
mkdir -p recovered
# Attempt transport hints first
eph fetch "$MANIFEST" --transport-only --out recovered/

# Pre-compute a bootstrap token when PoW is required
token=$(python3 scripts/pow_metrics_proxy.py solve --manifest "$MANIFEST")
eph fetch "$MANIFEST" --control-fallback --bootstrap-token "$token" --out recovered/
```

These scenarios double as regression playbooks: run them end-to-end after upgrades to ensure CLI, daemon, transport, and relay code paths still behave as designed.
