# unifi-dns4me

This tool enables all devices on your network to benefit from DNS4ME geo-unblocking without individual device configuration. It downloads DNS4ME's dnsmasq feed via their API and syncs it into UniFi Network DNS Forward Domain policies, so your UniFi setup stays up-to-date with DNS4ME's servers.

This setup ONLY sends DNS requests for the services you have geo-unblocked with DNS4ME, allowing you to keep your current upstream DNS server intact.

## Why this exists

My older gateway scripts wrote directly into unifis dnsmasq.

While this worked, it suffered from some caveats:

UniFi OS updates and restarts removed those changes and they needed to be reloaded again at startup.

This version uses the UniFi Network API instead:

- Your WAN/upstream DNS stays as-is, such as Cloudflare, Google, NextDNS, or encrypted DNS.
- Only DNS4ME managed domains are conditionally forwarded to DNS4ME's resolvers.
- The configuration lives in UniFi Network instead of an injected dnsmasq file.

## Requirements

- Python 3.10+ / Docker
- DNS4ME API key or raw dnsmasq API URL
- UniFi Network API key
- A UniFi gateway/network version that supports DNS `Forward Domain` policies

## Obtaining DNS4ME API key or raw dnsmasq API URL

Log into your DNS4ME account and navigate to this page: [Host File](https://dns4me.net/user/hosts_file)

Select the `dnsmasq Config` tab at the top and then click the `Show Raw dnsmasq API URL` button to reveal your raw dnsmasq API URL.

For example: `https://dns4me.net/api/v2/get_hosts/dnsmasq/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

Your `DNS4ME API key` is just the string at the end `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

## Generating your Unifi Network API key

You need to generate a Network App API key, found here:

`Network App > Integrations`

DO NOT generate a Site Manager/cloud key, Protect key, Access key, or password token.

## Running Sync

There are two ways to run the sync:

- Local CLI: useful while testing, debugging, or running from your own scheduler.
- Docker: best for an always-on daily sync container on a NAS, server, or Docker host.

### Local CLI

Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
cp .env.example .env
```

Edit `.env` with your API keys / settings, then load it:

```bash
set -a
. ./.env
set +a
```

Preview the DNS4ME feed:

```bash
unifi-dns4me preview
```

Check the loaded configuration without printing secrets:

```bash
unifi-dns4me doctor
```

List the UniFi forwarders that the tool recognizes:

```bash
unifi-dns4me existing
```

Check what would be created in UniFi:

```bash
unifi-dns4me sync --dry-run
```

Apply the changes:

```bash
unifi-dns4me sync
```

Check whether DNS4ME sees this host/container as correctly routed:

```bash
unifi-dns4me check
```

Run sync without removing stale entries:

```bash
unifi-dns4me sync --no-delete-stale
```

Rebuild the state file if it was accidentally deleted:

```bash
unifi-dns4me populate-state
```

If UniFi is currently using DNS4ME resolver index `2`, populate state from server index `2`:

```bash
unifi-dns4me populate-state --server-index 2
```

## Docker

Unifi-dns4me is a lightweight image and is supported on the following platforms:

```text
linux/amd64
linux/arm64
linux/arm/v7
```

### Compose

Edit `.env` or `docker-compose.yml` with your API keys / settings, then start the daily sync service:

```bash
docker compose up -d
```

Check logs:

```bash
docker compose logs -f
```

Operational logs are timestamped using the container's local timezone:

```text
2026-04-20T10:14:17 Heartbeat started. Current DNS4ME resolver: 3.10.65.124 (resolver 1 of 2).
```

With heartbeat enabled, failures and resolver switches are logged by default. To also log successful heartbeat checks, set:

```bash
HEARTBEAT_LOG_SUCCESS=true
```

To include the individual prerequisite check lines, set:

```bash
HEARTBEAT_LOG_DETAILS=true
```

With both enabled, healthy heartbeat logs look like:

```text
2026-04-20T10:14:17 Heartbeat started. Current DNS4ME resolver: 3.10.65.124 (resolver 1 of 2).
2026-04-20T10:14:17 Heartbeat internet check passed: 1.1.1.1:443
2026-04-20T10:14:17 Heartbeat DNS check passed: cloudflare.com
2026-04-20T10:14:17 Heartbeat HTTP check passed: https://cloudflare.com/cdn-cgi/trace HTTP 200
2026-04-20T10:14:17 Heartbeat DNS4ME check passed
2026-04-20T10:14:17 Heartbeat DNS4ME PASS. Current DNS4ME resolver is healthy: 3.10.65.124 (resolver 1 of 2).
```

If the internet, normal DNS, or normal HTTP checks fail, the daemon logs those failures and skips resolver switch decisions for that heartbeat.
Before switching all managed forwarders, heartbeat first updates only the `dns4me.net` check forwarder to the alternate resolver, runs the real DNS4ME check through UniFi, and skips the wider UniFi write if that check does not pass.

```text
2026-04-20T10:19:19 Heartbeat preflight for alternate DNS4ME resolver: 3.10.65.125 (resolver 2 of 2) using UniFi check-domain forwarding.
2026-04-20T10:19:19 updated check forwarder: dns4me.net -> 3.10.65.125
2026-04-20T10:19:19 Waiting 10s before DNS4ME preflight check (attempt 1, timeout 600s).
2026-04-20T10:19:29 Heartbeat preflight result: UniFi check-domain forwarding passed.
```

### Notifications

Notifications are optional and use [Apprise](https://github.com/caronc/apprise), so one setting can target Telegram, Discord, Gotify, Pushover, ntfy, Slack, and many others.

For example:

```bash
NOTIFY_URLS=tgram://bot_token/chat_id
```

Multiple notification targets can be comma-separated:

```bash
NOTIFY_URLS=tgram://bot_token/chat_id,discord://webhook_id/webhook_token
```

The daemon only sends high-value notifications by default: scheduled sync changes, scheduled sync errors, DNS4ME failure threshold reached, resolver switch success, resolver switch failure, and recovery after failed heartbeat checks. Notification delivery errors are logged but do not stop sync or heartbeat.

Test the configured notification URL from inside the container:

```bash
docker compose run --rm unifi-dns4me notify-test
```

### Testing / manual runs

Run a one-shot dry-run:

```bash
docker compose run --rm unifi-dns4me sync --dry-run
```

Run a one-shot sync:

```bash
docker compose run --rm unifi-dns4me sync
```

Run DNS4ME's check from inside the container:

```bash
docker compose run --rm unifi-dns4me check
```

Rebuild the state file if the Docker volume or `state.json` was accidentally deleted:

```bash
docker compose run --rm unifi-dns4me populate-state
```

If UniFi is currently using DNS4ME resolver index `2`:

```bash
docker compose run --rm unifi-dns4me populate-state --server-index 2
```

### Manual UniFi DNS API test

There is also a PowerShell helper for testing UniFi DNS policy writes directly:

```powershell
./scripts/Test-UnifiDnsPolicy.ps1 `
  -UnifiHost "https://192.168.1.1" `
  -ApiKey $env:UNIFI_API_KEY `
  -SiteId "Default" `
  -SkipTlsVerify `
  -Action RoundTrip
```

`RoundTrip` creates a harmless `unifi-dns4me-test.invalid` forwarder, updates it with `PUT`, then deletes it. That lets you test whether UniFi accepts DNS Forward Domain updates without touching DNS4ME-managed entries.

List current DNS policies:

```powershell
./scripts/Test-UnifiDnsPolicy.ps1 -ApiKey $env:UNIFI_API_KEY -SkipTlsVerify -Action List
```

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `DNS4ME_API_KEY` | yes* | DNS4ME API key. Used to build `https://dns4me.net/api/v2/get_hosts/dnsmasq/{key}`. |
| `DNS4ME_DNSMASQ_URL` | yes* | Full raw dnsmasq URL from DNS4ME. Takes precedence over `DNS4ME_API_KEY`. |
| `UNIFI_HOST` | no | Local UniFi host. Defaults to `https://192.168.1.1`. |
| `UNIFI_API_KEY` | yes | UniFi API key. |
| `UNIFI_SITE_ID` | no | UniFi site short name or internal id. Defaults to `default`. |
| `UNIFI_SKIP_TLS_VERIFY` | no | Set to `true` for self-signed local UniFi certificates. Defaults to `true` in `.env.example`. |
| `DNS4ME_MAX_SERVERS_PER_DOMAIN` | no | Maximum DNS4ME resolver targets to create per domain. Defaults to `1`, matching UniFi's single DNS Server field. |
| `DNS4ME_INCLUDE_CHECK_DOMAIN` | no | Add `dns4me.net` as a managed Forward Domain so DNS4ME's own status check resolves through DNS4ME. Defaults to `true`. |
| `SYNC_AT` | no | Daily scheduler time for `daemon`, in `HH:MM` container local time. Defaults to `03:15`. |
| `STATE_PATH` | no | Persistent state file used to track entries managed by this tool. Defaults to `.unifi-dns4me-state.json`; use `/data/state.json` for Docker with a `/data` volume. |
| `DELETE_STALE` | no | Delete stale entries that the state file identifies as previously managed. Defaults to `true`. |
| `CHECK_AFTER_SYNC` | no | Run `http://check.dns4me.net` after sync. Defaults to `true`. |
| `CHECK_AFTER_SYNC_DELAY_SECONDS` | no | Seconds to wait after UniFi writes before running DNS4ME checks. For heartbeat preflight this is the polling interval. Defaults to `10`; set `0` to disable waiting/polling. |
| `HEARTBEAT_ENABLED` | no | Enable periodic DNS4ME health checks while the daemon is running. Defaults to `true`. |
| `HEARTBEAT_INTERVAL_SECONDS` | no | Seconds between heartbeat checks. Defaults to `300`. |
| `HEARTBEAT_FAILURES_BEFORE_SWITCH` | no | Consecutive active DNS4ME resolver failures before trying the alternate resolver. Defaults to `2`. |
| `HEARTBEAT_SWITCH_RETRY_SECONDS` | no | Cooldown before retrying a failed resolver switch attempt. Also bounds how long heartbeat preflight polling may wait for UniFi DNS changes to settle. Defaults to `600`. |
| `HEARTBEAT_INTERNET_CHECKS` | no | Comma-separated `host:port` TCP checks used to confirm internet reachability. Defaults to `1.1.1.1:443,8.8.8.8:443,9.9.9.9:443`. |
| `HEARTBEAT_DNS_CHECK_DOMAINS` | no | Comma-separated domains used for the heartbeat general DNS check. Defaults to `cloudflare.com,dns.google,quad9.net`. |
| `HEARTBEAT_HTTP_CHECK_URLS` | no | Comma-separated URLs used for the heartbeat general HTTP check. Defaults to `https://cloudflare.com/cdn-cgi/trace,https://www.google.com/generate_204,https://dns.quad9.net/`. |
| `HEARTBEAT_LOG_SUCCESS` | no | Log successful heartbeat summaries. Defaults to `false`; failures and resolver switches are always logged. |
| `HEARTBEAT_LOG_DETAILS` | no | Log each heartbeat prerequisite check. Defaults to `false`; failed check details are still logged. |
| `NOTIFY_URLS` | no | Optional comma-separated Apprise URLs. Leave empty to disable notifications. |
| `NOTIFY_ON_SYNC_ERROR` | no | Notify when scheduled sync fails or post-sync checks fail. Defaults to `true`. |
| `NOTIFY_ON_SYNC_CHANGES` | no | Notify when sync creates, updates, or deletes UniFi DNS policies. Defaults to `true`. |
| `NOTIFY_ON_SWITCH` | no | Notify when heartbeat switches to the alternate DNS4ME resolver. Defaults to `true`. |
| `NOTIFY_ON_SWITCH_FAILURE` | no | Notify when heartbeat cannot validate or complete a resolver switch. Defaults to `true`. |
| `NOTIFY_ON_CHECK_FAIL` | no | Notify when heartbeat reaches the DNS4ME failure threshold. Defaults to `true`. |
| `NOTIFY_ON_CHECK_RECOVERY` | no | Notify when the active resolver recovers after one or more failed heartbeat checks. Defaults to `true`. |

*Use either `DNS4ME_API_KEY` or `DNS4ME_DNSMASQ_URL`.

## State File

The state file is JSON. Docker uses `/data/state.json` by default when using the example compose file:

```json
{
  "version": 1,
  "active_server_index": 1,
  "dns4me_servers": [
    "3.10.65.124",
    "3.10.65.125"
  ],
  "managed_rules": [
    {
      "domain": "bbc.co.uk",
      "server": "3.10.65.124"
    }
  ]
}
```

## How Sync Works

- `sync` downloads DNS4ME's dnsmasq rules, selects the active DNS4ME resolver, and then processes each wanted domain one at a time.
- For each domain, it queries UniFi with `filter=domain.eq('example.com')`.
- If no Forward Domain policy exists, it creates one.
- If one Forward Domain policy exists and already points to the current DNS4ME resolver, it leaves it alone.
- If one Forward Domain policy exists but points to a different resolver, it updates that policy with `PUT`.
- If multiple Forward Domain policies exist for the same domain, it deletes only the entries that do not point to the current DNS4ME resolver. If none of the duplicates point to the current resolver, it creates one clean replacement.
- Normal single-policy updates are `PUT` only. Duplicate cleanup may delete incorrect duplicate policies.
- The tool includes `dns4me.net` by default because DNS4ME's check endpoint depends on that domain resolving through DNS4ME.
- DNS4ME often supplies two resolver IPs per domain. UniFi's Forward Domain UI has one DNS Server field, so the tool defaults to one target per domain. Set `DNS4ME_MAX_SERVERS_PER_DOMAIN=2` only if your UniFi version supports duplicate Forward Domain policies for the same domain.
- The state file records the DNS4ME rules this tool manages after a successful non-dry-run sync. On later runs, stale deletion can safely remove UniFi forwarders that were previously managed but disappeared from DNS4ME.
- The state file records the current DNS4ME resolver slot and last-known DNS4ME resolver IPs. That cache is useful when the DNS4ME feed cannot be reached but the tool still needs to know which resolver was active.
- The first successful non-dry-run sync seeds the state file from the current DNS4ME rule set. A dry-run does not write state.
- If the state file is accidentally deleted, `populate-state` rebuilds it from DNS4ME rules that already exist as UniFi Forward Domain policies. It does not create, update, or delete UniFi policies.
- The DNS4ME check is only meaningful from a host or container whose DNS lookups use the UniFi gateway/DNS path you are configuring.
- `CHECK_AFTER_SYNC` only runs and reports the DNS4ME status check after sync. When the sync writes UniFi DNS policies, the check waits `CHECK_AFTER_SYNC_DELAY_SECONDS` first so the new forwarder can settle. During heartbeat resolver switching, the preflight check polls every `CHECK_AFTER_SYNC_DELAY_SECONDS` until DNS4ME passes or `HEARTBEAT_SWITCH_RETRY_SECONDS` is reached.
- Heartbeat checks distinguish "DNS4ME is down" from "the internet or general DNS is down" using TCP internet checks, normal DNS lookups, and HTTP requests. Configure multiple checks with the `HEARTBEAT_*` variables so one upstream service outage does not trigger a resolver switch on its own. The older single-value variables `HEARTBEAT_INTERNET_CHECK_HOST`, `HEARTBEAT_INTERNET_CHECK_PORT`, `HEARTBEAT_DNS_CHECK_DOMAIN`, and `HEARTBEAT_HTTP_CHECK_URL` still work for existing installs.
- If heartbeat sees enough active DNS4ME resolver failures while prerequisites are healthy, it validates and switches to the alternate resolver. It does not prefer resolver `1`; whichever resolver is currently working stays active until it fails.
- UniFi's local API documentation is available in UniFi Network under `Integrations`.

## Troubleshooting

### HTTP 401 Unauthorized

The request reached UniFi, but the API key was rejected. Check:

- Hyphens in the key are fine. Quote the value only if it contains spaces or shell-special characters.
- Create the key in the Network app at `Integrations`.
- Use a UniFi Network Integration API key, not a Site Manager, Protect, Access, or account password token.
- Make sure the key belongs to a user/admin with permission to manage Network settings.
- If your browser URL looks like `/network/default/dashboard`, `default` is the short site name. The tool will try to resolve that to the internal site id before syncing.
- Reload `.env` in your shell after changing the key:

```bash
set -a
. ./.env
set +a
```

### Permission denied writing `/data/state.json.tmp`

The container needs write access to `/data` so it can atomically save the state file. The image runs as root by default to avoid bind-mount ownership problems on NAS/appdata paths.

If you override the container user, make sure that user can write to the mounted `/data` directory.

### TLS or certificate errors

Local UniFi consoles often use self-signed certificates. Set:

```bash
UNIFI_SKIP_TLS_VERIFY=true
```

### Manually reviewing DNS Forwarding entries

Ubiquiti's current UI path to view the DNS entries is: `Network > Settings > Policy Table > DNS`

### UniFi returns HTTP 500 when updating a DNS policy

If the logged `UniFi PUT debug` command also fails when run manually, the request body is probably not the issue. One observed UniFi bug created duplicate DNS policies with broken or conflicting internal GUIDs. In that case, remove the bad duplicate policy in UniFi or let the next sync prune duplicates for that domain.

## References

- [UniFi DNS Records and Local Hostnames](https://help.ui.com/hc/en-us/articles/15179064940439-UniFi-DNS-Records-and-Local-Hostnames)
- [Getting Started with the Official UniFi API](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-UniFi-API)
