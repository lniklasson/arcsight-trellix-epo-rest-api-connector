# Trellix ePO → ArcSight

Fetches threat events from **Trellix ePolicy Orchestrator (on-prem)** via the Web API into
local JSON files, plus an **ArcSight JSON Folder Follower parser** that maps the fields to CEF.

| File | Description |
|---|---|
| `epo_fetch_events.py` | Incremental fetching of events from ePO into JSON files |
| `trellix_epo.jsonparser.properties` | ArcSight FlexConnector parser (JSON Folder Follower) |
| `epo_config.example.json` | Example config with an explanation of every setting |
| `epo_config.sample.json` | Complete, filled-in config showing what a finished `epo_config.json` looks like |

## Features

- `core.executeQuery` against ePO with basic auth (`https://<epo>:8443/remote/`)
- Incremental fetching: continues after the last fetched `EPOEvents.AutoID` (state file)
- Pagination with `top N` + `AutoID > x`, retry/backoff on 429/5xx/network errors, lock file
- Atomic writes (`.json.part` → `.json`), so ArcSight never reads half-written files
- Normalization: IPv4 (ePO integer → dotted notation), MAC (`00:11:22:AA:BB:CC`), ThreatHandled
- Enrichment according to ArcSight's ePO mapping: the ePO server, system properties per
  AgentGUID, event description per ThreatEventID (separate lookups, no join)
- Python 3.6+, the only dependency is `requests`

## Getting started

```bash
pip install requests            # Python 3.6: pip install "requests==2.27.1"
cp epo_config.sample.json epo_config.json     # or epo_config.example.json (with explanations)
chmod 600 epo_config.json

./epo_fetch_events.py --encode-password      # create the value for "password_b64"
# edit epo_config.json: epo_url, username, password_b64, ca_cert, output_dir ...

./epo_fetch_events.py --check-connection     # test network, TLS, login, permissions
./epo_fetch_events.py --start-index 1        # first run
./epo_fetch_events.py                        # afterwards, e.g. from cron
```

Example cron entry (every 5 minutes):

```
*/5 * * * * cd /opt/trellix && ./epo_fetch_events.py >> /var/log/epo_fetch.log 2>&1
```

All values in `epo_config.sample.json` are placeholders (host names, IP, account and the
password `ChangeMe!` encoded as base64) and must be replaced with your own.

## Options

| Option | Description |
|---|---|
| `--config FILE` | Config file. Without it, `epo_config.json`, `epo_config.example.json`, `config.example.json` are searched |
| `--start-index N` | Fetch from AutoID N (ignores the state) |
| `--check-connection` | Test connection, login, query permission and enrichment. Exit 0 = OK |
| `--describe TABLE` | Show columns/related tables in ePO, e.g. `EPOComputerProperties` |
| `--encode-password` | Create the base64 string for `password_b64` |
| `--debug` | Print everything the script does (passwords are masked) |
| `--version` | Show the version |

## Password

Read in this order: environment variable `EPO_PASSWORD` → `password_b64` in the config → terminal prompt.
Base64 is encoding, not encryption – protect the config file with `chmod 600`.
`epo_config.json` is listed in `.gitignore` and must never be committed.

## ArcSight

1. Copy `trellix_epo.jsonparser.properties` to `<ARCSIGHT_HOME>/current/user/agent/flexagent/`
2. Install a **JSON Folder Follower** connector with Configuration File `trellix_epo`
3. Point the folder at `output_dir`, wildcard `*.json`

The parser follows ArcSight's mapping table for ePO (e.g. dvc/dvchost = the ePO server,
cs1–cs5, cn1–cn2, oldFile* = system properties, severity 0–2 High / 3–4 Medium / 5–7 Low).
Fields without a natural CEF field go to Additional Data. See the comments in the parser.

## License

MIT – see [LICENSE](LICENSE).
