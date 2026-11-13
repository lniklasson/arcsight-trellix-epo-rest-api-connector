# Trellix ePO → ArcSight

Hämtar threat events från **Trellix ePolicy Orchestrator (on-prem)** via Web API till lokala
JSON-filer, och en **ArcSight JSON Folder Follower-parser** som mappar fälten till CEF.

| Fil | Beskrivning |
|---|---|
| `epo_fetch_events.py` | Inkrementell hämtning av events från ePO till JSON-filer |
| `trellix_epo.jsonparser.properties` | ArcSight FlexConnector-parser (JSON Folder Follower) |
| `epo_config.example.json` | Exempel på config med förklaring av alla inställningar |

## Funktioner

- `core.executeQuery` mot ePO med basic auth (`https://<epo>:8443/remote/`)
- Inkrementell hämtning: fortsätter efter senast hämtade `EPOEvents.AutoID` (state-fil)
- Paginering med `top N` + `AutoID > x`, retry/backoff vid 429/5xx/nätverksfel, lås-fil
- Atomisk skrivning (`.json.part` → `.json`), så ArcSight aldrig läser halvskrivna filer
- Normalisering: IPv4 (ePO-heltal → punktnotation), MAC (`00:11:22:AA:BB:CC`), ThreatHandled
- Berikning enligt ArcSights ePO-mappning: ePO-server, datoregenskaper per AgentGUID,
  eventbeskrivning per ThreatEventID (separata uppslag, ingen join)
- Python 3.6+, enda beroendet är `requests`

## Kom igång

```bash
pip install requests            # Python 3.6: pip install "requests==2.27.1"
cp epo_config.example.json epo_config.json
chmod 600 epo_config.json

./epo_fetch_events.py --encode-password      # skapa värdet till "password_b64"
# redigera epo_config.json: epo_url, username, password_b64, ca_cert, output_dir ...

./epo_fetch_events.py --check-connection     # testa nätverk, TLS, inloggning, behörighet
./epo_fetch_events.py --start-index 1        # första körningen
./epo_fetch_events.py                        # därefter, t.ex. från cron
```

Exempel på cron (var 5:e minut):

```
*/5 * * * * cd /opt/trellix && ./epo_fetch_events.py >> /var/log/epo_fetch.log 2>&1
```

## Kommandon

| Flagga | Beskrivning |
|---|---|
| `--config FIL` | Config-fil. Utan flaggan letas `epo_config.json`, `epo_config.example.json`, `config.example.json` |
| `--start-index N` | Hämta fr.o.m. AutoID N (ignorerar state) |
| `--check-connection` | Testa anslutning, inloggning, query-behörighet och berikning. Exit 0 = OK |
| `--describe TABELL` | Visa kolumner/relaterade tabeller i ePO, t.ex. `EPOComputerProperties` |
| `--encode-password` | Skapa base64-strängen till `password_b64` |
| `--debug` | Skriv ut allt skriptet gör (lösenord maskeras) |
| `--version` | Visa version |

## Lösenord

Läses i ordningen: miljövariabeln `EPO_PASSWORD` → `password_b64` i config → fråga i terminalen.
Base64 är kodning, inte kryptering – skydda config-filen med `chmod 600`.
`epo_config.json` finns i `.gitignore` och ska aldrig checkas in.

## ArcSight

1. Kopiera `trellix_epo.jsonparser.properties` till `<ARCSIGHT_HOME>/current/user/agent/flexagent/`
2. Installera en **JSON Folder Follower**-connector med Configuration File `trellix_epo`
3. Peka foldern mot `output_dir`, wildcard `*.json`

Parsern följer ArcSights mappningstabell för ePO (bl.a. dvc/dvchost = ePO-servern,
cs1–cs5, cn1–cn2, oldFile* = datoregenskaper, severity 0–2 High / 3–4 Medium / 5–7 Low).
Fält utan naturligt CEF-fält hamnar i Additional Data. Se kommentarerna i parsern.

## Licens

MIT – se [LICENSE](LICENSE).
