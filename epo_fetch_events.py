#!/usr/bin/env python3
# =============================================================================
#  Namn     : epo_fetch_events.py
#  Version  : 1.8.1
#  Datum    : 2026-11-13
#  Skapad av: Lars Niklasson (github.com/lniklasson)
#  Licens   : MIT (se LICENSE)
#  Syfte    : Hämtar Trellix ePO threat events inkrementellt till JSON-filer
#             för ArcSight JSON Folder Follower (parser: trellix_epo.jsonparser.properties)
# -----------------------------------------------------------------------------
#  Ändringslogg
#  1.8.1  2026-11-13  MIT-licens. Publicerad på GitHub.
#  1.8.0  2026-11-05  Berikning enligt ArcSights ePO-mappning: ePO-servern
#                     (ServerHostName, ServerIPAddress, LoadBalanceHttpPort),
#                     datoregenskaper per AgentGUID (SystemSerialNumber, EmailAddress,
#                     PlatformID, SystemManufacturer, SystemModel), eventbeskrivning
#                     (Name) per ThreatEventID samt AnalyzerDATVersionNum. Uppslagen är
#                     separata frågor (ingen join) och valfria. Dubbletter tas bort.
#                     --describe TABELL visar kolumner i ePO-tabeller.
#                     --check-connection testar även berikningen.
#  1.7.0  2026-11-05  --debug (alias -v/--verbose): skriver ut config (lösenord
#                     maskerat), varje HTTP-anrop, normalisering, fil- och
#                     state-skrivningar. --version tillagd.
#  1.6.0  2026-11-05  MAC-adresser normaliseras till 00:11:22:AA:BB:CC.
#                     ThreatHandled normaliseras till "true"/"false".
#  1.5.0  2026-11-05  Lösenord som base64 i config (password_b64).
#                     --encode-password skapar strängen. Klartext ("password")
#                     stöds fortfarande men ger varning.
#  1.4.0  2026-11-05  Lösenord kan anges i config-filen. Ordning: miljövariabel,
#                     config, fråga i terminal. Varning om config är läsbar för andra.
#  1.3.0  2026-11-03  TLS styrs med verify_tls (true/false) och ca_cert (CA-fil).
#                     Rättat: verify ignorerades om REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE
#                     var satta i miljön.
#  1.2.0  2026-11-03  --check-connection (nätverk, TLS, inloggning, query-behörighet).
#                     Tydligt felmeddelande med rad/kolumn vid felaktig JSON i config.
#  1.1.0  2026-11-03  Kompatibel med Python 3.6. Config läses automatiskt
#                     (epo_config.json m.fl.), annars standardvärden.
#  1.0.0  2026-10-21  Första version: core.executeQuery med basic auth,
#                     keyset-paginering på EPOEvents.AutoID, state-fil, atomisk
#                     skrivning, retry/backoff, lås-fil, IPv4-avkodning.
# =============================================================================
"""
epo_fetch_events.py - Inkrementell hämtning av threat events från Trellix ePO on-prem
via Web API (core.executeQuery) till lokala JSON-filer för ArcSight JSON Folder Follower.

Hur det fungerar
  * Basic auth (användare + lösenord) mot https://<epo>:8443/remote/core.executeQuery
  * Keyset-paginering på EPOEvents.AutoID:
        select (top N) ...  where (gt EPOEvents.AutoID <cursor>)  order (asc EPOEvents.AutoID)
    En full sida (N rader) betyder att det kan finnas mer -> nästa sida hämtas direkt.
  * Första körningen: fr.o.m. --start-index (eller start_index i config).
    Senare körningar: fortsätter efter senast hämtade AutoID (sparat i state-filen).
  * Varje sida skrivs atomiskt som {"meta": {...}, "events": [...]} och state uppdateras
    först därefter -> avbrott ger aldrig dataförlust.
  * Retry med backoff vid nätverksfel/429/5xx. Lås-fil mot parallella körningar.

Lösenord hämtas i denna ordning:
  1. miljövariabeln som password_env pekar på (standard EPO_PASSWORD), klartext
  2. "password_b64" i config-filen, base64-kodat (skydda filen: chmod 600)
  3. interaktiv fråga (bara om skriptet körs i en terminal)
ePO-användaren behöver behörighet att köra queries mot Threat Events.

Skapa base64-strängen till "password_b64" (välj ett sätt):
  ./epo_fetch_events.py --encode-password        # frågar efter lösenordet, skriver ut strängen
  echo -n 'MittLösenord' | base64                # Linux (-n är viktigt: ingen radbrytning)
  python3 -c "import base64,getpass; print(base64.b64encode(getpass.getpass().encode()).decode())"
Lägg in resultatet i config-filen:  "password_b64": "TWl0dEzDtnNlbm9yZA==",
OBS: base64 är kodning, inte kryptering - det döljer lösenordet för ögat men vem som
helst som kan läsa filen kan avkoda det. Skydda filen med chmod 600.

Användning
  python epo_fetch_events.py --encode-password        # skapa password_b64-strängen
  python epo_fetch_events.py --check-connection       # testa anslutning/inloggning/behörighet
  python epo_fetch_events.py --start-index 1          # första gången
  python epo_fetch_events.py                          # därefter (t.ex. schemalagt)
  python epo_fetch_events.py --config annan.json      # explicit config-fil
  python epo_fetch_events.py --debug                  # visa allt skriptet gör

Config: utan --config läses epo_config.json, epo_config.example.json eller
config.example.json (första som finns, bredvid skriptet eller i aktuell katalog).
Finns ingen används standardvärdena i DEFAULT_CONFIG. Saknade nycklar får standardvärdet.

Kräver: Python 3.6+ och requests  (pip install requests)
"""
import argparse
import base64
import binascii
import getpass
import json
import logging
import os
import re
import socket
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

__version__ = "1.8.1"
__author__ = "Lars Niklasson (github.com/lniklasson)"

log = logging.getLogger("epo_fetch")

# Kolumner i EPOEvents (finns för alla threat events)
COLUMNS_EPOEVENTS = """
AutoID AutoGUID ServerID ReceivedUTC DetectedUTC EventTimeLocal AgentGUID
Analyzer AnalyzerName AnalyzerVersion AnalyzerHostName AnalyzerIPV4 AnalyzerIPV6 AnalyzerMAC
AnalyzerDATVersion AnalyzerEngineVersion AnalyzerDetectionMethod
SourceHostName SourceIPV4 SourceIPV6 SourceMAC SourceUserName SourceProcessName SourceURL
TargetHostName TargetIPV4 TargetIPV6 TargetMAC TargetUserName TargetPort TargetProtocol
TargetProcessName TargetFileName
ThreatCategory ThreatEventID ThreatSeverity ThreatName ThreatType ThreatActionTaken ThreatHandled
TenantId
""".split()

# Kolumner i EPExtendedEvent (Endpoint Security-detaljer: hashar, sökvägar, regler m.m.)
COLUMNS_EXTENDED = """
EventAutoID Location BladeName AnalyzerTechnologyVersion AnalyzerContentCreationDate
AnalyzerContentVersion AMCoreContentVersion AnalyzerRuleID AnalyzerRuleName AnalyzerRegInfo
AnalyzerGTIQuery ThreatDetectedOnCreation ThreatImpact
SourcePort SourceShareName SourceProcessHash SourceProcessSigned SourceProcessSigner
SourceParentProcessName SourceParentProcessHash SourceParentProcessSigned SourceParentProcessSigner
SourceFilePath SourceFileSize SourceHash SourceSigned SourceSigner
SourceModifyTime SourceAccessTime SourceCreateTime
SourceDeviceDisplayName SourceDeviceSerialNumber SourceDeviceVID SourceDevicePID SourceDescription
SourceURLRatingCode SourceURLWebCategory
TargetURL TargetShareName TargetHash TargetSigned TargetSigner
TargetParentProcessSigned TargetParentProcessSigner TargetParentProcessName TargetParentProcessHash
TargetName TargetPath TargetFileSize TargetModifyTime TargetAccessTime TargetCreateTime
TargetDeviceDisplayName TargetDeviceSerialNumber TargetDeviceVID TargetDevicePID TargetDescription
Cleanable TaskName APIName FirstAttemptedAction FirstActionStatus SecondAttemptedAction SecondActionStatus
Topic AttackVectorType AccessRequested DurationBeforeDetection NaturalLangDescription Direction
""".split()

DEFAULT_CONFIG = {  # type: Dict[str, Any]
    "epo_url": "https://epo.example.local:8443",
    "username": "svc_arcsight",
    "password_b64": "",          # base64-kodat lösenord (skapa med --encode-password)
    "password": "",              # FÖRÅLDRAT: klartext, stöds bara för bakåtkompatibilitet
    "password_env": "EPO_PASSWORD",
    "verify_tls": True,          # true = verifiera ePO:s certifikat, false = verifiera inte (osäkert)
    "ca_cert": "",               # sökväg till CA-fil (.pem) som signerat ePO:s cert; tomt = systemets CA:er
    # "events"   = target EPOEvents -> ALLA threat events (rekommenderat)
    # "extended" = target EPExtendedEvent -> även hashar/sökvägar/regler, men BARA events
    #              som har extended-data (främst Endpoint Security). Kör ev. båda i separata
    #              konfigurationer med olika state/output-kataloger.
    "mode": "events",
    "page_size": 1000,
    "start_index": 1,            # första AutoID som ska hämtas (inklusivt)
    "extra_where": "",           # valfritt extra filter, ePO-syntax, t.ex. (eq EPOEvents.TenantId 1)
    "strip_table_prefix": True,  # "EPOEvents.ThreatName" -> "ThreatName" (krävs av parsern)
    "output_dir": "./epo_events",
    "state_file": "./epo_state.json",
    "timeout": 120,
    "max_retries": 6,
    "max_pages": 0,              # 0 = obegränsat per körning
    "lock_stale_seconds": 6 * 3600,
    # --- Berikning (enligt ArcSights ePO-mappning) -------------------------------------
    # ePO-servern läggs till på varje event: ServerHostName -> dvchost, ServerIPAddress -> dvc,
    # LoadBalanceHttpPort -> spt. Tomt = värd från epo_url, IP via DNS, port utelämnas.
    "server_host_name": "",
    "server_ip_address": "",
    "load_balance_http_port": "",
    # Datoregenskaper slås upp per AgentGUID (Systems-tabellen) -> oldFileId/Name/Path/Permission/Type
    "enrich_systems": True,
    "system_columns": ["SystemSerialNumber", "EmailAddress", "PlatformID",
                       "SystemManufacturer", "SystemModel"],
    # Eventbeskrivning ("Name") slås upp per ThreatEventID -> CEF name
    "enrich_event_names": True,
    "event_desc_language": "0409",   # 0409 = engelska
}


# --------------------------------------------------------------------------- hjälpfunktioner

SECRET_KEYS = ("password", "password_b64")
DEBUG_BODY_CHARS = 2000      # hur mycket av varje HTTP-svar som visas med --debug


def masked(cfg: dict) -> dict:
    """Kopia av config där lösenord är maskerade (för utskrift)."""
    return {k: ("***" if k in SECRET_KEYS and v else v)
            for k, v in cfg.items() if not k.startswith("_")}


def short(text: Any, limit: int = DEBUG_BODY_CHARS) -> str:
    text = str(text)
    return text if len(text) <= limit else "{} ... [{} tecken till]".format(text[:limit], len(text) - limit)


def atomic_write_json(path: Path, data: Any) -> None:
    """Skriver till <namn>.json.part och byter namn atomiskt, så ArcSight (wildcard *.json)
    aldrig läser en halvskriven fil."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".part")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    log.debug("Skrev %s (%d bytes, via %s)", path, path.stat().st_size, tmp.name)


def remove_file(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def load_state(path: Path) -> Dict[str, Any]:
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
        log.debug("Läste state-fil %s: %s", path, state)
        return state
    log.debug("State-fil %s finns inte", path)
    return {}


class Lock:
    def __init__(self, path: Path, stale_seconds: int):
        self.path, self.stale = path, stale_seconds

    def __enter__(self):
        if self.path.exists() and time.time() - self.path.stat().st_mtime > self.stale:
            log.warning("Tar över gammal lås-fil %s", self.path)
            remove_file(self.path)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            log.error("En annan körning pågår (lås-fil %s finns). Avbryter.", self.path)
            sys.exit(2)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        log.debug("Tog lås-fil %s (pid %d)", self.path, os.getpid())
        return self

    def __exit__(self, *exc):
        remove_file(self.path)
        log.debug("Släppte lås-fil %s", self.path)


def epo_ipv4(val: Any) -> Any:
    """ePO lagrar IPv4 som signerat heltal med offset 2^31 (t.ex. 1177773067 = 198.51.100.11).
    Returnerar punktnotation; lämnar redan formaterade värden orörda."""
    if isinstance(val, bool) or val is None:
        return val
    try:
        n = (int(val) + 2**31) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return val
    return ".".join(str((n >> s) & 0xFF) for s in (24, 16, 8, 0))


def epo_mac(val: Any) -> Any:
    """ePO lagrar MAC utan avgränsare ("005056a1b2c3") eller med - / :.
    Returnerar ArcSight-format "00:50:56:A1:B2:C3"; tomt/ogiltigt -> None (fältet lämnas tomt)."""
    if val is None:
        return None
    hexchars = re.sub(r"[^0-9A-Fa-f]", "", str(val))
    if len(hexchars) != 12 or set(hexchars) == {"0"}:
        return None
    return ":".join(hexchars[i:i + 2] for i in range(0, 12, 2)).upper()


def epo_bool(val: Any) -> Any:
    """ThreatHandled kan komma som true/false, 1/0 eller "True"/"False" -> "true"/"false"."""
    if val is None or val == "":
        return None
    if isinstance(val, str):
        return "true" if val.strip().lower() in ("true", "1", "yes") else "false"
    return "true" if bool(val) else "false"


def normalize(row: dict, strip: bool) -> dict:
    """Avkodar IPv4-fält, normaliserar MAC-adresser och ThreatHandled samt tar bort
    tabellprefix ("EPOEvents.X" -> "X"). Vid namnkrock behålls "Tabell_X"."""
    out = {}  # type: Dict[str, Any]
    for key, val in row.items():
        if key.endswith("IPV4"):
            val = epo_ipv4(val)
        elif key.endswith("MAC"):
            val = epo_mac(val)
        elif key.endswith("ThreatHandled"):
            val = epo_bool(val)
        short = key.split(".", 1)[-1] if strip else key
        if short in out:
            short = key.replace(".", "_")
        out[short] = val
    return out


# --------------------------------------------------------------------------- ePO API

def as_bool(val: Any) -> bool:
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("true", "yes", "1", "ja", "on"):
            return True
        if v in ("false", "no", "0", "nej", "off"):
            return False
        raise ValueError("Ogiltigt booleskt värde: {!r} (använd true eller false)".format(val))
    return bool(val)


def tls_verify_setting(cfg: dict) -> Any:
    """Översätter verify_tls/ca_cert till requests 'verify'-parameter:
        verify_tls=false             -> False (ingen verifiering, varning loggas)
        verify_tls=true, ca_cert=""  -> True  (systemets CA-lager)
        verify_tls=true, ca_cert=fil -> fil   (verifiera mot angiven CA)
    Bakåtkompatibelt: verify_tls som sökväg tolkas som ca_cert."""
    verify = cfg.get("verify_tls", True)
    ca_cert = (cfg.get("ca_cert") or "").strip()
    if isinstance(verify, str) and ("/" in verify or "\\" in verify
                                    or verify.lower().endswith((".pem", ".crt", ".cer"))):
        ca_cert, verify = verify.strip(), True   # gammalt format: sökväg i verify_tls

    if not as_bool(verify):
        log.warning("TLS-verifiering är AVSTÄNGD (verify_tls=false) - använd bara för test.")
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:  # noqa: BLE001
            pass
        return False
    if ca_cert:
        if not Path(ca_cert).is_file():
            raise RuntimeError("ca_cert-filen finns inte: {}".format(ca_cert))
        log.info("Verifierar TLS mot CA-fil %s", ca_cert)
        return ca_cert
    log.debug("Verifierar TLS mot systemets CA-lager (requests/certifi)")
    return True


class EpoClient:
    def __init__(self, cfg: dict, password: str):
        self.cfg = cfg
        self.base = cfg["epo_url"].rstrip("/") + "/remote/"
        self.url = self.base + "core.executeQuery"
        self.s = requests.Session()
        self.s.auth = (cfg["username"], password)
        # verify skickas med i VARJE anrop: Session.verify ignoreras av requests om
        # REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE är satta i miljön.
        self.verify = cfg["_tls_verify"] if "_tls_verify" in cfg else tls_verify_setting(cfg)
        self.n = 0
        log.debug("EpoClient: bas-URL %s, användare %s, TLS verify=%r", self.base, cfg["username"], self.verify)
        for var in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            if os.environ.get(var):
                log.debug("Miljövariabel %s=%s", var, os.environ[var])

    def get(self, url: str, params: dict, timeout: float) -> requests.Response:
        self.n += 1
        n = self.n
        if log.isEnabledFor(logging.DEBUG):
            log.debug("HTTP #%d -> GET %s (timeout %ss)", n, url, timeout)
            for k, v in params.items():
                log.debug("HTTP #%d    param %-8s = %s", n, k, short(v, 400))
            log.debug("HTTP #%d    full URL: %s", n, short(requests.Request("GET", url, params=params).prepare().url, 600))
        t0 = time.time()
        try:
            resp = self.s.get(url, params=params, timeout=timeout, verify=self.verify)
        except Exception as exc:
            log.debug("HTTP #%d <- undantag efter %.2fs: %r", n, time.time() - t0, exc)
            raise
        if log.isEnabledFor(logging.DEBUG):
            log.debug("HTTP #%d <- %d %s, %.2fs, %d bytes, Content-Type: %s", n, resp.status_code,
                      resp.reason, time.time() - t0, len(resp.content), resp.headers.get("Content-Type"))
            log.debug("HTTP #%d    svarshuvuden: %s", n, dict(resp.headers))
            log.debug("HTTP #%d    svar: %s", n, short(resp.text))
        return resp

    def query(self, params: dict) -> List[dict]:
        cfg, delay = self.cfg, 2.0
        for attempt in range(1, cfg["max_retries"] + 1):
            try:
                resp = self.get(self.url, params, cfg["timeout"])
            except (requests.ConnectionError, requests.Timeout) as exc:
                wait = delay
                log.debug("Försök %d misslyckades: %r", attempt, exc)
                log.warning("Nätverksfel (%s), försök %d/%d, väntar %.0fs", exc, attempt, cfg["max_retries"], wait)
            else:
                if resp.status_code == 401:
                    raise RuntimeError("401 Unauthorized - kontrollera användare/lösenord och API-behörighet i ePO")
                if resp.status_code == 429 or resp.status_code >= 500:
                    ra = resp.headers.get("Retry-After")
                    wait = float(ra) if ra and ra.isdigit() else delay
                    log.warning("HTTP %d, försök %d/%d, väntar %.0fs", resp.status_code, attempt, cfg["max_retries"], wait)
                else:
                    resp.raise_for_status()
                    return self._parse(resp.text)
            time.sleep(wait)
            delay = min(delay * 2, 300)
        raise RuntimeError(f"Gav upp efter {cfg['max_retries']} försök")

    @staticmethod
    def _parse(text: str) -> List[dict]:
        # ePO svarar "OK:\r\n<json>" vid lyckat anrop, annars t.ex. "Error 1 :\r\n<text>"
        body = text.strip()
        if not body.startswith("OK:"):
            raise RuntimeError("ePO returnerade fel: " + " ".join(body.split())[:500])
        data = json.loads(body[3:].strip() or "[]")
        if not isinstance(data, list):
            raise RuntimeError(f"Oväntat svar från ePO: {str(data)[:300]}")
        log.debug("Svaret tolkat: %d rader%s", len(data),
                  ", kolumner: " + ", ".join(data[0].keys()) if data and isinstance(data[0], dict) else "")
        return data


def dat_number(val: Any) -> Any:
    """AnalyzerDATVersion "10567.0000" -> 10567 (heltal till cn2)."""
    m = re.match(r"\s*(\d+)", str(val)) if val not in (None, "") else None
    return int(m.group(1)) if m else None


class Enricher:
    """Lägger till fält som inte finns i EPOEvents:
       * ePO-servern: ServerHostName, ServerIPAddress, LoadBalanceHttpPort (från config/DNS)
       * datoregenskaper per AgentGUID: SystemSerialNumber, EmailAddress, PlatformID, ... (EPOComputerProperties)
       * eventbeskrivning per ThreatEventID: Name (EPOEventFilterDesc)
       * AnalyzerDATVersionNum (heltalsdelen av AnalyzerDATVersion)
    Uppslagen görs med separata frågor (inte join), så inga events tappas för system
    som tagits bort ur ePO. Misslyckas ett uppslag loggas en varning och hämtningen fortsätter."""

    def __init__(self, cfg: dict, client: "EpoClient"):
        self.cfg, self.client = cfg, client
        self.loaded = False
        self.static = {}          # type: Dict[str, Any]
        self.systems = {}         # type: Dict[str, Dict[str, Any]]
        self.event_names = {}     # type: Dict[str, str]
        self.system_cols_ok = []  # type: List[str]
        self.status = {}          # type: Dict[str, str]

    # -- laddning ------------------------------------------------------------------
    def load(self) -> None:
        if self.loaded:
            return
        self.loaded = True
        self._load_static()
        if as_bool(self.cfg.get("enrich_systems", True)) and self.cfg.get("system_columns"):
            self._load_systems()
        else:
            self.status["systems"] = "avstängt i config"
        if as_bool(self.cfg.get("enrich_event_names", True)):
            self._load_event_names()
        else:
            self.status["event_names"] = "avstängt i config"

    def _load_static(self) -> None:
        url = urllib.parse.urlparse(self.cfg["epo_url"])
        host = (self.cfg.get("server_host_name") or url.hostname or "").strip()
        ip = (self.cfg.get("server_ip_address") or "").strip()
        if not ip and host:
            try:
                ip = socket.gethostbyname(host)
            except OSError as exc:
                log.warning("Kunde inte slå upp IP för ePO-servern %s (%s); ServerIPAddress lämnas tomt", host, exc)
        port = str(self.cfg.get("load_balance_http_port") or "").strip()
        if host:
            self.static["ServerHostName"] = host
        if ip:
            self.static["ServerIPAddress"] = ip
        if port:
            self.static["LoadBalanceHttpPort"] = int(port) if port.isdigit() else port
        self.status["server"] = ", ".join("{}={}".format(k, v) for k, v in self.static.items()) or "inga värden"
        log.debug("ePO-serverfält: %s", self.static)

    def _systems_query(self, cols: List[str]) -> List[dict]:
        sel = " ".join(["EPOLeafNode.AgentGUID"] + ["EPOComputerProperties." + c for c in cols])
        return self.client.query({"target": "EPOLeafNode", "select": "(select {})".format(sel),
                                  ":output": "json"})

    def _load_systems(self) -> None:
        cols = list(self.cfg["system_columns"])
        try:
            rows = self._systems_query(cols)
        except Exception as exc:  # noqa: BLE001
            log.debug("Systems-uppslag med alla kolumner misslyckades (%s), testar kolumnvis", exc)
            ok_cols = []
            for col in cols:
                try:
                    self._systems_query([col])
                    ok_cols.append(col)
                except Exception as exc2:  # noqa: BLE001
                    log.warning("Kolumnen EPOComputerProperties.%s kan inte hämtas och hoppas över: %s",
                                col, short(exc2, 200))
            cols = ok_cols
            if not cols:
                self.status["systems"] = "MISSLYCKADES (inga kolumner kunde hämtas)"
                return
            try:
                rows = self._systems_query(cols)
            except Exception as exc3:  # noqa: BLE001
                log.warning("Systems-uppslag misslyckades: %s", short(exc3, 300))
                self.status["systems"] = "MISSLYCKADES: " + short(exc3, 200)
                return
        for r in rows:
            guid = str(r.get("EPOLeafNode.AgentGUID") or "").strip().lower()
            if not guid:
                continue
            vals = {c: r.get("EPOComputerProperties." + c) for c in cols}
            self.systems[guid] = {k: v for k, v in vals.items() if v not in (None, "")}
        self.system_cols_ok = cols
        self.status["systems"] = "{} system, kolumner: {}".format(len(self.systems), ", ".join(cols))
        log.info("Systems-uppslag: %s", self.status["systems"])

    def _load_event_names(self) -> None:
        lang = str(self.cfg.get("event_desc_language") or "0409")
        params = {"target": "EPOEventFilterDesc",
                  "select": "(select EPOEventFilterDesc.EventId EPOEventFilterDesc.Name)",
                  "where": '(where (eq EPOEventFilterDesc.Language "{}"))'.format(lang),
                  ":output": "json"}
        try:
            rows = self.client.query(params)
        except Exception as exc:  # noqa: BLE001
            log.warning("Uppslag av eventbeskrivningar (Name) misslyckades, name faller tillbaka på "
                        "ThreatName: %s", short(exc, 300))
            self.status["event_names"] = "MISSLYCKADES: " + short(exc, 200)
            return
        for r in rows:
            eid, name = r.get("EPOEventFilterDesc.EventId"), r.get("EPOEventFilterDesc.Name")
            if eid not in (None, "") and name:
                self.event_names[str(eid)] = name
        self.status["event_names"] = "{} eventbeskrivningar (språk {})".format(len(self.event_names), lang)
        log.info("Eventbeskrivningar: %s", self.status["event_names"])

    # -- applicering ---------------------------------------------------------------
    def apply(self, ev: dict, strip: bool) -> dict:
        pre = "" if strip else "EPOEvents."
        for k, v in self.static.items():
            ev.setdefault(k, v)
        guid = str(ev.get(pre + "AgentGUID") or "").strip().lower()
        if guid and guid in self.systems:
            for k, v in self.systems[guid].items():
                ev.setdefault(k, v)
        eid = ev.get(pre + "ThreatEventID")
        if eid not in (None, "") and str(eid) in self.event_names:
            ev.setdefault("Name", self.event_names[str(eid)])
        num = dat_number(ev.get(pre + "AnalyzerDATVersion"))
        if num is not None:
            ev["AnalyzerDATVersionNum"] = num
        return ev


def build_params(cfg: dict, cursor: int) -> dict:
    cols = [f"EPOEvents.{c}" for c in COLUMNS_EPOEVENTS]
    if cfg["mode"] == "extended":
        target = "EPExtendedEvent"
        cols += [f"EPExtendedEvent.{c}" for c in COLUMNS_EXTENDED]
    elif cfg["mode"] == "events":
        target = "EPOEvents"
    else:
        raise ValueError("mode måste vara 'events' eller 'extended'")

    cond = f"(gt EPOEvents.AutoID {int(cursor)})"
    if cfg["extra_where"]:
        cond = f"(and {cond} {cfg['extra_where']})"

    return {
        "target": target,
        "select": f"(select (top {int(cfg['page_size'])}) {' '.join(cols)})",
        "where": f"(where {cond})",
        "order": "(order (asc EPOEvents.AutoID))",
        ":output": "json",
    }


# --------------------------------------------------------------------------- huvudlogik

def run(cfg: dict, password: str, start_override: Optional[int]) -> int:
    out_dir, state_path = Path(cfg["output_dir"]), Path(cfg["state_file"])
    out_dir.mkdir(parents=True, exist_ok=True)

    state = load_state(state_path)
    if start_override is not None:
        cursor = start_override - 1          # "fr.o.m." -> gt (start-1)
        log.info("Startindex satt manuellt: AutoID >= %d", start_override)
    elif "last_auto_id" in state:
        cursor = int(state["last_auto_id"])
        log.info("Fortsätter efter AutoID %d (senaste körning %s)", cursor, state.get("last_run"))
    else:
        cursor = int(cfg["start_index"]) - 1
        log.info("Ingen state, startar från AutoID >= %d", cursor + 1)

    client = EpoClient(cfg, password)
    enricher = Enricher(cfg, client)
    id_key = "AutoID" if cfg["strip_table_prefix"] else "EPOEvents.AutoID"
    pages = total = 0

    log.debug("Output-katalog: %s, state-fil: %s, mode: %s, page_size: %s",
              out_dir.resolve(), state_path.resolve(), cfg["mode"], cfg["page_size"])
    while True:
        log.debug("--- Hämtar sida %d: AutoID > %d", pages + 1, cursor)
        rows = client.query(build_params(cfg, cursor))
        events = [normalize(r, cfg["strip_table_prefix"]) for r in rows]
        if rows and log.isEnabledFor(logging.DEBUG):
            log.debug("Första raden rå:         %s", short(json.dumps(rows[0], ensure_ascii=False)))
            log.debug("Första raden normaliserad: %s", short(json.dumps(events[0], ensure_ascii=False)))
        before = len(events)
        events = [e for e in events if int(e[id_key]) > cursor]
        if len(events) != before:
            log.debug("Filtrerade bort %d rader med AutoID <= %d", before - len(events), cursor)
        events.sort(key=lambda e: int(e[id_key]))
        if not events:
            log.info("Inga fler events.")
            break
        # dubbletter (samma AutoID) tas bort
        seen, unique = set(), []
        for e in events:
            if e[id_key] not in seen:
                seen.add(e[id_key])
                unique.append(e)
        if len(unique) != len(events):
            log.debug("Tog bort %d dubbletter", len(events) - len(unique))
        events = unique
        # berikning (laddas först när det finns nya events)
        enricher.load()
        events = [enricher.apply(e, cfg["strip_table_prefix"]) for e in events]
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Första raden berikad:     %s", short(json.dumps(events[0], ensure_ascii=False)))

        first, last = int(events[0][id_key]), int(events[-1][id_key])
        now = datetime.now(timezone.utc)
        fname = out_dir / f"epo_{cfg['mode']}_{first:012d}_{last:012d}_{now:%Y%m%dT%H%M%SZ}.json"
        atomic_write_json(fname, {
            "meta": {"source": client.url, "collector_version": __version__,
                     "target_mode": cfg["mode"], "first_auto_id": first,
                     "last_auto_id": last, "count": len(events), "fetched_at": now.isoformat()},
            "events": events,
        })
        atomic_write_json(state_path, {"last_auto_id": last, "last_file": fname.name,
                                       "last_run": now.isoformat()})
        pages += 1
        total += len(events)
        log.info("Sida %d: AutoID %d-%d (%d events) -> %s", pages, first, last, len(events), fname.name)

        if last <= cursor:
            log.error("Cursor avancerade inte, avbryter.")
            break
        log.debug("State uppdaterad: last_auto_id=%d", last)
        cursor = last
        if len(rows) < int(cfg["page_size"]):   # kort sida = allt hämtat
            log.debug("Sidan hade %d < page_size %s rader -> allt hämtat", len(rows), cfg["page_size"])
            break
        if cfg["max_pages"] and pages >= cfg["max_pages"]:
            log.info("max_pages=%d nått, resten hämtas nästa körning.", cfg["max_pages"])
            break

    log.info("Klart: %d events i %d filer. Senaste AutoID: %d", total, pages, cursor)
    return total


def check_connection(cfg: dict, password: str) -> bool:
    """Testar steg för steg: nätverk/TLS -> inloggning -> query-behörighet. Hämtar inga events
    och skriver inga filer. Returnerar True om allt fungerar."""
    client = EpoClient(cfg, password)
    timeout = min(int(cfg["timeout"]), 30)
    ok = True

    def result(name: str, passed: bool, detail: str) -> None:
        print("  [{}] {:<22} {}".format("OK " if passed else "FEL", name, detail))

    print("Kontrollerar anslutning till {} som '{}'".format(cfg["epo_url"], cfg["username"]))
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy:
        print("  (OBS: HTTPS_PROXY={} är satt; lägg ePO-värden i NO_PROXY om den inte ska gå via proxy)".format(proxy))

    # 1-2. Nätverk, TLS och inloggning via core.help (ofarligt kommando som kräver inloggning)
    try:
        resp = client.get(client.base + "core.help", {":output": "json"}, timeout)
    except requests.exceptions.SSLError as exc:
        result("TLS-certifikat", False, "{}".format(exc))
        print("      -> Sätt ca_cert till sökvägen för CA-certifikatet (.pem) som signerat ePO:s cert, "
              "eller verify_tls till false för att testa utan verifiering.")
        return False
    except requests.ConnectionError as exc:
        result("Nätverk", False, "{}".format(exc))
        print("      -> Kontrollera epo_url (värd och port, normalt 8443), DNS och brandvägg.")
        return False
    except requests.Timeout:
        result("Nätverk", False, "Timeout efter {}s".format(timeout))
        return False
    result("Nätverk + TLS", True, "HTTP {} från {}".format(resp.status_code, client.base))

    if resp.status_code == 401:
        result("Inloggning", False, "401 Unauthorized - fel användare/lösenord, eller kontot saknar API-åtkomst")
        return False
    if resp.status_code != 200 or not resp.text.strip().startswith("OK:"):
        result("Inloggning", False, "HTTP {}: {}".format(resp.status_code, resp.text.strip()[:200]))
        return False
    result("Inloggning", True, "Basic auth accepterad")

    # 3. Behörighet att köra queries: senaste event i respektive tabell
    targets = [("EPOEvents", "EPOEvents")]
    if cfg["mode"] == "extended":
        targets.append(("EPExtendedEvent", "EPExtendedEvent"))
    latest = None
    for target, label in targets:
        params = {
            "target": target,
            "select": "(select (top 1) EPOEvents.AutoID EPOEvents.ReceivedUTC)",
            "order": "(order (desc EPOEvents.AutoID))",
            ":output": "json",
        }
        try:
            resp = client.get(client.url, params, timeout)
            rows = EpoClient._parse(resp.text)
        except Exception as exc:  # noqa: BLE001
            result("Query " + label, False, str(exc)[:300])
            print("      -> Kontot behöver behörighet att köra queries mot Threat Events i ePO.")
            ok = False
            continue
        if rows:
            auto_id = rows[0].get("EPOEvents.AutoID")
            result("Query " + label, True, "Senaste AutoID {} (mottaget {})".format(
                auto_id, rows[0].get("EPOEvents.ReceivedUTC")))
            if target == "EPOEvents":
                latest = int(auto_id)
        else:
            result("Query " + label, True, "Behörighet OK, men tabellen är tom")

    # 4. Berikning (ePO-server, datoregenskaper, eventbeskrivningar)
    enricher = Enricher(cfg, client)
    enricher.load()
    result("ePO-serverfält", bool(enricher.static), enricher.status.get("server", ""))
    for key, label in (("systems", "Datoregenskaper"), ("event_names", "Eventbeskrivningar")):
        st = enricher.status.get(key, "")
        result(label, not st.startswith("MISSLYCKADES"), st)
    if enricher.status.get("systems", "").startswith("MISSLYCKADES") or \
            enricher.status.get("event_names", "").startswith("MISSLYCKADES"):
        print("      -> Berikningen är valfri: hämtningen fungerar ändå, men fälten blir tomma.")
        print("         Kontrollera tabell-/kolumnnamn med: --describe EPOComputerProperties")

    # Status för inkrementell hämtning
    state = load_state(Path(cfg["state_file"]))
    if latest is not None:
        if "last_auto_id" in state:
            print("  State: senast hämtat AutoID {} -> ca {} nya events väntar".format(
                state["last_auto_id"], max(0, latest - int(state["last_auto_id"]))))
        else:
            print("  State: ingen tidigare hämtning; första körningen startar från AutoID {} "
                  "(start_index eller --start-index)".format(cfg["start_index"]))
    print("Resultat: " + ("anslutningen fungerar." if ok else "anslutningen har problem, se ovan."))
    return ok


def describe_table(cfg: dict, password: str, table: str) -> None:
    """--describe: visar kolumner och relaterade tabeller för en ePO-tabell (core.listTables)."""
    client = EpoClient(cfg, password)
    params = {"table": table} if table and table != "*" else {}
    resp = client.get(client.base + "core.listTables", params, min(int(cfg["timeout"]), 60))
    print(resp.text.strip())


CONFIG_CANDIDATES = ["epo_config.json", "epo_config.example.json", "config.example.json"]


def load_config(explicit: Optional[str]) -> Dict[str, Any]:
    """Startar från DEFAULT_CONFIG och lägger på värden från config-filen.
    Utan --config letas efter CONFIG_CANDIDATES (i tur och ordning) i skriptets katalog
    och i aktuell katalog. Hittas ingen används standardvärdena i skriptet.
    Nycklar som saknas i filen får standardvärdet."""
    cfg = dict(DEFAULT_CONFIG)
    path = None
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            log.error("Config-filen %s finns inte.", path)
            sys.exit(2)
    else:
        for d in (Path(__file__).resolve().parent, Path.cwd()):
            for name in CONFIG_CANDIDATES:
                log.debug("Letar config: %s %s", d / name, "(finns)" if (d / name).is_file() else "(finns inte)")
                if (d / name).is_file():
                    path = d / name
                    break
            if path:
                break

    if path is None:
        log.warning("Ingen config-fil hittad (%s), använder standardvärden i skriptet.",
                    ", ".join(CONFIG_CANDIDATES))
        return cfg

    with open(str(path), encoding="utf-8") as fh:
        text = fh.read()
    try:
        user_cfg = json.loads(text)
    except ValueError as exc:
        lineno = getattr(exc, "lineno", None)
        log.error("Felaktig JSON i %s: %s", path, exc)
        if lineno:
            line = text.splitlines()[lineno - 1]
            log.error("  rad %d: %s", lineno, line)
            log.error("  %s^", " " * (len("rad %d: " % lineno) + getattr(exc, "colno", 1) - 1))
            if "\\" in line:
                log.error("  Tips: backslash måste skrivas dubbelt i JSON, t.ex. \"DOMAN\\\\anvandare\" "
                          "eller \"C:\\\\ArcSight\\\\ca.pem\" (eller använd / i sökvägar).")
        sys.exit(2)
    if not isinstance(user_cfg, dict):
        log.error("%s måste innehålla ett JSON-objekt { ... }", path)
        sys.exit(2)
    # Nycklar som börjar med "_" är kommentarer och ignoreras tyst
    user_cfg = {k: v for k, v in user_cfg.items() if not k.startswith("_")}
    unknown = sorted(set(user_cfg) - set(DEFAULT_CONFIG))
    if unknown:
        log.warning("Okända nycklar i %s ignoreras: %s", path, ", ".join(unknown))
    cfg.update({k: v for k, v in user_cfg.items() if k in DEFAULT_CONFIG})
    log.info("Läste config från %s", path)
    log.debug("Värden från filen: %s", masked(user_cfg))
    cfg["_config_path"] = str(path)
    if (user_cfg.get("password") or user_cfg.get("password_b64")) and os.name == "posix":
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            log.warning("%s innehåller lösenord men är läsbar för andra (rättigheter %o). "
                        "Kör: chmod 600 %s", path, mode, path)
    return cfg


def encode_password(plain: str) -> str:
    return base64.b64encode(plain.encode("utf-8")).decode("ascii")


def decode_password(encoded: str) -> str:
    try:
        return base64.b64decode("".join(str(encoded).split()), validate=True).decode("utf-8")
    except (binascii.Error, ValueError) as exc:
        raise ValueError("password_b64 är inte giltig base64 ({}). Skapa strängen med "
                         "--encode-password".format(exc))


def encode_password_interactive() -> None:
    """--encode-password: frågar efter lösenordet (två gånger) och skriver ut config-raden."""
    if sys.stdin.isatty():
        pw1 = getpass.getpass("Lösenord att koda: ")
        pw2 = getpass.getpass("Upprepa lösenordet: ")
        if pw1 != pw2:
            print("Lösenorden matchar inte.", file=sys.stderr)
            sys.exit(2)
    else:  # t.ex. echo -n 'lösen' | ./epo_fetch_events.py --encode-password
        pw1 = sys.stdin.readline().rstrip("\r\n")
    if not pw1:
        print("Tomt lösenord.", file=sys.stderr)
        sys.exit(2)
    print('Lägg in denna rad i config-filen:\n\n  "password_b64": "{}",\n'.format(encode_password(pw1)))
    print("Skydda filen: chmod 600 <config-fil>   (base64 är kodning, inte kryptering)")


def get_password(cfg: dict) -> str:
    """Miljövariabel -> config-filens "password_b64" -> ("password") -> interaktiv fråga."""
    env_name = cfg.get("password_env") or ""
    src = cfg.get("_config_path", "")
    if env_name and os.environ.get(env_name):
        log.info("Använder lösenord från miljövariabeln %s", env_name)
        return os.environ[env_name]
    if cfg.get("password_b64"):
        try:
            pw = decode_password(cfg["password_b64"])
        except ValueError as exc:
            log.error("%s: %s", src, exc)
            sys.exit(2)
        log.info("Använder lösenord (password_b64) från config-filen %s", src)
        return pw
    if cfg.get("password"):
        log.warning("%s har lösenordet i klartext (password). Byt till password_b64, "
                    "skapa strängen med --encode-password", src)
        return str(cfg["password"])
    if sys.stdin.isatty():
        return getpass.getpass("Lösenord för {}@ePO: ".format(cfg["username"]))
    log.error("Lösenord saknas: ange \"password_b64\" i config-filen (skapa med --encode-password) "
              "eller sätt miljövariabeln %s", env_name)
    sys.exit(2)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Hämtar Trellix ePO threat events inkrementellt till JSON-filer. "
                    "Version {}".format(__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Lösenord (i denna ordning):
  1. miljövariabeln i password_env (standard EPO_PASSWORD)
  2. "password_b64" i config-filen (base64-kodat)
  3. fråga i terminalen

Skapa strängen till "password_b64":
  %(prog)s --encode-password
      frågar efter lösenordet och skriver ut config-raden (rekommenderas)
  echo -n 'MittLösenord' | base64
      Linux, glöm inte -n (annars kodas en radbrytning med)
  python3 -c "import base64,getpass; print(base64.b64encode(getpass.getpass().encode()).decode())"

Lägg in i config-filen, t.ex.:
  "password_b64": "TWl0dEzDtnNlbm9yZA==",

OBS: base64 döljer bara lösenordet för ögat - skydda filen med chmod 600.""")
    ap.add_argument("--version", action="version",
                    version="%(prog)s {} ({})".format(__version__, __author__))
    ap.add_argument("--config", help="JSON-konfigfil. Utan denna letas efter "
                    + ", ".join(CONFIG_CANDIDATES) + " bredvid skriptet / i aktuell katalog")
    ap.add_argument("--start-index", type=int, help="Hämta fr.o.m. detta AutoID (ignorerar state)")
    ap.add_argument("--check-connection", action="store_true",
                    help="Testa bara nätverk, TLS, inloggning och query-behörighet mot ePO "
                         "(hämtar inga events, skriver inga filer). Exit 0 = OK, 1 = fel")
    ap.add_argument("--describe", metavar="TABELL",
                    help="Visa kolumner och relaterade tabeller för en ePO-tabell, t.ex. EPOEvents "
                         "eller EPOComputerProperties (* = alla tabeller)")
    ap.add_argument("--encode-password", action="store_true",
                    help="Skapa base64-strängen till password_b64 i config-filen och avsluta")
    ap.add_argument("--debug", "-v", "--verbose", dest="debug", action="store_true",
                    help="Skriv ut allt skriptet gör: config, varje HTTP-anrop (URL, parametrar, "
                         "status, svarstid, svar), normalisering, fil- och state-skrivningar. "
                         "Lösenord maskeras")
    args = ap.parse_args()

    if args.encode_password:
        encode_password_interactive()
        return

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout,
                            format="%(asctime)s %(levelname)-7s [%(funcName)s] %(message)s")
        logging.getLogger("urllib3").setLevel(logging.DEBUG)   # anslutningar, TLS, proxy
        log.debug("Debug-läge. epo_fetch_events %s, Python %s, requests %s, skript %s",
                  __version__, sys.version.split()[0], requests.__version__, Path(__file__).resolve())
        log.debug("Argument: %s", vars(args))
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    cfg = load_config(args.config)
    try:
        cfg["_tls_verify"] = tls_verify_setting(cfg)
    except (ValueError, RuntimeError) as exc:
        log.error("TLS-inställning: %s", exc)
        sys.exit(2)

    log.debug("Gällande config (standard + fil): %s", masked(cfg))
    password = get_password(cfg)
    log.debug("Lösenord inläst (%d tecken)", len(password))

    if args.check_connection:
        sys.exit(0 if check_connection(cfg, password) else 1)
    if args.describe:
        describe_table(cfg, password, args.describe)
        return

    lock_path = Path(cfg["state_file"]).with_suffix(".lock")
    with Lock(lock_path, cfg["lock_stale_seconds"]):
        try:
            run(cfg, password, args.start_index)
        except Exception:
            log.exception("Körningen misslyckades; state pekar på senast lyckade sida.")
            sys.exit(1)


if __name__ == "__main__":
    main()
