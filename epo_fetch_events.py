#!/usr/bin/env python3
# =============================================================================
#  Name     : epo_fetch_events.py
#  Version  : 1.9.0
#  Date     : 2026-11-13
#  Author   : Lars Niklasson (github.com/lniklasson)
#  License  : MIT (see LICENSE)
#  Purpose  : Incrementally fetches Trellix ePO threat events into JSON files
#             for the ArcSight JSON Folder Follower (parser: trellix_epo.jsonparser.properties)
# -----------------------------------------------------------------------------
#  Changelog
#  1.9.0  2026-11-13  All comments, log messages, help texts and output in English.
#  1.8.1  2026-11-13  MIT license. Published on GitHub.
#  1.8.0  2026-11-05  Enrichment according to ArcSight's ePO mapping: the ePO server
#                     (ServerHostName, ServerIPAddress, LoadBalanceHttpPort),
#                     system properties per AgentGUID (SystemSerialNumber, EmailAddress,
#                     PlatformID, SystemManufacturer, SystemModel), event description
#                     (Name) per ThreatEventID and AnalyzerDATVersionNum. Lookups are
#                     separate queries (no join) and optional. Duplicates are removed.
#                     --describe TABLE shows the columns of ePO tables.
#                     --check-connection also tests the enrichment.
#  1.7.0  2026-11-05  --debug (alias -v/--verbose): prints the config (password
#                     masked), every HTTP call, normalization, file and state
#                     writes. --version added.
#  1.6.0  2026-11-05  MAC addresses normalized to 00:11:22:AA:BB:CC.
#                     ThreatHandled normalized to "true"/"false".
#  1.5.0  2026-11-05  Password as base64 in the config (password_b64).
#                     --encode-password creates the string. Plain text ("password")
#                     is still supported but logs a warning.
#  1.4.0  2026-11-05  Password can be set in the config file. Order: environment
#                     variable, config, terminal prompt. Warning if the config is
#                     readable by others.
#  1.3.0  2026-11-03  TLS controlled by verify_tls (true/false) and ca_cert (CA file).
#                     Fixed: verify was ignored when REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE
#                     was set in the environment.
#  1.2.0  2026-11-03  --check-connection (network, TLS, login, query permission).
#                     Clear error message with line/column for invalid JSON in the config.
#  1.1.0  2026-11-03  Compatible with Python 3.6. Config is loaded automatically
#                     (epo_config.json etc.), otherwise defaults are used.
#  1.0.0  2026-10-21  First version: core.executeQuery with basic auth,
#                     keyset pagination on EPOEvents.AutoID, state file, atomic
#                     writes, retry/backoff, lock file, IPv4 decoding.
# =============================================================================
"""
epo_fetch_events.py - Incremental fetching of threat events from Trellix ePO on-prem
via the Web API (core.executeQuery) into local JSON files for the ArcSight JSON Folder Follower.

How it works
  * Basic auth (user + password) against https://<epo>:8443/remote/core.executeQuery
  * Keyset pagination on EPOEvents.AutoID:
        select (top N) ...  where (gt EPOEvents.AutoID <cursor>)  order (asc EPOEvents.AutoID)
    A full page (N rows) means there may be more -> the next page is fetched right away.
  * First run: from --start-index (or start_index in the config), inclusive.
    Later runs: continue after the last fetched AutoID (saved in the state file).
  * Each page is written atomically as {"meta": {...}, "events": [...]} and the state is
    updated only afterwards -> an interruption never loses data.
  * Retry with backoff on network errors/429/5xx. Lock file prevents parallel runs.

The password is read in this order:
  1. the environment variable named by password_env (default EPO_PASSWORD), plain text
  2. "password_b64" in the config file, base64 encoded (protect the file: chmod 600)
  3. interactive prompt (only when the script runs in a terminal)
The ePO user needs permission to run queries against Threat Events.

Create the base64 string for "password_b64" (pick one):
  ./epo_fetch_events.py --encode-password        # prompts for the password, prints the string
  echo -n 'MyPassword' | base64                  # Linux (-n matters: no trailing newline)
  python3 -c "import base64,getpass; print(base64.b64encode(getpass.getpass().encode()).decode())"
Put the result in the config file:  "password_b64": "TXlQYXNzd29yZA==",
NOTE: base64 is encoding, not encryption - it hides the password from casual view, but
anyone who can read the file can decode it. Protect the file with chmod 600.

Usage
  python epo_fetch_events.py --encode-password        # create the password_b64 string
  python epo_fetch_events.py --check-connection       # test connection/login/permissions
  python epo_fetch_events.py --start-index 1          # first run
  python epo_fetch_events.py                          # afterwards (e.g. scheduled)
  python epo_fetch_events.py --config other.json      # explicit config file
  python epo_fetch_events.py --debug                  # show everything the script does

Config: without --config, epo_config.json, epo_config.example.json or
config.example.json is read (the first one found, next to the script or in the current
directory). If none exists, the defaults in DEFAULT_CONFIG are used. Missing keys get
their default value.

Requires: Python 3.6+ and requests  (pip install requests)
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

__version__ = "1.9.0"
__author__ = "Lars Niklasson (github.com/lniklasson)"

log = logging.getLogger("epo_fetch")

# Columns in EPOEvents (present for all threat events)
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

# Columns in EPExtendedEvent (Endpoint Security details: hashes, paths, rules etc.)
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
    "password_b64": "",          # base64-encoded password (create with --encode-password)
    "password": "",              # DEPRECATED: plain text, supported for backward compatibility only
    "password_env": "EPO_PASSWORD",
    "verify_tls": True,          # true = verify the ePO certificate, false = do not verify (insecure)
    "ca_cert": "",               # path to the CA file (.pem) that signed the ePO cert; empty = system CAs
    # "events"   = target EPOEvents -> ALL threat events (recommended)
    # "extended" = target EPExtendedEvent -> also hashes/paths/rules, but ONLY events
    #              that have extended data (mainly Endpoint Security). Optionally run both
    #              as separate configurations with different state/output directories.
    "mode": "events",
    "page_size": 1000,
    "start_index": 1,            # first AutoID to fetch (inclusive)
    "extra_where": "",           # optional extra filter, ePO syntax, e.g. (eq EPOEvents.TenantId 1)
    "strip_table_prefix": True,  # "EPOEvents.ThreatName" -> "ThreatName" (required by the parser)
    "output_dir": "./epo_events",
    "state_file": "./epo_state.json",
    "timeout": 120,
    "max_retries": 6,
    "max_pages": 0,              # 0 = unlimited per run
    "lock_stale_seconds": 6 * 3600,
    # --- Enrichment (according to ArcSight's ePO mapping) ------------------------------
    # The ePO server is added to every event: ServerHostName -> dvchost, ServerIPAddress -> dvc,
    # LoadBalanceHttpPort -> spt. Empty = host from epo_url, IP via DNS, port omitted.
    "server_host_name": "",
    "server_ip_address": "",
    "load_balance_http_port": "",
    # System properties looked up per AgentGUID (Systems table) -> oldFileId/Name/Path/Permission/Type
    "enrich_systems": True,
    "system_columns": ["SystemSerialNumber", "EmailAddress", "PlatformID",
                       "SystemManufacturer", "SystemModel"],
    # Event description ("Name") looked up per ThreatEventID -> CEF name
    "enrich_event_names": True,
    "event_desc_language": "0409",   # 0409 = English
}


# --------------------------------------------------------------------------- helpers

SECRET_KEYS = ("password", "password_b64")
DEBUG_BODY_CHARS = 2000      # how much of each HTTP response is shown with --debug


def masked(cfg: dict) -> dict:
    """Copy of the config with passwords masked (for printing)."""
    return {k: ("***" if k in SECRET_KEYS and v else v)
            for k, v in cfg.items() if not k.startswith("_")}


def short(text: Any, limit: int = DEBUG_BODY_CHARS) -> str:
    text = str(text)
    return text if len(text) <= limit else "{} ... [{} more characters]".format(text[:limit], len(text) - limit)


def atomic_write_json(path: Path, data: Any) -> None:
    """Writes to <name>.json.part and renames atomically, so ArcSight (wildcard *.json)
    never reads a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".part")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    log.debug("Wrote %s (%d bytes, via %s)", path, path.stat().st_size, tmp.name)


def remove_file(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def load_state(path: Path) -> Dict[str, Any]:
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
        log.debug("Read state file %s: %s", path, state)
        return state
    log.debug("State file %s does not exist", path)
    return {}


class Lock:
    def __init__(self, path: Path, stale_seconds: int):
        self.path, self.stale = path, stale_seconds

    def __enter__(self):
        if self.path.exists() and time.time() - self.path.stat().st_mtime > self.stale:
            log.warning("Taking over stale lock file %s", self.path)
            remove_file(self.path)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            log.error("Another run is in progress (lock file %s exists). Aborting.", self.path)
            sys.exit(2)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        log.debug("Acquired lock file %s (pid %d)", self.path, os.getpid())
        return self

    def __exit__(self, *exc):
        remove_file(self.path)
        log.debug("Released lock file %s", self.path)


def epo_ipv4(val: Any) -> Any:
    """ePO stores IPv4 as a signed integer with an offset of 2^31 (e.g. 1177773067 = 198.51.100.11).
    Returns dotted notation; values that are already formatted are left untouched."""
    if isinstance(val, bool) or val is None:
        return val
    try:
        n = (int(val) + 2**31) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return val
    return ".".join(str((n >> s) & 0xFF) for s in (24, 16, 8, 0))


def epo_mac(val: Any) -> Any:
    """ePO stores MACs without separators ("005056a1b2c3") or with - / :.
    Returns ArcSight format "00:50:56:A1:B2:C3"; empty/invalid -> None (field left empty)."""
    if val is None:
        return None
    hexchars = re.sub(r"[^0-9A-Fa-f]", "", str(val))
    if len(hexchars) != 12 or set(hexchars) == {"0"}:
        return None
    return ":".join(hexchars[i:i + 2] for i in range(0, 12, 2)).upper()


def epo_bool(val: Any) -> Any:
    """ThreatHandled may arrive as true/false, 1/0 or "True"/"False" -> "true"/"false"."""
    if val is None or val == "":
        return None
    if isinstance(val, str):
        return "true" if val.strip().lower() in ("true", "1", "yes") else "false"
    return "true" if bool(val) else "false"


def normalize(row: dict, strip: bool) -> dict:
    """Decodes IPv4 fields, normalizes MAC addresses and ThreatHandled, and strips the
    table prefix ("EPOEvents.X" -> "X"). On a name clash "Table_X" is kept."""
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
        raise ValueError("Invalid boolean value: {!r} (use true or false)".format(val))
    return bool(val)


def tls_verify_setting(cfg: dict) -> Any:
    """Translates verify_tls/ca_cert into the requests 'verify' parameter:
        verify_tls=false              -> False (no verification, warning logged)
        verify_tls=true, ca_cert=""   -> True  (system CA store)
        verify_tls=true, ca_cert=file -> file  (verify against the given CA)
    Backward compatible: a path in verify_tls is treated as ca_cert."""
    verify = cfg.get("verify_tls", True)
    ca_cert = (cfg.get("ca_cert") or "").strip()
    if isinstance(verify, str) and ("/" in verify or "\\" in verify
                                    or verify.lower().endswith((".pem", ".crt", ".cer"))):
        ca_cert, verify = verify.strip(), True   # old format: path in verify_tls

    if not as_bool(verify):
        log.warning("TLS verification is DISABLED (verify_tls=false) - use for testing only.")
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:  # noqa: BLE001
            pass
        return False
    if ca_cert:
        if not Path(ca_cert).is_file():
            raise RuntimeError("ca_cert file does not exist: {}".format(ca_cert))
        log.info("Verifying TLS against CA file %s", ca_cert)
        return ca_cert
    log.debug("Verifying TLS against the system CA store (requests/certifi)")
    return True


class EpoClient:
    def __init__(self, cfg: dict, password: str):
        self.cfg = cfg
        self.base = cfg["epo_url"].rstrip("/") + "/remote/"
        self.url = self.base + "core.executeQuery"
        self.s = requests.Session()
        self.s.auth = (cfg["username"], password)
        # verify is passed with EVERY call: requests ignores Session.verify when
        # REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE is set in the environment.
        self.verify = cfg["_tls_verify"] if "_tls_verify" in cfg else tls_verify_setting(cfg)
        self.n = 0
        log.debug("EpoClient: base URL %s, user %s, TLS verify=%r", self.base, cfg["username"], self.verify)
        for var in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            if os.environ.get(var):
                log.debug("Environment variable %s=%s", var, os.environ[var])

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
            log.debug("HTTP #%d <- exception after %.2fs: %r", n, time.time() - t0, exc)
            raise
        if log.isEnabledFor(logging.DEBUG):
            log.debug("HTTP #%d <- %d %s, %.2fs, %d bytes, Content-Type: %s", n, resp.status_code,
                      resp.reason, time.time() - t0, len(resp.content), resp.headers.get("Content-Type"))
            log.debug("HTTP #%d    response headers: %s", n, dict(resp.headers))
            log.debug("HTTP #%d    response: %s", n, short(resp.text))
        return resp

    def query(self, params: dict) -> List[dict]:
        cfg, delay = self.cfg, 2.0
        for attempt in range(1, cfg["max_retries"] + 1):
            try:
                resp = self.get(self.url, params, cfg["timeout"])
            except (requests.ConnectionError, requests.Timeout) as exc:
                wait = delay
                log.debug("Attempt %d failed: %r", attempt, exc)
                log.warning("Network error (%s), attempt %d/%d, waiting %.0fs", exc, attempt, cfg["max_retries"], wait)
            else:
                if resp.status_code == 401:
                    raise RuntimeError("401 Unauthorized - check user/password and API permissions in ePO")
                if resp.status_code == 429 or resp.status_code >= 500:
                    ra = resp.headers.get("Retry-After")
                    wait = float(ra) if ra and ra.isdigit() else delay
                    log.warning("HTTP %d, attempt %d/%d, waiting %.0fs", resp.status_code, attempt, cfg["max_retries"], wait)
                else:
                    resp.raise_for_status()
                    return self._parse(resp.text)
            time.sleep(wait)
            delay = min(delay * 2, 300)
        raise RuntimeError(f"Gave up after {cfg['max_retries']} attempts")

    @staticmethod
    def _parse(text: str) -> List[dict]:
        # ePO responds "OK:\r\n<json>" on success, otherwise e.g. "Error 1 :\r\n<text>"
        body = text.strip()
        if not body.startswith("OK:"):
            raise RuntimeError("ePO returned an error: " + " ".join(body.split())[:500])
        data = json.loads(body[3:].strip() or "[]")
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected response from ePO: {str(data)[:300]}")
        log.debug("Response parsed: %d rows%s", len(data),
                  ", columns: " + ", ".join(data[0].keys()) if data and isinstance(data[0], dict) else "")
        return data


def dat_number(val: Any) -> Any:
    """AnalyzerDATVersion "10567.0000" -> 10567 (integer for cn2)."""
    m = re.match(r"\s*(\d+)", str(val)) if val not in (None, "") else None
    return int(m.group(1)) if m else None


class Enricher:
    """Adds fields that do not exist in EPOEvents:
       * the ePO server: ServerHostName, ServerIPAddress, LoadBalanceHttpPort (from config/DNS)
       * system properties per AgentGUID: SystemSerialNumber, EmailAddress, PlatformID, ... (EPOComputerProperties)
       * event description per ThreatEventID: Name (EPOEventFilterDesc)
       * AnalyzerDATVersionNum (integer part of AnalyzerDATVersion)
    The lookups are separate queries (no join), so no events are lost for systems that
    have been removed from ePO. If a lookup fails, a warning is logged and fetching continues."""

    def __init__(self, cfg: dict, client: "EpoClient"):
        self.cfg, self.client = cfg, client
        self.loaded = False
        self.static = {}          # type: Dict[str, Any]
        self.systems = {}         # type: Dict[str, Dict[str, Any]]
        self.event_names = {}     # type: Dict[str, str]
        self.system_cols_ok = []  # type: List[str]
        self.status = {}          # type: Dict[str, str]

    # -- loading -------------------------------------------------------------------
    def load(self) -> None:
        if self.loaded:
            return
        self.loaded = True
        self._load_static()
        if as_bool(self.cfg.get("enrich_systems", True)) and self.cfg.get("system_columns"):
            self._load_systems()
        else:
            self.status["systems"] = "disabled in config"
        if as_bool(self.cfg.get("enrich_event_names", True)):
            self._load_event_names()
        else:
            self.status["event_names"] = "disabled in config"

    def _load_static(self) -> None:
        url = urllib.parse.urlparse(self.cfg["epo_url"])
        host = (self.cfg.get("server_host_name") or url.hostname or "").strip()
        ip = (self.cfg.get("server_ip_address") or "").strip()
        if not ip and host:
            try:
                ip = socket.gethostbyname(host)
            except OSError as exc:
                log.warning("Could not resolve the IP of the ePO server %s (%s); ServerIPAddress left empty", host, exc)
        port = str(self.cfg.get("load_balance_http_port") or "").strip()
        if host:
            self.static["ServerHostName"] = host
        if ip:
            self.static["ServerIPAddress"] = ip
        if port:
            self.static["LoadBalanceHttpPort"] = int(port) if port.isdigit() else port
        self.status["server"] = ", ".join("{}={}".format(k, v) for k, v in self.static.items()) or "no values"
        log.debug("ePO server fields: %s", self.static)

    def _systems_query(self, cols: List[str]) -> List[dict]:
        sel = " ".join(["EPOLeafNode.AgentGUID"] + ["EPOComputerProperties." + c for c in cols])
        return self.client.query({"target": "EPOLeafNode", "select": "(select {})".format(sel),
                                  ":output": "json"})

    def _load_systems(self) -> None:
        cols = list(self.cfg["system_columns"])
        try:
            rows = self._systems_query(cols)
        except Exception as exc:  # noqa: BLE001
            log.debug("Systems lookup with all columns failed (%s), testing column by column", exc)
            ok_cols = []
            for col in cols:
                try:
                    self._systems_query([col])
                    ok_cols.append(col)
                except Exception as exc2:  # noqa: BLE001
                    log.warning("Column EPOComputerProperties.%s cannot be fetched and is skipped: %s",
                                col, short(exc2, 200))
            cols = ok_cols
            if not cols:
                self.status["systems"] = "FAILED (no columns could be fetched)"
                return
            try:
                rows = self._systems_query(cols)
            except Exception as exc3:  # noqa: BLE001
                log.warning("Systems lookup failed: %s", short(exc3, 300))
                self.status["systems"] = "FAILED: " + short(exc3, 200)
                return
        for r in rows:
            guid = str(r.get("EPOLeafNode.AgentGUID") or "").strip().lower()
            if not guid:
                continue
            vals = {c: r.get("EPOComputerProperties." + c) for c in cols}
            self.systems[guid] = {k: v for k, v in vals.items() if v not in (None, "")}
        self.system_cols_ok = cols
        self.status["systems"] = "{} systems, columns: {}".format(len(self.systems), ", ".join(cols))
        log.info("Systems lookup: %s", self.status["systems"])

    def _load_event_names(self) -> None:
        lang = str(self.cfg.get("event_desc_language") or "0409")
        params = {"target": "EPOEventFilterDesc",
                  "select": "(select EPOEventFilterDesc.EventId EPOEventFilterDesc.Name)",
                  "where": '(where (eq EPOEventFilterDesc.Language "{}"))'.format(lang),
                  ":output": "json"}
        try:
            rows = self.client.query(params)
        except Exception as exc:  # noqa: BLE001
            log.warning("Lookup of event descriptions (Name) failed, name falls back to "
                        "ThreatName: %s", short(exc, 300))
            self.status["event_names"] = "FAILED: " + short(exc, 200)
            return
        for r in rows:
            eid, name = r.get("EPOEventFilterDesc.EventId"), r.get("EPOEventFilterDesc.Name")
            if eid not in (None, "") and name:
                self.event_names[str(eid)] = name
        self.status["event_names"] = "{} event descriptions (language {})".format(len(self.event_names), lang)
        log.info("Event descriptions: %s", self.status["event_names"])

    # -- applying ------------------------------------------------------------------
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
        raise ValueError("mode must be 'events' or 'extended'")

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


# --------------------------------------------------------------------------- main logic

def run(cfg: dict, password: str, start_override: Optional[int]) -> int:
    out_dir, state_path = Path(cfg["output_dir"]), Path(cfg["state_file"])
    out_dir.mkdir(parents=True, exist_ok=True)

    state = load_state(state_path)
    if start_override is not None:
        cursor = start_override - 1          # "from" (inclusive) -> gt (start-1)
        log.info("Start index set manually: AutoID >= %d", start_override)
    elif "last_auto_id" in state:
        cursor = int(state["last_auto_id"])
        log.info("Continuing after AutoID %d (last run %s)", cursor, state.get("last_run"))
    else:
        cursor = int(cfg["start_index"]) - 1
        log.info("No state, starting from AutoID >= %d", cursor + 1)

    client = EpoClient(cfg, password)
    enricher = Enricher(cfg, client)
    id_key = "AutoID" if cfg["strip_table_prefix"] else "EPOEvents.AutoID"
    pages = total = 0

    log.debug("Output directory: %s, state file: %s, mode: %s, page_size: %s",
              out_dir.resolve(), state_path.resolve(), cfg["mode"], cfg["page_size"])
    while True:
        log.debug("--- Fetching page %d: AutoID > %d", pages + 1, cursor)
        rows = client.query(build_params(cfg, cursor))
        events = [normalize(r, cfg["strip_table_prefix"]) for r in rows]
        if rows and log.isEnabledFor(logging.DEBUG):
            log.debug("First row raw:        %s", short(json.dumps(rows[0], ensure_ascii=False)))
            log.debug("First row normalized: %s", short(json.dumps(events[0], ensure_ascii=False)))
        before = len(events)
        events = [e for e in events if int(e[id_key]) > cursor]
        if len(events) != before:
            log.debug("Filtered out %d rows with AutoID <= %d", before - len(events), cursor)
        events.sort(key=lambda e: int(e[id_key]))
        if not events:
            log.info("No more events.")
            break
        # duplicates (same AutoID) are removed
        seen, unique = set(), []
        for e in events:
            if e[id_key] not in seen:
                seen.add(e[id_key])
                unique.append(e)
        if len(unique) != len(events):
            log.debug("Removed %d duplicates", len(events) - len(unique))
        events = unique
        # enrichment (loaded only once there are new events)
        enricher.load()
        events = [enricher.apply(e, cfg["strip_table_prefix"]) for e in events]
        if log.isEnabledFor(logging.DEBUG):
            log.debug("First row enriched:   %s", short(json.dumps(events[0], ensure_ascii=False)))

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
        log.info("Page %d: AutoID %d-%d (%d events) -> %s", pages, first, last, len(events), fname.name)

        if last <= cursor:
            log.error("Cursor did not advance, aborting.")
            break
        log.debug("State updated: last_auto_id=%d", last)
        cursor = last
        if len(rows) < int(cfg["page_size"]):   # short page = everything fetched
            log.debug("Page had %d < page_size %s rows -> everything fetched", len(rows), cfg["page_size"])
            break
        if cfg["max_pages"] and pages >= cfg["max_pages"]:
            log.info("max_pages=%d reached, the rest is fetched on the next run.", cfg["max_pages"])
            break

    log.info("Done: %d events in %d files. Last AutoID: %d", total, pages, cursor)
    return total


def check_connection(cfg: dict, password: str) -> bool:
    """Tests step by step: network/TLS -> login -> query permission -> enrichment. Fetches no
    events and writes no files. Returns True if everything works."""
    client = EpoClient(cfg, password)
    timeout = min(int(cfg["timeout"]), 30)
    ok = True

    def result(name: str, passed: bool, detail: str) -> None:
        print("  [{}] {:<22} {}".format("OK  " if passed else "FAIL", name, detail))

    print("Checking connection to {} as '{}'".format(cfg["epo_url"], cfg["username"]))
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy:
        print("  (NOTE: HTTPS_PROXY={} is set; add the ePO host to NO_PROXY if it should not go via the proxy)".format(proxy))

    # 1-2. Network, TLS and login via core.help (harmless command that requires login)
    try:
        resp = client.get(client.base + "core.help", {":output": "json"}, timeout)
    except requests.exceptions.SSLError as exc:
        result("TLS certificate", False, "{}".format(exc))
        print("      -> Set ca_cert to the path of the CA certificate (.pem) that signed the ePO cert, "
              "or verify_tls to false to test without verification.")
        return False
    except requests.ConnectionError as exc:
        result("Network", False, "{}".format(exc))
        print("      -> Check epo_url (host and port, normally 8443), DNS and firewall.")
        return False
    except requests.Timeout:
        result("Network", False, "Timeout after {}s".format(timeout))
        return False
    result("Network + TLS", True, "HTTP {} from {}".format(resp.status_code, client.base))

    if resp.status_code == 401:
        result("Login", False, "401 Unauthorized - wrong user/password, or the account lacks API access")
        return False
    if resp.status_code != 200 or not resp.text.strip().startswith("OK:"):
        result("Login", False, "HTTP {}: {}".format(resp.status_code, resp.text.strip()[:200]))
        return False
    result("Login", True, "Basic auth accepted")

    # 3. Permission to run queries: latest event in each table
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
            print("      -> The account needs permission to run queries against Threat Events in ePO.")
            ok = False
            continue
        if rows:
            auto_id = rows[0].get("EPOEvents.AutoID")
            result("Query " + label, True, "Latest AutoID {} (received {})".format(
                auto_id, rows[0].get("EPOEvents.ReceivedUTC")))
            if target == "EPOEvents":
                latest = int(auto_id)
        else:
            result("Query " + label, True, "Permission OK, but the table is empty")

    # 4. Enrichment (ePO server, system properties, event descriptions)
    enricher = Enricher(cfg, client)
    enricher.load()
    result("ePO server fields", bool(enricher.static), enricher.status.get("server", ""))
    for key, label in (("systems", "System properties"), ("event_names", "Event descriptions")):
        st = enricher.status.get(key, "")
        result(label, not st.startswith("FAILED"), st)
    if enricher.status.get("systems", "").startswith("FAILED") or \
            enricher.status.get("event_names", "").startswith("FAILED"):
        print("      -> Enrichment is optional: fetching still works, but those fields stay empty.")
        print("         Check table/column names with: --describe EPOComputerProperties")

    # Status of the incremental fetch
    state = load_state(Path(cfg["state_file"]))
    if latest is not None:
        if "last_auto_id" in state:
            print("  State: last fetched AutoID {} -> approx. {} new events waiting".format(
                state["last_auto_id"], max(0, latest - int(state["last_auto_id"]))))
        else:
            print("  State: no previous fetch; the first run starts from AutoID {} "
                  "(start_index or --start-index)".format(cfg["start_index"]))
    print("Result: " + ("the connection works." if ok else "the connection has problems, see above."))
    return ok


def describe_table(cfg: dict, password: str, table: str) -> None:
    """--describe: shows columns and related tables of an ePO table (core.listTables)."""
    client = EpoClient(cfg, password)
    params = {"table": table} if table and table != "*" else {}
    resp = client.get(client.base + "core.listTables", params, min(int(cfg["timeout"]), 60))
    print(resp.text.strip())


CONFIG_CANDIDATES = ["epo_config.json", "epo_config.example.json", "config.example.json"]


def load_config(explicit: Optional[str]) -> Dict[str, Any]:
    """Starts from DEFAULT_CONFIG and applies the values from the config file.
    Without --config, CONFIG_CANDIDATES are searched (in order) in the script directory
    and the current directory. If none is found, the defaults in the script are used.
    Keys missing from the file get their default value."""
    cfg = dict(DEFAULT_CONFIG)
    path = None
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            log.error("The config file %s does not exist.", path)
            sys.exit(2)
    else:
        for d in (Path(__file__).resolve().parent, Path.cwd()):
            for name in CONFIG_CANDIDATES:
                log.debug("Looking for config: %s %s", d / name, "(found)" if (d / name).is_file() else "(not found)")
                if (d / name).is_file():
                    path = d / name
                    break
            if path:
                break

    if path is None:
        log.warning("No config file found (%s), using the defaults in the script.",
                    ", ".join(CONFIG_CANDIDATES))
        return cfg

    with open(str(path), encoding="utf-8") as fh:
        text = fh.read()
    try:
        user_cfg = json.loads(text)
    except ValueError as exc:
        lineno = getattr(exc, "lineno", None)
        log.error("Invalid JSON in %s: %s", path, exc)
        if lineno:
            line = text.splitlines()[lineno - 1]
            log.error("  line %d: %s", lineno, line)
            log.error("  %s^", " " * (len("line %d: " % lineno) + getattr(exc, "colno", 1) - 1))
            if "\\" in line:
                log.error("  Hint: backslashes must be doubled in JSON, e.g. \"DOMAIN\\\\user\" "
                          "or \"C:\\\\ArcSight\\\\ca.pem\" (or use / in paths).")
        sys.exit(2)
    if not isinstance(user_cfg, dict):
        log.error("%s must contain a JSON object { ... }", path)
        sys.exit(2)
    # Keys starting with "_" are comments and are silently ignored
    user_cfg = {k: v for k, v in user_cfg.items() if not k.startswith("_")}
    unknown = sorted(set(user_cfg) - set(DEFAULT_CONFIG))
    if unknown:
        log.warning("Unknown keys in %s are ignored: %s", path, ", ".join(unknown))
    cfg.update({k: v for k, v in user_cfg.items() if k in DEFAULT_CONFIG})
    log.info("Read config from %s", path)
    log.debug("Values from the file: %s", masked(user_cfg))
    cfg["_config_path"] = str(path)
    if (user_cfg.get("password") or user_cfg.get("password_b64")) and os.name == "posix":
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            log.warning("%s contains a password but is readable by others (permissions %o). "
                        "Run: chmod 600 %s", path, mode, path)
    return cfg


def encode_password(plain: str) -> str:
    return base64.b64encode(plain.encode("utf-8")).decode("ascii")


def decode_password(encoded: str) -> str:
    try:
        return base64.b64decode("".join(str(encoded).split()), validate=True).decode("utf-8")
    except (binascii.Error, ValueError) as exc:
        raise ValueError("password_b64 is not valid base64 ({}). Create the string with "
                         "--encode-password".format(exc))


def encode_password_interactive() -> None:
    """--encode-password: prompts for the password (twice) and prints the config line."""
    if sys.stdin.isatty():
        pw1 = getpass.getpass("Password to encode: ")
        pw2 = getpass.getpass("Repeat the password: ")
        if pw1 != pw2:
            print("The passwords do not match.", file=sys.stderr)
            sys.exit(2)
    else:  # e.g. echo -n 'secret' | ./epo_fetch_events.py --encode-password
        pw1 = sys.stdin.readline().rstrip("\r\n")
    if not pw1:
        print("Empty password.", file=sys.stderr)
        sys.exit(2)
    print('Add this line to the config file:\n\n  "password_b64": "{}",\n'.format(encode_password(pw1)))
    print("Protect the file: chmod 600 <config file>   (base64 is encoding, not encryption)")


def get_password(cfg: dict) -> str:
    """Environment variable -> config file "password_b64" -> ("password") -> interactive prompt."""
    env_name = cfg.get("password_env") or ""
    src = cfg.get("_config_path", "")
    if env_name and os.environ.get(env_name):
        log.info("Using password from environment variable %s", env_name)
        return os.environ[env_name]
    if cfg.get("password_b64"):
        try:
            pw = decode_password(cfg["password_b64"])
        except ValueError as exc:
            log.error("%s: %s", src, exc)
            sys.exit(2)
        log.info("Using password (password_b64) from config file %s", src)
        return pw
    if cfg.get("password"):
        log.warning("%s has the password in plain text (password). Switch to password_b64, "
                    "create the string with --encode-password", src)
        return str(cfg["password"])
    if sys.stdin.isatty():
        return getpass.getpass("Password for {}@ePO: ".format(cfg["username"]))
    log.error("Password missing: set \"password_b64\" in the config file (create with --encode-password) "
              "or set the environment variable %s", env_name)
    sys.exit(2)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Incrementally fetches Trellix ePO threat events into JSON files. "
                    "Version {}".format(__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Password (in this order):
  1. the environment variable in password_env (default EPO_PASSWORD)
  2. "password_b64" in the config file (base64 encoded)
  3. prompt in the terminal

Create the string for "password_b64":
  %(prog)s --encode-password
      prompts for the password and prints the config line (recommended)
  echo -n 'MyPassword' | base64
      Linux, do not forget -n (otherwise a newline is encoded as well)
  python3 -c "import base64,getpass; print(base64.b64encode(getpass.getpass().encode()).decode())"

Add it to the config file, e.g.:
  "password_b64": "TXlQYXNzd29yZA==",

NOTE: base64 only hides the password from casual view - protect the file with chmod 600.""")
    ap.add_argument("--version", action="version",
                    version="%(prog)s {} ({})".format(__version__, __author__))
    ap.add_argument("--config", help="JSON config file. Without it, "
                    + ", ".join(CONFIG_CANDIDATES) + " is searched next to the script / in the current directory")
    ap.add_argument("--start-index", type=int, help="Fetch from this AutoID (inclusive, ignores the state)")
    ap.add_argument("--check-connection", action="store_true",
                    help="Only test network, TLS, login, query permission and enrichment against ePO "
                         "(fetches no events, writes no files). Exit 0 = OK, 1 = error")
    ap.add_argument("--describe", metavar="TABLE",
                    help="Show columns and related tables of an ePO table, e.g. EPOEvents "
                         "or EPOComputerProperties (* = all tables)")
    ap.add_argument("--encode-password", action="store_true",
                    help="Create the base64 string for password_b64 in the config file and exit")
    ap.add_argument("--debug", "-v", "--verbose", dest="debug", action="store_true",
                    help="Print everything the script does: config, every HTTP call (URL, parameters, "
                         "status, response time, response), normalization, file and state writes. "
                         "Passwords are masked")
    args = ap.parse_args()

    if args.encode_password:
        encode_password_interactive()
        return

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout,
                            format="%(asctime)s %(levelname)-7s [%(funcName)s] %(message)s")
        logging.getLogger("urllib3").setLevel(logging.DEBUG)   # connections, TLS, proxy
        log.debug("Debug mode. epo_fetch_events %s, Python %s, requests %s, script %s",
                  __version__, sys.version.split()[0], requests.__version__, Path(__file__).resolve())
        log.debug("Arguments: %s", vars(args))
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    cfg = load_config(args.config)
    try:
        cfg["_tls_verify"] = tls_verify_setting(cfg)
    except (ValueError, RuntimeError) as exc:
        log.error("TLS setting: %s", exc)
        sys.exit(2)

    log.debug("Effective config (defaults + file): %s", masked(cfg))
    password = get_password(cfg)
    log.debug("Password loaded (%d characters)", len(password))

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
            log.exception("The run failed; the state points to the last successful page.")
            sys.exit(1)


if __name__ == "__main__":
    main()
