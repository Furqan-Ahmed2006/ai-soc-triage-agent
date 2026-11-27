import json
import re
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB limit
MAX_RECORDS = 10_000
SESSIONS_DIR = Path(__file__).with_name("session_stores")

EVENT_TYPE_ALIASES = {
    "failed_login": "failed_login",
    "authentication_failure": "failed_login",
    "auth_fail": "failed_login",
    "login_failed": "failed_login",
    "invalid_password": "failed_login",
    "successful_login": "successful_login",
    "authentication_success": "successful_login",
    "auth_success": "successful_login",
    "login_success": "successful_login",
    "privilege_escalation": "privilege_escalation",
    "sudo_exec": "privilege_escalation",
    "api_error": "api_error",
    "unauthorized_access": "unauthorized_access",
    "port_scan": "port_scan",
    "outbound_connection": "outbound_connection",
}


def _strip_control_chars(value: Any, max_len: int = 512) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len] if text else None


def _normalize_timestamp(raw_ts: Any) -> Tuple[Optional[str], bool]:
    if raw_ts is None or str(raw_ts).strip() == "":
        return None, False
    ts_str = str(raw_ts).strip()
    if ts_str.isdigit():
        try:
            val = int(ts_str)
            if val > 10**12:
                val = val // 1000
            return datetime.utcfromtimestamp(val).isoformat() + "Z", True
        except Exception:
            return None, False

    candidate = ts_str.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(candidate)
        return dt.isoformat(), True
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
            try:
                return datetime.strptime(ts_str, fmt).isoformat(), True
            except ValueError:
                continue
    return None, False


def _normalize_event_type(raw_val: Any) -> str:
    cleaned = (_strip_control_chars(raw_val, 128) or "unknown_event").lower()
    cleaned = cleaned.replace(" ", "_").replace("-", "_")
    return EVENT_TYPE_ALIASES.get(cleaned, cleaned)


def normalize_record(
    raw: Dict[str, Any],
    index: int,
    source_category: str,
    filename: str,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    warnings: List[str] = []
    if not isinstance(raw, dict):
        return None, [f"Record #{index}: Expected JSON object, got {type(raw).__name__}."]

    raw_event = raw.get("event_type") or raw.get("event") or raw.get("action") or raw.get("type")
    if not raw_event:
        warnings.append(f"Record #{index}: Missing event type field; defaulted to 'unknown_event'.")

    raw_ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("ip") or raw.get("client_ip")
    raw_user = raw.get("username") or raw.get("user") or raw.get("account") or raw.get("actor")
    raw_host = raw.get("hostname") or raw.get("host") or raw.get("target") or raw.get("service")
    raw_ts = raw.get("timestamp") or raw.get("time") or raw.get("@timestamp") or raw.get("created_at")

    norm_ts, ts_valid = _normalize_timestamp(raw_ts)
    if raw_ts is not None and not ts_valid:
        warnings.append(f"Record #{index}: Invalid timestamp '{raw_ts}'; stored as null.")
    elif raw_ts is None:
        warnings.append(f"Record #{index}: Missing timestamp.")

    source_ip = _strip_control_chars(raw_ip, 64)
    username = _strip_control_chars(raw_user, 128)
    hostname = _strip_control_chars(raw_host, 128)

    if not source_ip and not username:
        warnings.append(f"Record #{index}: Missing both source_ip and username.")

    normalized = {
        "event_id": f"EVT-{index:05d}",
        "event_type": _normalize_event_type(raw_event),
        "source_ip": source_ip,
        "username": username,
        "hostname": hostname,
        "timestamp": norm_ts,
        "source": "uploaded_file",
        "source_category": source_category,
        "filename": filename,
        "raw_json": json.dumps(raw, default=str)[:2000],
    }
    return normalized, warnings


def get_session_db_path(session_id: str) -> Path:
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "", session_id)
    if not safe_id:
        raise ValueError("Invalid session_id.")
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return SESSIONS_DIR / f"{safe_id}.db"


def delete_session_store(session_id: str) -> bool:
    try:
        db_path = get_session_db_path(session_id)
        if db_path.exists():
            db_path.unlink()
            return True
    except Exception:
        pass
    return False


def ingest_uploaded_logs(
    file_bytes: bytes,
    filename: str,
    source_category: str = "Authentication logs",
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Validates, parses, normalizes, and stores uploaded .json/.jsonl logs in an isolated SQLite DB."""
    if not file_bytes:
        raise ValueError("Uploaded file is empty.")
    if len(file_bytes) > MAX_FILE_BYTES:
        raise ValueError(f"File exceeds maximum allowed size of {MAX_FILE_BYTES // (1024 * 1024)} MB.")

    lower_name = filename.lower().strip()
    if not (lower_name.endswith(".json") or lower_name.endswith(".jsonl")):
        raise ValueError("Unsupported file format. Only .json and .jsonl files are accepted.")

    try:
        text = file_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("File must be valid UTF-8 encoded text.") from exc

    raw_records: List[Any] = []
    malformed_errors: List[str] = []

    if lower_name.endswith(".jsonl"):
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw_records.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                malformed_errors.append(f"Line {line_no}: Malformed JSON ({exc.msg}).")
    else:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON file: {exc.msg} at line {exc.lineno}.") from exc

        if isinstance(parsed, list):
            raw_records = parsed
        elif isinstance(parsed, dict) and isinstance(parsed.get("events"), list):
            raw_records = parsed["events"]
        elif isinstance(parsed, dict):
            raw_records = [parsed]
        else:
            raise ValueError("JSON root must be an object, a list of objects, or {'events': [...]}.")

    if not raw_records and malformed_errors:
        raise ValueError(f"No valid records found. Errors: {malformed_errors[:5]}")
    if len(raw_records) > MAX_RECORDS:
        raise ValueError(f"Record count ({len(raw_records)}) exceeds maximum limit ({MAX_RECORDS}).")

    normalized_rows: List[Dict[str, Any]] = []
    field_warnings: List[str] = []

    for idx, item in enumerate(raw_records, start=1):
        norm, warns = normalize_record(item, idx, source_category, filename)
        field_warnings.extend(warns)
        if norm is not None:
            normalized_rows.append(norm)
        else:
            malformed_errors.extend(warns)

    if not normalized_rows:
        raise ValueError("File contained zero valid log event objects after normalization.")

    sid = session_id or f"sess_{uuid.uuid4().hex[:12]}"
    db_path = get_session_db_path(sid)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            """
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT,
                source_ip TEXT,
                username TEXT,
                hostname TEXT,
                timestamp TEXT,
                source TEXT,
                source_category TEXT,
                filename TEXT,
                raw_json TEXT
            )
            """
        )
        conn.executemany(
            """
            INSERT INTO events (
                event_id, event_type, source_ip, username, hostname,
                timestamp, source, source_category, filename, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    r["event_id"],
                    r["event_type"],
                    r["source_ip"],
                    r["username"],
                    r["hostname"],
                    r["timestamp"],
                    r["source"],
                    r["source_category"],
                    r["filename"],
                    r["raw_json"],
                )
                for r in normalized_rows
            ],
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "session_id": sid,
        "filename": filename,
        "source_category": source_category,
        "total_raw_items": len(raw_records) + len(malformed_errors),
        "valid_events_stored": len(normalized_rows),
        "malformed_count": len(malformed_errors),
        "warning_count": len(field_warnings),
        "malformed_samples": malformed_errors[:10],
        "warning_samples": field_warnings[:10],
    }