import json
import sqlite3
from typing import Any, Dict, List, Optional

from mcp.server.mcpserver import MCPServer

from guardrails import neutralize_untrusted_log_payload
from log_processor import get_session_db_path
from risk_engine import calculate_deterministic_risk

mcp = MCPServer("Sentinel-LogiX-MCP-Server")


def _query_session_db(session_id: str, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    db_path = get_session_db_path(session_id)
    if not db_path.exists():
        raise FileNotFoundError(f"No dataset found for session '{session_id}'. Please upload a log file first.")
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _format_tool_output(payload: Dict[str, Any]) -> str:
    return neutralize_untrusted_log_payload(json.dumps(payload, indent=2, default=str), max_chars=5000)


@mcp.tool()
def search_security_events(
    session_id: str,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    limit: int = 50,
) -> str:
    """Search normalized security events in the uploaded session dataset using optional filters."""
    clauses = ["1=1"]
    params: List[Any] = []
    if event_type:
        clauses.append("LOWER(event_type) = LOWER(?)")
        params.append(event_type.strip())
    if source_ip:
        clauses.append("source_ip = ?")
        params.append(source_ip.strip())
    if username:
        clauses.append("LOWER(username) = LOWER(?)")
        params.append(username.strip())
    if hostname:
        clauses.append("LOWER(hostname) = LOWER(?)")
        params.append(hostname.strip())

    safe_limit = max(1, min(int(limit), 100))
    total_row = _query_session_db(session_id, "SELECT COUNT(*) AS cnt FROM events")[0]
    sql = (
        f"SELECT event_id, event_type, source_ip, username, hostname, timestamp, source_category "
        f"FROM events WHERE {' AND '.join(clauses)} ORDER BY timestamp ASC LIMIT ?"
    )
    params.append(safe_limit)
    rows = _query_session_db(session_id, sql, tuple(params))

    return _format_tool_output({
        "dataset_total_events": total_row["cnt"],
        "matched_count": len(rows),
        "status": "ok" if rows else "telemetry_gap",
        "events": rows,
    })


@mcp.tool()
def get_event_details(session_id: str, event_id: str) -> str:
    """Retrieve complete normalized and raw details for a specific event_id."""
    rows = _query_session_db(
        session_id,
        "SELECT * FROM events WHERE UPPER(event_id) = UPPER(?)",
        (event_id.strip(),),
    )
    if not rows:
        return _format_tool_output({
            "found": False,
            "status": "telemetry_gap",
            "reason": f"Event '{event_id}' does not exist in uploaded dataset.",
        })
    return _format_tool_output({"found": True, "status": "ok", "event": rows[0]})


@mcp.tool()
def get_ip_activity(session_id: str, source_ip: str) -> str:
    """Investigate all events, targeted accounts, and event types associated with a specific source IP."""
    rows = _query_session_db(
        session_id,
        "SELECT event_id, event_type, source_ip, username, hostname, timestamp FROM events "
        "WHERE source_ip = ? ORDER BY timestamp ASC",
        (source_ip.strip(),),
    )
    if not rows:
        return _format_tool_output({
            "source_ip": source_ip,
            "found": False,
            "status": "telemetry_gap",
            "reason": f"No events recorded for IP '{source_ip}' in uploaded logs.",
        })
    targeted_users = sorted({r["username"] for r in rows if r.get("username")})
    event_types = sorted({r["event_type"] for r in rows if r.get("event_type")})
    return _format_tool_output({
        "source_ip": source_ip,
        "found": True,
        "event_count": len(rows),
        "targeted_users": targeted_users,
        "event_types": event_types,
        "timeline": rows,
    })


@mcp.tool()
def get_user_activity(session_id: str, username: str) -> str:
    """Retrieve all events, source IPs, and hosts associated with a specific username."""
    rows = _query_session_db(
        session_id,
        "SELECT event_id, event_type, source_ip, username, hostname, timestamp FROM events "
        "WHERE LOWER(username) = LOWER(?) ORDER BY timestamp ASC",
        (username.strip(),),
    )
    if not rows:
        return _format_tool_output({
            "username": username,
            "found": False,
            "status": "telemetry_gap",
            "reason": f"No events recorded for user '{username}' in uploaded logs.",
        })
    source_ips = sorted({r["source_ip"] for r in rows if r.get("source_ip")})
    return _format_tool_output({
        "username": username,
        "found": True,
        "event_count": len(rows),
        "source_ips": source_ips,
        "timeline": rows,
    })


@mcp.tool()
def correlate_security_events(
    session_id: str,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
) -> str:
    """Correlate events across IP and username to reconstruct an ordered attack/activity timeline."""
    if not source_ip and not username:
        rows = _query_session_db(
            session_id,
            "SELECT event_id, event_type, source_ip, username, hostname, timestamp FROM events "
            "ORDER BY timestamp ASC LIMIT 100",
        )
    else:
        clauses = []
        params: List[Any] = []
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip.strip())
        if username:
            clauses.append("LOWER(username) = LOWER(?)")
            params.append(username.strip())
        rows = _query_session_db(
            session_id,
            f"SELECT event_id, event_type, source_ip, username, hostname, timestamp FROM events "
            f"WHERE {' OR '.join(clauses)} ORDER BY timestamp ASC LIMIT 100",
            tuple(params),
        )

    if not rows:
        return _format_tool_output({
            "correlated_count": 0,
            "status": "telemetry_gap",
            "reason": "No matching events found to build correlation timeline.",
        })

    failed_count = sum(1 for r in rows if r.get("event_type") == "failed_login")
    success_count = sum(1 for r in rows if r.get("event_type") == "successful_login")
    return _format_tool_output({
        "correlated_count": len(rows),
        "failed_login_count": failed_count,
        "successful_login_count": success_count,
        "failure_then_success_pattern": failed_count >= 2 and success_count >= 1,
        "ordered_timeline": rows,
    })


@mcp.tool()
def evaluate_risk(
    session_id: str,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
) -> str:
    """Calculate deterministic weighted risk score and IOC evaluation from uploaded evidence."""
    clauses = ["1=1"]
    params: List[Any] = []
    if source_ip:
        clauses.append("source_ip = ?")
        params.append(source_ip.strip())
    if username:
        clauses.append("LOWER(username) = LOWER(?)")
        params.append(username.strip())

    rows = _query_session_db(
        session_id,
        f"SELECT * FROM events WHERE {' AND '.join(clauses)} ORDER BY timestamp ASC",
        tuple(params),
    )
    assessment = calculate_deterministic_risk(rows)
    return _format_tool_output({
        "analyzed_events": len(rows),
        "risk_assessment": assessment,
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")