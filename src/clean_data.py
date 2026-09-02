#!/usr/bin/env python3
"""Nettoyage et consolidation des données du TP3.

Principe de prudence :
- on supprime uniquement les doublons strictement identiques ;
- on ne supprime pas une ligne parce qu'elle contient une anomalie ;
- les anomalies sont conservées dans quality_flags ;
- les valeurs originales sensibles aux transformations sont conservées
  dans des colonnes *_raw lorsque cela apporte de la traçabilité.
"""

from pathlib import Path
import csv
import re
import ipaddress
from collections import Counter
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"

DATE_FORMATS = [
    ("iso_space", "%Y-%m-%d %H:%M:%S"),
    ("fr_minute", "%d/%m/%Y %H:%M"),
    ("iso_z", "%Y-%m-%dT%H:%M:%SZ"),
]

def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def write_csv(path, rows, fieldnames=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

def deduplicate_exact(rows):
    seen = set()
    out = []
    for row in rows:
        key = tuple((k, row.get(k, "")) for k in row.keys())
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out

def normalize_timestamp(value):
    value = (value or "").strip()
    for name, fmt in DATE_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S"), name
        except ValueError:
            pass
    return "", "invalid"

def normalize_severity(value):
    v = (value or "").strip().upper()
    aliases = {
        "LOW": "LOW",
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    }
    return aliases.get(v, v)

def normalize_auth_result(value):
    v = (value or "").strip().upper()
    if v in {"SUCCESS"}:
        return "SUCCESS"
    if v in {"FAILED", "FAILURE"}:
        return "FAILURE"
    return v

def validate_ip(value):
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return ""

def flags_to_text(flags):
    return ";".join(sorted(set(f for f in flags if f)))

def clean_users(rows):
    rows = deduplicate_exact(rows)
    out = []
    for r in rows:
        flags = []
        if not re.fullmatch(r"U\d{4}", r["user_id"]):
            flags.append("INVALID_USER_ID")
        nr = dict(r)
        nr["quality_flags"] = flags_to_text(flags)
        out.append(nr)
    return out

def clean_assets(rows):
    rows = deduplicate_exact(rows)
    host_counts = Counter(r["hostname"] for r in rows if r["hostname"])
    out = []
    for r in rows:
        flags = []
        if not re.fullmatch(r"D\d{4}", r["device_id"]):
            flags.append("INVALID_DEVICE_ID")
        if not r["owner"].strip():
            flags.append("MISSING_OWNER")
        if not r["criticality"].strip():
            flags.append("MISSING_CRITICALITY")
        if r["hostname"] and host_counts[r["hostname"]] > 1:
            flags.append("DUPLICATE_HOSTNAME")
        nr = dict(r)
        nr["criticality_raw"] = r["criticality"]
        nr["criticality"] = normalize_severity(r["criticality"]) if r["criticality"] else ""
        nr["quality_flags"] = flags_to_text(flags)
        out.append(nr)
    return out

def clean_auth(rows, user_ids, device_ids):
    rows = deduplicate_exact(rows)
    out = []
    for r in rows:
        flags = []
        ts, ts_format = normalize_timestamp(r["timestamp"])
        if not ts:
            flags.append("INVALID_TIMESTAMP")
        uid = r["user_id"].strip()
        did = r["device_id"].strip()
        if not uid:
            flags.append("MISSING_USER_ID")
        elif uid not in user_ids:
            flags.append("UNKNOWN_USER_REF")
        if did and did not in device_ids:
            flags.append("UNKNOWN_DEVICE_REF")
        ip_norm = validate_ip(r["src_ip"])
        if r["src_ip"].strip() and not ip_norm:
            flags.append("INVALID_SRC_IP")
        nr = dict(r)
        nr["timestamp_raw"] = r["timestamp"]
        nr["timestamp"] = ts
        nr["timestamp_format_raw"] = ts_format
        nr["src_ip_raw"] = r["src_ip"]
        nr["src_ip"] = ip_norm
        nr["authentication_result_raw"] = r["authentication_result"]
        nr["authentication_result"] = normalize_auth_result(r["authentication_result"])
        nr["severity_raw"] = r["severity"]
        nr["severity"] = normalize_severity(r["severity"])
        nr["quality_flags"] = flags_to_text(flags)
        out.append(nr)
    return out

def clean_edr(rows, user_ids, device_ids):
    rows = deduplicate_exact(rows)
    out = []
    for r in rows:
        flags = []
        ts, ts_format = normalize_timestamp(r["timestamp"])
        if not ts:
            flags.append("INVALID_TIMESTAMP")
        uid = r["user_id"].strip()
        did = r["device_id"].strip()
        if uid and uid not in user_ids:
            flags.append("UNKNOWN_USER_REF")
        if did and did not in device_ids:
            flags.append("UNKNOWN_DEVICE_REF")
        if not r["analyst_decision"].strip():
            flags.append("MISSING_ANALYST_DECISION")
        nr = dict(r)
        nr["timestamp_raw"] = r["timestamp"]
        nr["timestamp"] = ts
        nr["timestamp_format_raw"] = ts_format
        nr["severity_raw"] = r["severity"]
        nr["severity"] = normalize_severity(r["severity"])
        nr["quality_flags"] = flags_to_text(flags)
        out.append(nr)
    return out

def consolidate(auth, edr, users, assets):
    users_by_id = {r["user_id"]: r for r in users}
    assets_by_id = {r["device_id"]: r for r in assets}
    out = []

    def context(uid, did):
        u = users_by_id.get(uid, {})
        a = assets_by_id.get(did, {})
        return {
            "user_department": u.get("department", ""),
            "user_role": u.get("role", ""),
            "employment_status": u.get("employment_status", ""),
            "privileged_account": u.get("privileged_account", ""),
            "user_location": u.get("location", ""),
            "asset_hostname": a.get("hostname", ""),
            "asset_type": a.get("asset_type", ""),
            "asset_department": a.get("department", ""),
            "asset_owner": a.get("owner", ""),
            "asset_criticality": a.get("criticality", ""),
            "operating_system": a.get("operating_system", ""),
        }

    for r in auth:
        row = {
            "event_id": r["event_id"],
            "timestamp": r["timestamp"],
            "source": "AUTHENTICATION",
            "event_type": r["event_type"],
            "severity": r["severity"],
            "user_id": r["user_id"],
            "device_id": r["device_id"],
            "src_ip": r["src_ip"],
            "event_location": r["location"],
            "authentication_result": r["authentication_result"],
            "process_name": "",
            "alert_status": "",
            "analyst_decision": "",
            "quality_flags": r["quality_flags"],
        }
        row.update(context(r["user_id"], r["device_id"]))
        out.append(row)

    for r in edr:
        row = {
            "event_id": r["alert_id"],
            "timestamp": r["timestamp"],
            "source": "EDR",
            "event_type": r["alert_type"],
            "severity": r["severity"],
            "user_id": r["user_id"],
            "device_id": r["device_id"],
            "src_ip": "",
            "event_location": "",
            "authentication_result": "",
            "process_name": r["process_name"],
            "alert_status": r["status"],
            "analyst_decision": r["analyst_decision"],
            "quality_flags": r["quality_flags"],
        }
        row.update(context(r["user_id"], r["device_id"]))
        out.append(row)

    out.sort(key=lambda x: (x["timestamp"] or "9999-99-99 99:99:99", x["source"], x["event_id"]))
    return out

def quality_summary(raw_auth, raw_edr, raw_assets, raw_users, clean_auth_rows, clean_edr_rows, clean_assets_rows, clean_users_rows):
    def duplicate_extras(rows):
        seen = set()
        d = 0
        for r in rows:
            k = tuple(r.items())
            if k in seen:
                d += 1
            else:
                seen.add(k)
        return d

    rows = []
    for source, raw, clean in [
        ("authentication_logs.csv", raw_auth, clean_auth_rows),
        ("edr_alerts.csv", raw_edr, clean_edr_rows),
        ("assets.csv", raw_assets, clean_assets_rows),
        ("users.csv", raw_users, clean_users_rows),
    ]:
        flag_counts = Counter()
        for r in clean:
            for f in (r.get("quality_flags") or "").split(";"):
                if f:
                    flag_counts[f] += 1
        rows.append({
            "source": source,
            "raw_rows": len(raw),
            "clean_rows": len(clean),
            "exact_duplicates_removed": duplicate_extras(raw),
            "rows_with_quality_flag": sum(bool(r.get("quality_flags")) for r in clean),
            "quality_flags_detail": " | ".join(f"{k}:{v}" for k, v in sorted(flag_counts.items())),
        })
    return rows

def main():
    raw_auth = read_csv(RAW / "authentication_logs.csv")
    raw_edr = read_csv(RAW / "edr_alerts.csv")
    raw_assets = read_csv(RAW / "assets.csv")
    raw_users = read_csv(RAW / "users.csv")

    users = clean_users(raw_users)
    assets = clean_assets(raw_assets)
    user_ids = {r["user_id"] for r in users}
    device_ids = {r["device_id"] for r in assets}
    auth = clean_auth(raw_auth, user_ids, device_ids)
    edr = clean_edr(raw_edr, user_ids, device_ids)

    write_csv(PROCESSED / "users_clean.csv", users)
    write_csv(PROCESSED / "assets_clean.csv", assets)
    write_csv(PROCESSED / "authentication_logs_clean.csv", auth)
    write_csv(PROCESSED / "edr_alerts_clean.csv", edr)

    consolidated = consolidate(auth, edr, users, assets)
    write_csv(PROCESSED / "security_events_consolidated.csv", consolidated)

    summary = quality_summary(raw_auth, raw_edr, raw_assets, raw_users, auth, edr, assets, users)
    write_csv(PROCESSED / "data_quality_summary.csv", summary)

    print("Nettoyage terminé")
    for r in summary:
        print(r)

if __name__ == "__main__":
    main()
