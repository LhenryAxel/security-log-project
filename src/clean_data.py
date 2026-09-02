#!/usr/bin/env python3

from pathlib import Path
import csv
import re
import ipaddress
from collections import Counter
from datetime import datetime


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"

# Les données contiennent plusieurs formats de date, on accepte les principaux
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
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)


def deduplicate_exact(rows):
    """Supprime uniquement les lignes totalement identiques."""
    seen = set()
    output = []

    for row in rows:
        key = tuple((k, row.get(k, "")) for k in row.keys())

        if key not in seen:
            seen.add(key)
            output.append(row)

    return output


def normalize_timestamp(value):
    value = (value or "").strip()

    # On essaie chaque format connu jusqu'à en trouver un qui fonctionne
    for name, fmt in DATE_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S"), name
        except ValueError:
            pass

    return "", "invalid"


def normalize_severity(value):
    value = (value or "").strip().upper()

    aliases = {
        "LOW": "LOW",
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    }

    return aliases.get(value, value)


def clean_users(rows):
    rows = deduplicate_exact(rows)
    output = []

    for row in rows:
        flags = []

        if not re.fullmatch(r"U\d{4}", row["user_id"]):
            flags.append("INVALID_USER_ID")

        new_row = dict(row)
        new_row["quality_flags"] = flags_to_text(flags)

        output.append(new_row)

    return output


def clean_assets(rows):
    rows = deduplicate_exact(rows)

    # Permet de repérer si plusieurs machines ont le même hostname
    hostname_counts = Counter(
        row["hostname"]
        for row in rows
        if row["hostname"]
    )

    output = []

    for row in rows:
        flags = []

        if not re.fullmatch(r"D\d{4}", row["device_id"]):
            flags.append("INVALID_DEVICE_ID")

        if not row["owner"].strip():
            flags.append("MISSING_OWNER")

        if not row["criticality"].strip():
            flags.append("MISSING_CRITICALITY")

        if row["hostname"] and hostname_counts[row["hostname"]] > 1:
            flags.append("DUPLICATE_HOSTNAME")

        new_row = dict(row)

        # On garde aussi la valeur originale pour pouvoir vérifier les transformations
        new_row["criticality_raw"] = row["criticality"]
        new_row["criticality"] = (
            normalize_severity(row["criticality"])
            if row["criticality"]
            else ""
        )

        new_row["quality_flags"] = flags_to_text(flags)

        output.append(new_row)

    return output


def clean_auth(rows, user_ids, device_ids):
    rows = deduplicate_exact(rows)
    output = []

    for row in rows:
        flags = []

        timestamp, timestamp_format = normalize_timestamp(row["timestamp"])

        if not timestamp:
            flags.append("INVALID_TIMESTAMP")

        user_id = row["user_id"].strip()
        device_id = row["device_id"].strip()

        # Vérification des références avec users.csv et assets.csv
        if not user_id:
            flags.append("MISSING_USER_ID")
        elif user_id not in user_ids:
            flags.append("UNKNOWN_USER_REF")

        if device_id and device_id not in device_ids:
            flags.append("UNKNOWN_DEVICE_REF")

        normalized_ip = validate_ip(row["src_ip"])

        if row["src_ip"].strip() and not normalized_ip:
            flags.append("INVALID_SRC_IP")

        new_row = dict(row)

        # Les colonnes *_raw gardent les données avant nettoyage
        new_row["timestamp_raw"] = row["timestamp"]
        new_row["timestamp"] = timestamp
        new_row["timestamp_format_raw"] = timestamp_format

        new_row["src_ip_raw"] = row["src_ip"]
        new_row["src_ip"] = normalized_ip

        new_row["authentication_result_raw"] = row["authentication_result"]
        new_row["authentication_result"] = normalize_auth_result(
            row["authentication_result"]
        )

        new_row["severity_raw"] = row["severity"]
        new_row["severity"] = normalize_severity(row["severity"])

        new_row["quality_flags"] = flags_to_text(flags)

        output.append(new_row)

    return output


def clean_edr(rows, user_ids, device_ids):
    rows = deduplicate_exact(rows)
    output = []

    for row in rows:
        flags = []

        timestamp, timestamp_format = normalize_timestamp(row["timestamp"])

        if not timestamp:
            flags.append("INVALID_TIMESTAMP")

        user_id = row["user_id"].strip()
        device_id = row["device_id"].strip()

        if user_id and user_id not in user_ids:
            flags.append("UNKNOWN_USER_REF")

        if device_id and device_id not in device_ids:
            flags.append("UNKNOWN_DEVICE_REF")

        # Une décision vide signifie simplement que l'alerte n'a pas encore été traitée
        if not row["analyst_decision"].strip():
            flags.append("NOT_REVIEWED")
        new_row = dict(row)

        new_row["timestamp_raw"] = row["timestamp"]
        new_row["timestamp"] = timestamp
        new_row["timestamp_format_raw"] = timestamp_format

        new_row["severity_raw"] = row["severity"]
        new_row["severity"] = normalize_severity(row["severity"])

        new_row["quality_flags"] = flags_to_text(flags)

        output.append(new_row)

    return output



def normalize_auth_result(value):
    value = (value or "").strip().upper()

    if value == "SUCCESS":
        return "SUCCESS"

    if value in {"FAILED", "FAILURE"}:
        return "FAILURE"

    return value


def validate_ip(value):
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return ""


def flags_to_text(flags):
    """Regroupe les problèmes détectés dans une seule colonne."""
    return ";".join(sorted(set(flag for flag in flags if flag)))

def consolidate(auth, edr, users, assets):
    """Regroupe les événements AUTH et EDR dans un format commun."""

    users_by_id = {
        row["user_id"]: row
        for row in users
    }

    assets_by_id = {
        row["device_id"]: row
        for row in assets
    }

    output = []

    def get_context(user_id, device_id):
        user = users_by_id.get(user_id, {})
        asset = assets_by_id.get(device_id, {})

        return {
            "user_department": user.get("department", ""),
            "user_role": user.get("role", ""),
            "employment_status": user.get("employment_status", ""),
            "privileged_account": user.get("privileged_account", ""),
            "user_location": user.get("location", ""),

            "asset_hostname": asset.get("hostname", ""),
            "asset_type": asset.get("asset_type", ""),
            "asset_department": asset.get("department", ""),
            "asset_owner": asset.get("owner", ""),
            "asset_criticality": asset.get("criticality", ""),
            "operating_system": asset.get("operating_system", ""),
        }

    for row in auth:
        event = {
            "event_id": row["event_id"],
            "timestamp": row["timestamp"],
            "source": "AUTHENTICATION",
            "event_type": row["event_type"],
            "severity": row["severity"],
            "user_id": row["user_id"],
            "device_id": row["device_id"],
            "src_ip": row["src_ip"],
            "event_location": row["location"],
            "authentication_result": row["authentication_result"],

            # Ces champs n'existent pas pour une authentification
            "process_name": "",
            "alert_status": "",
            "analyst_decision": "",

            "quality_flags": row["quality_flags"],
        }

        event.update(
            get_context(
                row["user_id"],
                row["device_id"]
            )
        )

        output.append(event)

    for row in edr:
        event = {
            "event_id": row["alert_id"],
            "timestamp": row["timestamp"],
            "source": "EDR",
            "event_type": row["alert_type"],
            "severity": row["severity"],
            "user_id": row["user_id"],
            "device_id": row["device_id"],

            # Ces champs n'existent pas dans les événements EDR
            "src_ip": "",
            "event_location": "",
            "authentication_result": "",

            "process_name": row["process_name"],
            "alert_status": row["status"],
            "analyst_decision": row["analyst_decision"],
            "quality_flags": row["quality_flags"],
        }

        event.update(
            get_context(
                row["user_id"],
                row["device_id"]
            )
        )

        output.append(event)

    # On trie les événements dans l'ordre chronologique
    output.sort(
        key=lambda row: (
            row["timestamp"] or "9999-99-99 99:99:99",
            row["source"],
            row["event_id"]
        )
    )

    return output


def quality_summary(
    raw_auth,
    raw_edr,
    raw_assets,
    raw_users,
    clean_auth_rows,
    clean_edr_rows,
    clean_assets_rows,
    clean_users_rows
):
    """Produit un résumé des problèmes trouvés dans chaque fichier."""

    def count_duplicates(rows):
        seen = set()
        duplicates = 0

        for row in rows:
            key = tuple(row.items())

            if key in seen:
                duplicates += 1
            else:
                seen.add(key)

        return duplicates

    summary = []

    datasets = [
        ("authentication_logs.csv", raw_auth, clean_auth_rows),
        ("edr_alerts.csv", raw_edr, clean_edr_rows),
        ("assets.csv", raw_assets, clean_assets_rows),
        ("users.csv", raw_users, clean_users_rows),
    ]

    for source, raw_rows, clean_rows in datasets:
        flag_counts = Counter()

        for row in clean_rows:
            for flag in (row.get("quality_flags") or "").split(";"):
                if flag:
                    flag_counts[flag] += 1

        summary.append({
            "source": source,
            "raw_rows": len(raw_rows),
            "clean_rows": len(clean_rows),
            "exact_duplicates_removed": count_duplicates(raw_rows),
            "rows_with_quality_flag": sum(
                bool(row.get("quality_flags"))
                for row in clean_rows
            ),
            "quality_flags_detail": " | ".join(
                f"{key}:{value}"
                for key, value in sorted(flag_counts.items())
            ),
        })

    return summary


def main():

    # Lecture des quatre fichiers reçus pour le TP
    raw_auth = read_csv(RAW / "authentication_logs.csv")
    raw_edr = read_csv(RAW / "edr_alerts.csv")
    raw_assets = read_csv(RAW / "assets.csv")
    raw_users = read_csv(RAW / "users.csv")

    # On nettoie d'abord les référentiels users et assets
    users = clean_users(raw_users)
    assets = clean_assets(raw_assets)

    # Ces listes permettent ensuite de vérifier les références des événements
    user_ids = {row["user_id"] for row in users}
    device_ids = {row["device_id"] for row in assets}

    auth = clean_auth(
        raw_auth,
        user_ids,
        device_ids
    )

    edr = clean_edr(
        raw_edr,
        user_ids,
        device_ids
    )

    # Sauvegarde des fichiers nettoyés
    write_csv(
        PROCESSED / "users_clean.csv",
        users
    )

    write_csv(
        PROCESSED / "assets_clean.csv",
        assets
    )

    write_csv(
        PROCESSED / "authentication_logs_clean.csv",
        auth
    )

    write_csv(
        PROCESSED / "edr_alerts_clean.csv",
        edr
    )

    # Création du dataset final réunissant les deux sources d'événements
    consolidated = consolidate(
        auth,
        edr,
        users,
        assets
    )

    write_csv(
        PROCESSED / "security_events_consolidated.csv",
        consolidated
    )

    # Petit rapport permettant de voir ce qui a été corrigé ou signalé
    summary = quality_summary(
        raw_auth,
        raw_edr,
        raw_assets,
        raw_users,
        auth,
        edr,
        assets,
        users
    )

    write_csv(
        PROCESSED / "data_quality_summary.csv",
        summary
    )

    print("\n" + "=" * 90)
    print("RÉSUMÉ DU NETTOYAGE")
    print("=" * 90)

    print(
        f"{'SOURCE':<28}"
        f"{'BRUT':>10}"
        f"{'NETTOYÉ':>12}"
        f"{'DOUBLONS':>12}"
        f"{'ANOMALIES':>12}"
    )

    print("-" * 90)

    for row in summary:
        print(
            f"{row['source']:<28}"
            f"{row['raw_rows']:>10}"
            f"{row['clean_rows']:>12}"
            f"{row['exact_duplicates_removed']:>12}"
            f"{row['rows_with_quality_flag']:>12}"
        )

    print("\n" + "=" * 90)
    print("DÉTAIL DES ANOMALIES")
    print("=" * 90)

    for row in summary:
        print(f"\n{row['source']}")

        details = row["quality_flags_detail"]

        if not details:
            print("  Aucune anomalie détectée")
            continue

        for anomaly in details.split(" | "):
            name, count = anomaly.split(":")
            print(f"  - {name:<25} : {count}")

    print("\nNettoyage terminé avec succès.\n")


if __name__ == "__main__":
    main()