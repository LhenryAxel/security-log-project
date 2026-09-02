from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / "data" / "processed"

# Chargement des données nettoyées
events = pd.read_csv(PROCESSED / "security_events_consolidated.csv")

print("\n" + "=" * 80)
print("CORRÉLATION AUTHENTIFICATION + ALERTES EDR")
print("=" * 80)

events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce")

auth = events[events["source"] == "AUTHENTICATION"].copy()
edr = events[events["source"] == "EDR"].copy()

candidates = []

# On analyse chaque couple utilisateur / machine
for (user_id, device_id), group in auth.dropna(
    subset=["user_id", "device_id"]
).groupby(["user_id", "device_id"]):

    group = group.sort_values("timestamp")

    # On regarde chaque authentification réussie
    successes = group[group["authentication_result"] == "SUCCESS"]

    for _, success in successes.iterrows():

        success_time = success["timestamp"]

        # Échecs dans les 30 minutes avant le succès
        previous_failures = group[
            (group["authentication_result"] == "FAILURE")
            & (group["timestamp"] >= success_time - pd.Timedelta(minutes=30))
            & (group["timestamp"] < success_time)
        ]

        # On considère intéressant à partir de 3 échecs
        if len(previous_failures) < 3:
            continue

        # Alertes EDR sur la même machine dans l'heure suivante
        edr_after = edr[
            (edr["device_id"] == device_id)
            & (edr["timestamp"] >= success_time)
            & (edr["timestamp"] <= success_time + pd.Timedelta(hours=1))
        ]

        # On garde les alertes les plus préoccupantes
        suspicious_edr = edr_after[
            (edr_after["severity"].isin(["HIGH", "CRITICAL"]))
            | (edr_after["analyst_decision"] == "TRUE_POSITIVE")
        ]

        if len(suspicious_edr) == 0:
            continue

        candidates.append({
            "user_id": user_id,
            "device_id": device_id,
            "success_time": success_time,
            "location": success["event_location"],
            "previous_failures": len(previous_failures),
            "edr_alerts_next_hour": len(edr_after),
            "suspicious_edr_next_hour": len(suspicious_edr)
        })


results = pd.DataFrame(candidates)

if results.empty:
    print("\nAucune corrélation suspecte trouvée.")
else:
    results = results.sort_values(
        ["suspicious_edr_next_hour", "previous_failures"],
        ascending=False
    )

    print("\nSéquences suspectes détectées :")
    print(results.to_string(index=False))

    print("\n" + "=" * 80)
print("INVESTIGATION DU CANDIDAT U0113 / D0011")
print("=" * 80)

incident = events[
    (events["user_id"] == "U0113")
    & (events["device_id"] == "D0011")
].copy()

incident["timestamp"] = pd.to_datetime(incident["timestamp"])

print("\nInformations utilisateur :")
print(
    incident[
        [
            "user_department",
            "user_role",
            "employment_status",
            "privileged_account",
            "user_location"
        ]
    ]
    .drop_duplicates()
    .to_string(index=False)
)

print("\nInformations machine :")
print(
    incident[
        [
            "asset_hostname",
            "asset_type",
            "asset_department",
            "asset_owner",
            "asset_criticality",
            "operating_system"
        ]
    ]
    .drop_duplicates()
    .to_string(index=False)
)

print("\nChronologie AUTH + EDR :")

print(
    incident[
        [
            "timestamp",
            "source",
            "event_type",
            "authentication_result",
            "event_location",
            "process_name",
            "severity",
            "analyst_decision"
        ]
    ]
    .sort_values("timestamp")
    .to_string(index=False)
)