from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / "data" / "processed"

# Chargement des données nettoyées
events = pd.read_csv(PROCESSED / "security_events_consolidated.csv")

print("\n" + "=" * 80)
print("CONNEXIONS RÉUSSIES DE COMPTES INACTIFS")
print("=" * 80)

auth = events[events["source"] == "AUTHENTICATION"].copy()

inactive_success = auth[
    (auth["employment_status"] == "INACTIVE")
    & (auth["authentication_result"] == "SUCCESS")
]

print(
    inactive_success[
        [
            "timestamp",
            "user_id",
            "user_role",
            "src_ip",
            "event_location",
            "event_type",
            "device_id"
        ]
    ]
    .sort_values("timestamp")
    .to_string(index=False)
)

print("\nNombre d'événements par utilisateur :")
print(inactive_success["user_id"].value_counts())