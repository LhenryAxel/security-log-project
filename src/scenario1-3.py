from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / "data" / "processed"

# Chargement des données nettoyées
events = pd.read_csv(PROCESSED / "security_events_consolidated.csv")

print("\n" + "=" * 80)
print("ANALYSE DES ÉVÉNEMENTS DE SÉCURITÉ")
print("=" * 80)

print(f"\nNombre total d'événements : {len(events)}")
print("\nRépartition par source :")
print(events["source"].value_counts())

# On garde uniquement les alertes EDR
edr = events[events["source"] == "EDR"]

print("\n" + "=" * 80)
print("MACHINES AVEC LE PLUS D'ALERTES EDR")
print("=" * 80)

print(edr["device_id"].value_counts().head(10))

print("\n" + "=" * 80)
print("DÉTAIL DE LA MACHINE D0003")
print("=" * 80)

d0003 = events[events["device_id"] == "D0003"]

print("\nInformations sur la machine :")
print(
    d0003[
        [
            "asset_hostname",
            "asset_type",
            "asset_department",
            "asset_owner",
            "asset_criticality",
            "operating_system"
        ]
    ].drop_duplicates()
)

print("\nRépartition des événements par source :")
print(d0003["source"].value_counts())

print("\nTypes d'alertes EDR sur D0003 :")
print(
    d0003[d0003["source"] == "EDR"]["event_type"]
    .value_counts()
    .head(10)
)

print("\n" + "=" * 80)
print("AUTHENTIFICATIONS SUR D0003")
print("=" * 80)

auth_d0003 = d0003[d0003["source"] == "AUTHENTICATION"].copy()

# Conversion en vraie date pour pouvoir trier correctement
auth_d0003["timestamp"] = pd.to_datetime(auth_d0003["timestamp"])

print("\nUtilisateurs les plus présents :")
print(auth_d0003["user_id"].value_counts())

print("\nRésultats d'authentification :")
print(auth_d0003["authentication_result"].value_counts())

print("\nCombinaisons utilisateur / IP / résultat :")
print(
    auth_d0003.groupby(
        ["user_id", "src_ip", "authentication_result"]
    )
    .size()
    .sort_values(ascending=False)
    .head(15)
)

print("\nChronologie complète :")
print(
    auth_d0003[
        [
            "timestamp",
            "user_id",
            "src_ip",
            "event_location",
            "event_type",
            "authentication_result"
        ]
    ]
    .sort_values("timestamp")
    .to_string(index=False)
)

print("\n" + "=" * 80)
print("INFORMATIONS SUR U0007")
print("=" * 80)

u0007 = events[events["user_id"] == "U0007"]

print(
    u0007[
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


print("\n" + "=" * 80)
print("ALERTES EDR SUR D0003 AUTOUR DE L'ATTAQUE")
print("=" * 80)

edr_d0003 = d0003[d0003["source"] == "EDR"].copy()
edr_d0003["timestamp"] = pd.to_datetime(edr_d0003["timestamp"])

attaque_edr = edr_d0003[
    (edr_d0003["timestamp"] >= "2026-03-12 01:30:00")
    & (edr_d0003["timestamp"] <= "2026-03-12 04:00:00")
]

print(
    attaque_edr[
        [
            "timestamp",
            "user_id",
            "event_type",
            "process_name",
            "severity",
            "analyst_decision"
        ]
    ]
    .sort_values("timestamp")
    .to_string(index=False)
)   