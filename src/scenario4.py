from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / "data" / "processed"

# Chargement des données nettoyées
events = pd.read_csv(PROCESSED / "security_events_consolidated.csv")

edr = events[events["source"] == "EDR"]

print("\n" + "=" * 80)
print("PROCESSUS GÉNÉRANT LE PLUS D'ALERTES EDR")
print("=" * 80)

print(
    edr["process_name"]
    .value_counts()
    .head(15)
)

print("\n" + "=" * 80)
print("\n" + "=" * 80)
print("RÉPARTITION DES DÉCISIONS ANALYSTE PAR PROCESSUS")
print("=" * 80)

edr_decisions = edr.copy()

# Les décisions absentes sont affichées explicitement
edr_decisions["analyst_decision"] = (
    edr_decisions["analyst_decision"]
    .fillna("UNLABELED")
    .replace("", "UNLABELED")
)

process_decisions = (
    edr_decisions.groupby(["process_name", "analyst_decision"])
    .size()
    .unstack(fill_value=0)
)

process_decisions["TOTAL"] = process_decisions.sum(axis=1)

print(
    process_decisions
    .sort_values("TOTAL", ascending=False)
    .head(15)
    .to_string()
)

print("\n" + "=" * 80)
print("ALERTES CRITICAL CLASSÉES FALSE_POSITIVE")
print("=" * 80)

critical_false_positive = edr[
    (edr["severity"] == "CRITICAL")
    & (edr["analyst_decision"] == "FALSE_POSITIVE")
]

print(f"\nNombre d'alertes : {len(critical_false_positive)}")

print("\nProcessus concernés :")
print(
    critical_false_positive["process_name"]
    .value_counts()
)

print("\nDétail :")
print(
    critical_false_positive[
        [
            "timestamp",
            "device_id",
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