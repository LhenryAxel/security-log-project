# Security Log Project — TP3

Projet de réception et qualification des données de sécurité.

## Objectif
Auditer, nettoyer, normaliser et consolider les données reçues afin de produire
un dataset exploitable pour la phase de modélisation.

## Structure
- `data/raw/` : fichiers d'origine, jamais modifiés.
- `data/processed/` : fichiers nettoyés et dataset consolidé.
- `src/clean_data.py` : script reproductible de nettoyage.
- `docs/` : diagnostic, règles de transformation et impact projet.
- `tests/` : tests unitaires simples.
- `notebooks/` : analyses exploratoires éventuelles.

## Exécution
```bash
python src/clean_data.py
python -m unittest discover -s tests -v
```

## Principes retenus
- seuls les doublons strictement identiques sont supprimés ;
- les anomalies ne sont pas supprimées : elles sont signalées dans `quality_flags` ;
- les formats de dates, sévérités et résultats d'authentification sont normalisés ;
- les références utilisateur / actif inconnues sont conservées mais signalées ;
- les valeurs manquantes ne sont pas inventées.
