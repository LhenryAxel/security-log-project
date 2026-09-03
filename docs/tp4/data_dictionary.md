# TP 4 — Dictionnaire de données

Fichier : `cleaned_dataset.csv` — **6 702 lignes × 24 colonnes**

Ce dataset est le résultat du travail de nettoyage et de consolidation réalisé
au TP 3, enrichi d'une colonne cible. Chaque ligne représente **un événement de
sécurité**, provenant soit des journaux d'authentification, soit de l'outil EDR.

---

## Colonne cible

| Colonne | Valeurs | Description |
|---|---|---|
| `triage_label` | `NORMAL`, `SUSPICIOUS`, `MALICIOUS` | Conclusion portée sur l'événement **après investigation complète** |

| Classe | Signification opérationnelle |
|---|---|
| `NORMAL` | Événement ne nécessitant pas d'investigation |
| `SUSPICIOUS` | Événement nécessitant une vérification humaine |
| `MALICIOUS` | Événement associé à un incident confirmé |

Les trois classes ne sont **pas équilibrées**. Commencez par regarder leur
distribution : elle conditionne le choix de vos métriques.

---

## Colonnes descriptives

### Identification de l'événement

| Colonne | Type | Description |
|---|---|---|
| `event_id` | texte | Identifiant unique de l'événement |
| `timestamp` | texte | Date et heure, format `YYYY-MM-DD HH:MM:SS` |
| `source` | catégorie | `authentication_logs` ou `edr_alerts` |

### Entités concernées

| Colonne | Type | Description |
|---|---|---|
| `user_id` | texte | Identifiant de l'utilisateur (`UNKNOWN` si absent) |
| `device_id` | texte | Identifiant de la machine (`UNKNOWN` si absent) |
| `src_ip` | texte | Adresse IP source (`UNKNOWN` pour les alertes EDR) |
| `src_ip_valid` | booléen | `False` si l'IP était malformée dans la source |
| `user_known` | booléen | `False` si l'utilisateur est absent du référentiel |
| `device_known` | booléen | `False` si la machine est absente de l'inventaire |

### Caractéristiques de l'événement

| Colonne | Type | Description |
|---|---|---|
| `event_type` | catégorie | Type d'événement (`LOGIN`, `VPN_CONNECT`, `Credential Access`…) |
| `process_name` | catégorie | Processus à l'origine de l'alerte EDR (`UNKNOWN` côté authentification) |
| `severity` | catégorie | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNKNOWN` |
| `authentication_result` | catégorie | `SUCCESS`, `FAILED`, `NOT_APPLICABLE` |
| `location` | catégorie | Localisation géographique estimée |

### Contexte utilisateur

| Colonne | Type | Description |
|---|---|---|
| `user_department` | catégorie | Département de rattachement |
| `user_role` | catégorie | Fonction occupée |
| `employment_status` | catégorie | `ACTIVE`, `INACTIVE`, `UNKNOWN` |
| `privileged_account` | catégorie | `YES`, `NO`, `UNKNOWN` |

### Contexte machine

| Colonne | Type | Description |
|---|---|---|
| `hostname` | texte | Nom réseau de la machine |
| `asset_type` | catégorie | `Laptop`, `Server`, `VM`, `Desktop`, `Mobile` |
| `asset_owner` | catégorie | Entité responsable de l'actif |
| `asset_criticality` | catégorie | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNKNOWN` |

### Historique d'analyse

| Colonne | Type | Description |
|---|---|---|
| `label` | catégorie | Décision rendue par l'analyste lors du traitement historique : `TRUE_POSITIVE`, `FALSE_POSITIVE`, `NEEDS_INVESTIGATION`, `UNLABELED` |

---

## Avertissement

Toutes les colonnes présentes dans ce fichier **ne sont pas utilisables comme
variables d'entrée du modèle**. Avant d'entraîner quoi que ce soit, posez-vous
systématiquement la question suivante pour chaque colonne :

> *Cette information est-elle réellement disponible au moment où le système
> doit prioriser un événement qui vient d'arriver ?*

Une colonne qui n'existe qu'*après* le traitement d'un événement ne peut pas
servir à le prédire. L'utiliser produirait un modèle qui semble excellent en
test et qui s'effondre en production.

---

## Pistes de feature engineering

Le fichier contient un événement par ligne. Plusieurs signaux utiles ne s'y
trouvent **pas directement** et doivent être construits :

- caractéristiques temporelles (heure, nuit/jour, jour de semaine) ;
- nombre d'échecs d'authentification récents pour un même utilisateur ;
- succès survenant après une série d'échecs ;
- volume d'activité par utilisateur ou par machine ;
- caractère inhabituel d'une localisation ;
- croisement entre privilèges du compte et criticité de l'actif.

Cette liste n'est ni obligatoire ni exhaustive : c'est à vous de décider ce qui
a du sens pour le problème posé, et de le justifier.
