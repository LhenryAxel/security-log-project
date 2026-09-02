# Diagnostic de Data Quality

## Synthèse

| Dimension | Constats principaux | Niveau |
|---|---|---|
| Completeness | 151 `user_id` manquants dans les logs d'authentification ; 234 décisions analyste manquantes dans EDR ; 14 owners et 20 criticités manquants dans les actifs | Moyen |
| Consistency | 3 formats de timestamp dans l'authentification, 2 dans EDR ; casse incohérente des sévérités et résultats d'authentification | Faible à moyen |
| Validity | 52 IP invalides ; références vers utilisateurs/actifs inconnus | Moyen |
| Uniqueness | 145 doublons stricts dans l'authentification, 74 dans EDR, 5 dans users ; 3 hostnames apparaissent deux fois | Moyen |
| Accuracy | Vérifiable seulement en partie ; certaines références ne correspondent pas aux référentiels et des événements sont associés à des utilisateurs inactifs | À investiguer |
| Timeliness | Les logs reçus couvrent seulement 21 jours | Limité pour le ML |

## Détails

### 1. Completeness
- `authentication_logs.csv` : **151 / 4992** lignes sans `user_id` (3.0 %).
- `edr_alerts.csv` : **234 / 1929** lignes sans `analyst_decision` (12.1 %).
- `assets.csv` : **14 / 200** assets sans owner (7 %) et **20 / 200** sans criticité (10 %).

Décision : **ne pas inventer** les valeurs manquantes. Les lignes sont conservées et signalées par `quality_flags`.

### 2. Consistency
Formats de date détectés :
- Authentification : `{'iso_space': 1670, 'fr_minute': 1657, 'iso_z': 1665}`.
- EDR : `{'iso_space': 1447, 'iso_z': 482}`.

Les sévérités existent sous plusieurs casses (`High`, `HIGH`, `high`, etc.).
Les résultats d'authentification utilisent plusieurs variantes (`SUCCESS`, `Success`, `success`, `FAILED`, `Failed`, `failed`, `FAILURE`).

Décision : normaliser les timestamps en `YYYY-MM-DD HH:MM:SS`, les sévérités en majuscules et les résultats en `SUCCESS` / `FAILURE`.

### 3. Validity
- **52** adresses IP sont syntaxiquement invalides dans les données brutes.
- Authentification : **37** événements référencent 6 utilisateurs absents de `users.csv`.
- Authentification : **47** événements référencent 8 devices absents de `assets.csv`.
- EDR : **33** alertes référencent 8 devices absents de `assets.csv`.
- Les formats des identifiants (`Uxxxx`, `Dxxxx`, `AUTHxxxxxx`, `EDRxxxxxx`) sont globalement valides.

Décision : conserver l'événement, conserver l'IP originale dans `src_ip_raw`, vider uniquement la valeur normalisée invalide et ajouter un flag.

### 4. Uniqueness
- Authentification : **145** doublons strictement identiques.
- EDR : **74** doublons strictement identiques.
- Users : **5** doublons strictement identiques.
- Assets : aucun doublon de `device_id`, mais 3 hostnames sont utilisés deux fois (`PHF-WS-0120`, `PHF-WS-0020`, `PHF-LT-0055`).

Décision : supprimer uniquement les doublons **strictement identiques**. Ne pas supprimer les assets partageant un hostname, car leur `device_id` est différent.

### 5. Accuracy
L'exactitude métier ne peut pas être démontrée automatiquement sans documentation ou validation humaine.
Deux points doivent être investigués :
- des événements référencent des comptes ou devices absents des référentiels ;
- **6** événements d'authentification et **207** alertes EDR sont associés à des utilisateurs marqués `INACTIVE`.

Ces événements ne sont pas supprimés : ils peuvent représenter soit des erreurs de référentiel, soit de vrais événements de sécurité.

### 6. Timeliness
Les logs reçus couvrent seulement environ **21 jours**. Cela suffit pour le TP et un prototype de pipeline, mais c'est court pour juger la saisonnalité ou entraîner un modèle robuste.

### 7. Qualité des labels EDR
Répartition brute des décisions analyste :
- `FALSE_POSITIVE` : **1456**
- `TRUE_POSITIVE` : **66**
- `NEEDS_INVESTIGATION` : **173**
- non renseigné : **234**

Le futur dataset de classification est donc **très déséquilibré** : beaucoup plus de faux positifs que de vrais positifs. C'est un risque important pour la phase de modélisation.
