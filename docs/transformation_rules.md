# Règles de nettoyage et de normalisation

| Règle | Décision | Justification |
|---|---|---|
| Données brutes | Ne jamais modifier `data/raw/` | Traçabilité et reproductibilité |
| Doublons stricts | Supprimer une copie | Même identifiant + mêmes valeurs = duplication certaine |
| Timestamp | Convertir vers `YYYY-MM-DD HH:MM:SS` | Format commun inter-sources |
| Timestamp original | Conserver dans `timestamp_raw` | Traçabilité de la transformation |
| Sévérité | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Éviter les variantes de casse |
| Auth result | `SUCCESS` ou `FAILURE` | Uniformiser `FAILED`, `failed`, `FAILURE`, etc. |
| IP invalide | Conserver l'originale, laisser `src_ip` normalisé vide, ajouter `INVALID_SRC_IP` | Ne pas effacer l'événement |
| User manquant | Ne pas imputer ; ajouter `MISSING_USER_ID` | Pas de valeur fiable à inventer |
| Référence inconnue | Conserver ; ajouter `UNKNOWN_USER_REF` ou `UNKNOWN_DEVICE_REF` | Peut révéler un décalage de référentiel ou une anomalie sécurité |
| Alerte EDR non traitée | Conserver ; ajouter `NOT_REVIEWED` | La documentation indique que `analyst_decision` n'est renseigné que lorsqu'un analyste a traité l'alerte |
| Owner/criticité manquants | Ne pas imputer | Nécessite une validation métier |
| Hostname dupliqué | Conserver les deux assets et ajouter `DUPLICATE_HOSTNAME` | Le `device_id` reste unique |
| Consolidation | Aligner auth + EDR sur un schéma commun et enrichir avec users/assets quand possible | Préparer un dataset exploitable pour la phase suivante |

## Principe général
Aucune ligne présentant une anomalie métier n'est supprimée sans certitude. En cybersécurité, une anomalie de données peut aussi être un signal utile.
