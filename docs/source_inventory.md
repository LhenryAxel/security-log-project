# Inventaire et diagnostic des sources

> Limite documentaire : le sujet annonce un fichier `README_ETUDIANTS.md`, mais ce fichier n'a pas été fourni ici.
> Les propriétaires exacts et la fréquence officielle de mise à jour restent donc **à confirmer**.

| Source | Propriétaire | Contenu | Format | Volume reçu | Fréquence probable* | Diagnostic rapide |
|---|---|---|---|---:|---|---|
| `authentication_logs.csv` | À confirmer (IT / IAM probable) | Authentifications AD, VPN, RDP, MFA, etc. | CSV | 4992 lignes | Événementielle / continue | Plusieurs formats de dates, casse incohérente, doublons, IP invalides, références manquantes |
| `edr_alerts.csv` | À confirmer (équipe sécurité / IT probable) | Alertes EDR | CSV | 1929 lignes | Événementielle / continue | Doublons, casse de sévérité, décisions analyste manquantes, références actifs inconnues |
| `assets.csv` | À confirmer (IT Infrastructure probable) | Référentiel des actifs | CSV | 200 lignes | Snapshot / mise à jour sur changement | Owners et criticités manquants, hostnames dupliqués |
| `users.csv` | À confirmer (RH / IAM probable) | Référentiel utilisateurs | CSV | 400 lignes | Snapshot / mise à jour sur changement | 5 doublons stricts, structure globalement cohérente |

\* La fréquence est une proposition de travail, pas une information confirmée par les fichiers reçus.

## Période couverte
- Authentification : du **2 mars 2026** au **22 mars 2026**.
- EDR : du **2 mars 2026** au **22 mars 2026**.
- Historique réellement reçu : environ **21 jours**, ce qui est court pour une future modélisation robuste.
