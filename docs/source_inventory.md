# Inventaire et diagnostic des sources

Les données ont été fournies par l'équipe IT telles qu'elles ont été extraites.
Aucun contrôle qualité préalable n'a été réalisé et les référentiels utilisateurs
et actifs ne sont pas garantis à jour.

| Source | Propriétaire | Contenu | Format | Volume reçu | Fréquence | Diagnostic rapide |
|---|---|---|---|---:|---|---|
| `authentication_logs.csv` | À confirmer | Événements d'authentification (AD, VPN, RDP...) | CSV | 4992 lignes | Non documentée | Plusieurs formats de dates, doublons, IP invalides et références manquantes |
| `edr_alerts.csv` | À confirmer | Alertes remontées par l'outil EDR | CSV | 1929 lignes | Non documentée | Doublons, sévérités non homogènes et alertes non encore traitées par un analyste |
| `assets.csv` | À confirmer | Référentiel des actifs (postes, serveurs, VM) | CSV | 200 lignes | Non documentée | Owners et criticités manquants, quelques hostnames dupliqués |
| `users.csv` | À confirmer | Référentiel des utilisateurs | CSV | 400 lignes | Non documentée | Quelques doublons, structure globalement cohérente |

## Période couverte

- Authentification : du 2 mars 2026 au 22 mars 2026.
- EDR : du 2 mars 2026 au 22 mars 2026.
- Historique reçu : environ 21 jours.

## Réserves communiquées par l'IT

- Les données proviennent d'outils différents.
- `users.csv` et `assets.csv` ne sont pas garantis à jour.
- `analyst_decision` n'est renseigné que lorsqu'une alerte a été traitée.
- Aucune vérification de cohérence entre les fichiers n'avait été réalisée avant leur transmission.