# Impact sur le backlog, le planning et les risques

## Backlog
Les problèmes découverts ajoutent ou renforcent les éléments suivants :
1. Contrôle automatique de la qualité des données à l'entrée.
2. Normalisation des timestamps et catégories.
3. Gestion des références utilisateur / actif inconnues.
4. Collecte de labels supplémentaires pour les alertes EDR.
5. Clarification des owners et criticités manquants dans `assets.csv`.
6. Récupération d'un historique plus long avant une modélisation définitive.

## Planning
Le Sprint 1 doit consacrer du temps supplémentaire au nettoyage et à la compréhension des données.
La modélisation ne doit pas démarrer avant validation du schéma commun et vérification des labels.
Un historique supplémentaire peut être demandé en parallèle sans bloquer le prototype de pipeline.

## Risques projet mis à jour
- **Qualité des données : élevée** — plusieurs incohérences et valeurs manquantes.
- **Qualité des labels : élevée** — décisions EDR manquantes et classes très déséquilibrées.
- **Référentiels incomplets : moyen à élevé** — users/devices inconnus dans les logs.
- **Historique trop court : moyen** — seulement 21 jours reçus.
- **Risque de perte d'information : élevé si nettoyage agressif** — d'où l'utilisation de `quality_flags`.

## Décision projet
Le dataset est **exploitable pour poursuivre le prototype**, à condition de conserver les flags de qualité et de ne pas considérer le dataset actuel comme suffisant pour valider définitivement un modèle ML.
