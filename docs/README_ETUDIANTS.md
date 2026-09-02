# TP 3 - Données transmises par les équipes IT

Vous trouverez dans ce dossier les données historiques que les équipes IT ont
pu extraire à votre demande.

> Ces données sont fournies **telles qu'elles ont été extraites**. Elles n'ont
> fait l'objet d'aucun contrôle qualité préalable et leur documentation est
> partielle : c'est le cas le plus courant en environnement réel.

Toutes les données sont **entièrement synthétiques**. Elles ne contiennent
aucune information personnelle réelle.

---

## Fichiers fournis

| Fichier | Contenu | Volume |
|---|---|---|
| `authentication_logs.csv` | Événements d'authentification (AD, VPN, RDP…) | ~5 000 lignes |
| `edr_alerts.csv` | Alertes remontées par l'outil EDR | ~2 000 lignes |
| `assets.csv` | Référentiel des actifs (postes, serveurs, VM) | ~200 lignes |
| `users.csv` | Référentiel des utilisateurs | ~400 lignes |

---

## Description des champs

### `authentication_logs.csv`

| Champ | Description |
|---|---|
| `event_id` | Identifiant de l'événement |
| `timestamp` | Date et heure de l'événement |
| `user_id` | Identifiant de l'utilisateur |
| `src_ip` | Adresse IP source |
| `device_id` | Identifiant de la machine |
| `event_type` | Type d'événement (LOGIN, VPN_CONNECT…) |
| `authentication_result` | Résultat de l'authentification |
| `location` | Localisation géographique estimée |
| `severity` | Niveau de sévérité attribué par l'outil |

### `edr_alerts.csv`

| Champ | Description |
|---|---|
| `alert_id` | Identifiant de l'alerte |
| `timestamp` | Date et heure de l'alerte |
| `device_id` | Machine concernée |
| `user_id` | Utilisateur associé |
| `alert_type` | Catégorie d'alerte |
| `process_name` | Processus à l'origine de l'alerte |
| `severity` | Niveau de sévérité |
| `status` | État de traitement de l'alerte |
| `analyst_decision` | Conclusion de l'analyste, lorsqu'elle existe |

### `assets.csv`

| Champ | Description |
|---|---|
| `device_id` | Identifiant de la machine |
| `hostname` | Nom réseau |
| `asset_type` | Type d'actif |
| `department` | Département utilisateur |
| `owner` | Entité responsable |
| `criticality` | Criticité métier de l'actif |
| `operating_system` | Système d'exploitation |

### `users.csv`

| Champ | Description |
|---|---|
| `user_id` | Identifiant de l'utilisateur |
| `department` | Département |
| `role` | Fonction |
| `employment_status` | Statut (en poste ou non) |
| `privileged_account` | Compte à privilèges |
| `location` | Site de rattachement |

---

## Points signalés par l'équipe IT

L'équipe IT vous transmet ces données avec les réserves suivantes :

- les extractions proviennent d'outils différents, configurés à des époques
  différentes ;
- personne n'a pu garantir que les référentiels `users.csv` et `assets.csv`
  sont à jour ;
- le champ `analyst_decision` n'est renseigné que lorsqu'un analyste a
  effectivement traité l'alerte ;
- aucune vérification de cohérence n'a été effectuée entre les fichiers.

---

## Ce qui vous est demandé

1. **Inventorier** chaque source : contenu, format, volume, qualité.
2. **Évaluer la qualité** des données selon les dimensions vues en cours
   (completeness, consistency, validity, uniqueness, accuracy, timeliness).
3. **Nettoyer et normaliser** ce qui peut l'être.
4. **Identifier ce qui n'est pas exploitable** - vous avez parfaitement le
   droit de conclure qu'une donnée ne peut pas être utilisée, à condition de
   le justifier.
5. **Produire un dataset consolidé** exploitable pour la phase de modélisation,
   et documenter votre modèle de données.
6. **Mesurer l'impact** de vos découvertes sur le backlog, le planning et les
   risques définis au TP précédent.

### Recommandation

Documentez chaque décision de nettoyage. Une ligne supprimée sans
justification est une information perdue - et en sécurité, l'anomalie que
vous effacez est parfois précisément celle qu'il fallait voir.

---

## Outils

`pandas` suffit pour l'ensemble du travail. `matplotlib` peut aider à
visualiser les distributions. **Aucun traitement de machine learning n'est
attendu à ce stade.**
