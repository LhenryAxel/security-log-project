# Scénarios de sécurité identifiés

## Scénario 1 — Compte privilégié attaqué sur D0003

### Raisonnement
On a d'abord cherché les machines générant le plus d'alertes EDR. `D0003` ressortait nettement avec 50 alertes, bien plus que les autres machines. On a donc regardé les authentifications associées à cette machine, puis les utilisateurs les plus présents.

### Découverte
`U0007`, compte privilégié du service IT, présente 9 échecs de connexion successifs depuis Bucharest, suivis d'une connexion réussie puis d'une session RDP. Sur la même période, plusieurs alertes EDR critiques apparaissent sur `D0003`, avec notamment `mimikatz.exe`, `cryptolock.exe` et `psexec.exe`.

Ce comportement indique une forte suspicion de compromission d'un compte privilégié.

## Scénario 2 — Compte inactif encore utilisé

### Raisonnement
Après avoir enrichi les événements avec le référentiel utilisateurs, on a vérifié s'il existait des authentifications réussies réalisées par des comptes marqués `INACTIVE`.

### Découverte
Le compte `U0042`, pourtant marqué inactif, réalise 6 connexions VPN réussies entre le 8 et le 13 mars.

Cela montre un possible défaut dans le processus de désactivation des comptes après le départ d'un salarié.

## Scénario 3 — Machine critique générant beaucoup d'alertes

### Raisonnement
On a compté le nombre d'alertes EDR par machine afin d'identifier les machines qui sortaient anormalement du lot.

### Découverte
`D0003` génère 50 alertes EDR, contre seulement 18 pour la machine suivante. Il s'agit en plus d'un serveur Windows critique du service IT.

Les alertes concernent principalement `Credential Access`, `Persistence Attempt` et `PowerShell Abuse`. Cette concentration d'alertes sur un actif critique justifie une investigation approfondie.

## Scénario 4 — Rafale de faux positifs

### Raisonnement
On a regardé quels processus généraient le plus d'alertes EDR, puis on a comparé ces volumes avec les décisions prises par les analystes.

### Découverte
`backup_agent.exe` génère environ 400 alertes, soit presque deux fois plus que le processus suivant. Parmi les alertes déjà qualifiées, elles sont quasiment toutes classées `FALSE_POSITIVE`.

Ce processus semble donc être une importante source de bruit pour les analystes. Une règle de filtrage spécifique pourrait être plus adaptée qu'un traitement par Machine Learning.

## Scénario 5 — Incident corrélé entre authentification et EDR

### Raisonnement
Après avoir consolidé les événements AUTH et EDR, on a cherché automatiquement les cas où plusieurs échecs d'authentification étaient suivis d'un succès, puis d'alertes EDR importantes sur la même machine dans l'heure suivante.

### Découverte
Cette règle a fait ressortir `U0113` sur `D0011`. Le compte privilégié présente 4 échecs de connexion depuis Lagos, suivis d'une connexion réussie puis d'un changement de mot de passe.

Dans les minutes suivantes, plusieurs alertes EDR critiques et confirmées `TRUE_POSITIVE` apparaissent sur le serveur, dont `Ransomware Behaviour`, `Persistence Attempt` et `Credential Access`.

La corrélation entre les deux sources indique une forte suspicion de compromission suivie d'une activité malveillante.

## Conclusion

Ces analyses montrent l'intérêt de la consolidation des différentes sources de sécurité. Certaines anomalies ne sont visibles qu'en croisant les informations utilisateurs, machines, authentifications et alertes EDR.

Elles permettent également d'identifier des impacts concrets sur le projet : réduction des faux positifs, amélioration de l'offboarding, meilleure surveillance des comptes privilégiés et besoin de corrélation entre les sources.