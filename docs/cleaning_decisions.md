# Journal des décisions de nettoyage

1. Les fichiers bruts sont conservés sans modification.
2. Les doublons strictement identiques sont supprimés.
3. Les formats de dates sont uniformisés mais la valeur originale est conservée.
4. Les sévérités sont uniformisées en majuscules.
5. Les résultats d'authentification sont ramenés à `SUCCESS` / `FAILURE`.
6. Les IP invalides ne provoquent pas la suppression de la ligne.
7. Les utilisateurs / devices inconnus sont signalés plutôt que supprimés.
8. Les données manquantes ne sont pas imputées sans base métier.
9. Un champ `quality_flags` documente les anomalies conservées.
10. Le dataset consolidé est enrichi avec les référentiels users/assets lorsque les clés correspondent.
