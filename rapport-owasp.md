# TP : Analyse dynamique (DAST) de TIWAP avec OWASP ZAP

Entreprise : NOVA SERVICES | Application étudiée : TIWAP
Auteur : Edouard Dieppois | Date : 16/10/2026

Ce TP fait suite à l'analyse statique avec SonarQube ([rapport.md](rapport.md)). TIWAP est ici lancée et analysée en fonctionnement, dans un environnement local isolé. Aucun scan actif n'a été réalisé.

## 1. Déploiement de TIWAP

Versions : OWASP ZAP 2.17.0 (`ghcr.io/zaproxy/zaproxy:stable`), MongoDB 4.4, TIWAP sur Python 3.6.15 / Werkzeug 2.0.3.

Modifications de [TIWAP/docker-compose.yml](TIWAP/docker-compose.yml) :

- `app` : port publié uniquement sur `127.0.0.1:5000`.
- `db` : port 27017 retiré, MongoDB n'est joignable que par `app` sur le réseau Docker.
- `zap` : service ajouté, avec le dossier `reports` monté dans `/zap/wrk/` pour récupérer les rapports.
- `version: "2"` retiré (obsolète).

```yaml
  zap:
    image: ghcr.io/zaproxy/zaproxy:stable
    depends_on:
      - app
    volumes:
      - ./reports:/zap/wrk/:rw
    entrypoint: ["sleep", "infinity"]
```

Lancement : `docker compose up -d --build`

TIWAP démarre Flask avec un certificat auto-signé (`app.py:913`). L'application répond donc en **HTTPS** : `https://localhost:5000` depuis le navigateur, `https://app:5000` depuis le conteneur ZAP.

![Conteneurs démarrés](captures/dast/01-docker-compose-ps.png)
![TIWAP fonctionne localement](captures/dast/02-tiwap-login.png)

## 2. Scan de référence

```bash
docker compose exec zap zap-baseline.py -t https://app:5000 -m 2 -r zap-report.html -J zap-report.json
```

Le scan explore l'application pendant 2 minutes au maximum, puis analyse passivement les réponses. Il se termine avec un code non nul, ce qui est normal : ZAP le fait dès qu'il a trouvé des alertes.

![Exécution du scan](captures/dast/03-zap-scan.png)

Rapports : [zap-report.html](rapports-zap/zap-report.html) et [zap-report.json](rapports-zap/zap-report.json)

## 3. Résultats

| Mesure | Valeur |
|---|---|
| URL découvertes | 19 (10 endpoints) |
| Règles passives OK | 52 |
| Alertes WARN | 15 |
| Alertes FAIL | 0 |
| Par niveau ZAP | 0 High, 4 Medium, 8 Low, 6 Informational |
| Réponses 5xx | 7 % |

![Résumé du rapport ZAP](captures/dast/04-zap-resume.png)

L'exploration est très limitée : ZAP n'est pas authentifié et toutes les pages de vulnérabilités de TIWAP sont protégées par le décorateur `@is_logged` (`app.py:78`), qui redirige vers l'accueil. ZAP n'a donc analysé que la page d'accueil, le formulaire de connexion et les fichiers statiques.

## 4. Qualification des alertes

| Alerte (ID) | Risque ZAP (confiance) | URL et preuve | Vérification | Résultat | Action |
|---|---|---|---|---|---|
| Source Code Disclosure - SQL (10099) et Application Error Disclosure (90022) | Medium et Low (Medium) | `POST /login` → 500. Trace Python affichée avec `SELECT username, password FROM users WHERE username` | Lecture de `helper/db_manager.py:40-45` et `app.py:913` | Confirmé, plus grave qu'indiqué | Corriger |
| Content Security Policy Header Not Set (10038) | Medium (High) | Toutes les réponses, en-tête absent | Réponses HTTP observées | Confirmé | Corriger |
| Missing Anti-clickjacking Header (10020) | Medium (Medium) | `GET /`, ni `X-Frame-Options` ni `frame-ancestors` | Réponse HTTP observée | Confirmé | Corriger (avec la CSP) |
| Absence of Anti-CSRF Tokens (10202) | Medium (Low) | `<form method="post" action="/login">` | Formulaire de connexion uniquement, les formulaires derrière l'authentification n'ont pas été explorés | À confirmer | Analyse complémentaire avec un scan authentifié |
| Server Leaks Version Information (10036) | Low (High) | `Server: Werkzeug/2.0.3 Python/3.6.15` | Réponses HTTP observées | Confirmé | Corriger |
| Strict-Transport-Security Header Not Set (10035) | Low (High) | Toutes les réponses | Contexte : labo local, certificat auto-signé | Confirmé, sans impact en labo | Justifier, à gérer au reverse proxy en production |

![Alerte Source Code Disclosure](captures/dast/05-zap-source-code-disclosure.png)

## 5. Pourquoi une alerte doit être vérifiée

### Erreur 500 sur /login : une alerte sous-évaluée

ZAP a soumis le formulaire de connexion avec l'utilisateur `ZAP`, qui n'existe pas. En lisant le code, j'ai trouvé la cause de l'erreur :

```python
result = self.cur.execute("SELECT username, password FROM users WHERE username = ?", (username,))
if type(result) != 'NoneType':      # toujours vrai : compare un type à une chaîne
    data = self.cur.fetchone()      # None si l'utilisateur n'existe pas
    ...
    password_db = data[1]           # TypeError -> erreur 500
```

L'application tourne avec `debug=True` (`app.py:913`). L'erreur affiche donc la trace complète et le **débogueur interactif Werkzeug** (URL `?__debugger__=yes&cmd=resource&f=debugger.js` dans le rapport). La trace révèle :
- le code source ;
- les chemins internes, que ZAP a ensuite suivis (`/app/app.py`, `/app/helper/db_manager.py`, `/usr/local/lib/python3.6/...`) ;
- la version de Python.

ZAP classe ces deux alertes en Medium et Low. Pourtant, la console du débogueur permet d'exécuter du code Python sur le serveur pour quiconque obtient son code PIN. En contexte, le risque est donc **critique**. De plus, n'importe quel visiteur non connecté peut déclencher l'erreur en saisissant un identifiant inconnu.

Le nom de l'alerte est aussi trompeur : la requête affichée est paramétrée (`?`), elle n'est **pas** vulnérable à l'injection SQL. C'est une fuite de code source, pas une injection.

### En-têtes HTTP (CSP)

| Question | Réponse |
|---|---|
| Réponse concernée | Toutes les réponses HTML, dont `GET /` et `POST /login` |
| Utilisateurs non fiables ? | La page de connexion est publique. Pour une application NOVA SERVICES exposée aux clients, oui |
| Risque | Pas de CSP, donc aucune limite aux scripts exécutés. Une XSS (TIWAP en contient plusieurs) peut charger du code externe ou voler la session |
| Où corriger | Dans l'application (`@app.after_request` qui ajoute les en-têtes) ou sur le reverse proxy devant toutes les applications |
| Vérification | Relancer le scan : les alertes 10038, 10020 et 10021 doivent passer en PASS. Contrôle manuel avec `curl -kI https://localhost:5000` |

L'absence d'un en-tête est une observation technique certaine. Sa gravité métier dépend en revanche de ce qu'il protège : la CSP compte davantage sur une application qui contient des XSS, alors que HSTS n'a aucun impact dans ce labo local.

## 6. Lien avec l'injection SQL et SonarQube

**ZAP n'a détecté aucune injection SQL.** Deux raisons :
1. La page `/sql-injection` exige d'être connecté. ZAP n'étant pas authentifié, il ne l'a jamais atteinte.
2. Le Baseline Scan est passif : il observe les réponses mais n'envoie pas de charges comme `x' OR '1'='1' --`. Même avec accès à la page, il n'aurait pas pu confirmer l'injection.

| | SonarQube (SAST) | ZAP Baseline (DAST) |
|---|---|---|
| Injection SQL de `SQLi.py` | Non détectée (règle absente de l'édition Community) | Non détectée (page non explorée, scan passif) |
| Mode debug / erreur 500 sur `/login` | Non relevé | Détecté (alertes 10099, 90022) |
| Clé Flask, JWT, MD5 | Détectés | Non visibles de l'extérieur |
| En-têtes HTTP | Non analysés | Détectés |

Les deux outils sont complémentaires et aucun des deux n'a trouvé l'injection SQL. Elle a été confirmée par la lecture du code et par les tests du TP précédent. Pour la détecter dynamiquement, il faudrait un scan **authentifié** et **actif** (ou des tests IAST).

## 7. Fiches de traitement NOVA SERVICES

| Champ | Fiche 1 | Fiche 2 | Fiche 3 |
|---|---|---|---|
| Référence | ZAP 10099 + 90022 | ZAP 10038 + 10020 | ZAP 10036 |
| Application | TIWAP, cible de laboratoire | TIWAP, cible de laboratoire | TIWAP, cible de laboratoire |
| Actif métier analogue | Portail client NOVA SERVICES (connexion publique) | Portail client et back-office | Toutes les applications Flask hébergées |
| Impact | Exécution de code sur le serveur via le débogueur, fuite du code et de l'architecture | Aggrave les XSS (vol de session), clickjacking sur les actions sensibles | Aide un attaquant à cibler les failles connues de Werkzeug 2.0.3 et Python 3.6 (fin de vie depuis 2021) |
| Priorité | Critique : exploitable sans compte, impact total | Élevée : défense en profondeur sur une application qui contient des XSS | Moyenne : pas exploitable seul, mais révèle une pile obsolète |
| Responsable | Équipe de développement | Exploitation (reverse proxy), avec le développement | Exploitation |
| Échéance | 23/10/2026 (7 jours) | 15/11/2026 (30 jours) | 15/12/2026 (60 jours) |
| Action | `debug=False` en dehors du poste de développement, gérer l'utilisateur inconnu dans `check_login`, page d'erreur générique | Ajouter `Content-Security-Policy` (avec `frame-ancestors 'none'`) et `X-Content-Type-Options: nosniff` | Servir l'application avec gunicorn derrière un reverse proxy qui masque `Server`, mettre à jour Python |
| Vérification | Test de connexion avec un utilisateur inconnu (réponse 200 ou 401, pas de trace), nouveau scan | Nouveau scan, `curl -kI` | Nouveau scan |
| Statut | Ouvert | Ouvert | Ouvert |

## 8. Intégration continue (GitHub Actions)

Le dépôt est hébergé sur GitHub : le pipeline est donc fait avec GitHub Actions plutôt que GitLab CI. Fichier [.github/workflows/dast.yml](.github/workflows/dast.yml) :

```yaml
name: DAST ZAP

on:
  push:
    paths: ["TIWAP/**", ".github/workflows/dast.yml"]
  workflow_dispatch:

jobs:
  dast_zap:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: TIWAP
    steps:
      - uses: actions/checkout@v4

      - name: Démarrer TIWAP et ZAP
        run: |
          mkdir -p reports && chmod 777 reports
          docker compose up -d --build

      - name: Attendre que TIWAP réponde
        run: |
          for i in $(seq 1 30); do
            curl -ksf https://localhost:5000 > /dev/null && exit 0
            sleep 5
          done
          docker compose logs app
          exit 1

      - name: Scan ZAP Baseline
        run: docker compose exec -T zap zap-baseline.py -t https://app:5000 -m 2 -r zap-report.html -J zap-report.json -I

      - name: Publier les rapports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: zap-report
          path: TIWAP/reports/

      - name: Arrêter les services
        if: always()
        run: docker compose down -v
```

- `chmod 777` : ZAP tourne avec un utilisateur non root et doit pouvoir écrire dans `reports`.
- La boucle `curl` attend que TIWAP réponde avant de lancer le scan, sinon ZAP analyserait une application absente.
- `-I` : les alertes WARN ne font pas échouer le job. TIWAP étant volontairement vulnérable, le pipeline serait sinon toujours en échec. En production, on bloquerait le pipeline sur les vulnérabilités confirmées et de priorité élevée.
- `if: always()` : les rapports sont publiés et les conteneurs arrêtés même si une étape échoue.
- Le dossier `reports/` est exclu de Git : les rapports de CI sont conservés comme artefacts.

![Pipeline GitHub Actions](captures/dast/06-github-actions-pipeline.png)
![Artefact zap-report](captures/dast/07-github-actions-artefact.png)

Limite : l'artefact HTML et JSON n'alimente aucun tableau de bord. Pour suivre les vulnérabilités dans GitHub (onglet Security), il faudrait convertir le rapport au format SARIF.

## 9. Indicateurs de suivi

| Indicateur | Définition et calcul | Source | Fréquence | Responsable | Décision |
|---|---|---|---|---|---|
| Vulnérabilités DAST confirmées ouvertes | Nombre d'alertes qualifiées « confirmé », par priorité | Fiches de traitement / outil de tickets | Hebdomadaire | RSSI | Répartir l'effort de correction entre les équipes |
| Vulnérabilités en retard | Confirmées critiques ou élevées dont l'échéance est dépassée | Outil de tickets | Hebdomadaire | RSSI | Escalader ou bloquer une mise en production |
| Corrections vérifiées par un nouveau scan | Corrections dont l'alerte a disparu au scan suivant / corrections déclarées | Rapports JSON ZAP comparés | Mensuelle | Équipe sécurité | Valider ou rouvrir une correction |
| Couverture DAST des applications critiques | Applications critiques avec au moins un scan dans le mois / applications critiques | Historique des pipelines | Mensuelle | Responsable sécurité applicative | Étendre le DAST aux applications non couvertes |
| Couverture de l'exploration | URL explorées / URL connues de l'application | Rapport ZAP et inventaire des routes | Par scan | Équipe sécurité | Mettre en place un scan authentifié si la couverture est faible (ici, 10 endpoints pour 34 routes déclarées dans `app.py`) |
| Taux d'échec technique des scans | Scans sans rapport exploitable / scans lancés | GitHub Actions | Mensuelle | Exploitation | Corriger le pipeline avant de se fier aux résultats |

Le nombre brut d'alertes n'est pas un indicateur de sécurité : un scan authentifié ferait augmenter ce nombre sans que l'application soit moins sûre.

## 10. Questions de compréhension

**Partie 1**

1. Si l'application ne répond pas, ZAP n'explore rien et produit un rapport vide ou incomplet, qu'on pourrait prendre à tort pour un bon résultat.
2. MongoDB n'est pas utile depuis l'hôte : seule l'application y accède, par le réseau Docker. Exposer le port 27017, avec les identifiants par défaut `username` / `password`, rendrait la base accessible depuis le réseau local.

**Questions finales**

1. Le SAST lit le code source sans l'exécuter. Le DAST interroge l'application en fonctionnement, comme un client HTTP, sans voir le code.
2. ZAP n'a pas accès au code : il ne peut analyser que les pages, formulaires et réponses qu'il obtient en interrogeant l'application.
3. Dans un conteneur, `localhost` désigne le conteneur lui-même. ZAP joint TIWAP par le nom du service `app` sur le réseau Docker.
4. Le scan passif observe les échanges sans rien modifier. Le scan actif envoie des requêtes d'attaque, qui peuvent modifier des données ou perturber l'application : il est réservé à un environnement autorisé.
5. Il n'envoie aucune charge d'injection et n'explore pas les pages qui demandent une authentification. C'est le cas ici : l'injection SQL n'a pas été détectée.
6. Une alerte est un constat de l'outil. Une vulnérabilité confirmée a été vérifiée dans son contexte (code, réponse, exploitabilité). L'alerte « Source Code Disclosure - SQL » en est un exemple : elle signale une fuite de code et non une injection SQL.
7. En croisant la sensibilité des données, l'exposition, la facilité d'exploitation et l'impact, sans recopier le niveau de ZAP. L'erreur 500 classée Low par ZAP est ici critique.
8. Pour garder une preuve de chaque contrôle, comparer les scans dans le temps et vérifier qu'une correction a bien supprimé l'alerte.
9. Publier les ports uniquement sur `127.0.0.1`, ne pas exposer la base, arrêter les conteneurs après usage, et ne jamais déployer TIWAP sur un serveur accessible depuis Internet.
10. Le délai médian de correction, le nombre de vulnérabilités en retard et le pourcentage de corrections vérifiées par un nouveau scan.

## 11. Conclusion

Le Baseline Scan a relevé 15 alertes, dont surtout des en-têtes HTTP manquants. Le résultat le plus important est une erreur 500 qui expose le débogueur Werkzeug. ZAP la classe Low et Medium alors qu'elle est critique en contexte. Ni ZAP ni SonarQube n'ont détecté l'injection SQL : le DAST passif et non authentifié n'a exploré qu'une petite partie de l'application.

Le DAST voit ce que le SAST ne voit pas (configuration du serveur, en-têtes, erreurs en fonctionnement), et inversement (secrets et faiblesses dans le code). Pour NOVA SERVICES, ces outils sont des sources d'information à qualifier, pas une garantie de sécurité. La prochaine étape serait un scan authentifié puis un scan actif dans un environnement de test dédié.

Nettoyage : `docker compose down`, puis `docker compose ps` pour vérifier.
