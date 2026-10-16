# SonarQube : analyse de TIWAP

Analyse de sécurité de [TIWAP](https://github.com/tombstoneghost/TIWAP), une application web volontairement vulnérable, en deux temps :

- analyse statique avec SonarQube, puis correction d'une injection SQL que l'outil ne détecte pas ([rapport.md](rapport.md)) ;
- analyse dynamique avec OWASP ZAP ([rapport-owasp.md](rapport-owasp.md)).

## Contenu

- `compose.yaml` : SonarQube Community, PostgreSQL et SonarScanner CLI
- `TIWAP/` : code analysé, avec la correction dans `vulnerabilities/SQLi.py` et les tests dans `tests/`
- `captures/` : captures d'écran utilisées dans le rapport

## Lancement

Prérequis : Docker et Docker Compose.

```bash
cp .env.example .env        # puis renseigner POSTGRES_PASSWORD
docker compose up -d
```

SonarQube est accessible sur http://127.0.0.1:9000. Crée un projet `tiwap` et génère un jeton d'analyse, puis lance le scan :

```bash
SONAR_TOKEN=<jeton> docker compose run --rm -e SONAR_TOKEN scanner
```

## Tests

```bash
cd TIWAP
python -m pytest tests -v
```

## Analyse dynamique avec OWASP ZAP

Scan de référence (Baseline Scan, passif) de TIWAP en fonctionnement. Le détail est dans [rapport-owasp.md](rapport-owasp.md).

- `TIWAP/docker-compose.yml` : TIWAP, MongoDB et ZAP
- `rapports-zap/` : rapports HTML et JSON du scan
- `.github/workflows/dast.yml` : scan automatique à chaque modification de `TIWAP/`, rapports publiés en artefact

```bash
cd TIWAP
mkdir -p reports
docker compose up -d --build
docker compose exec zap zap-baseline.py -t https://app:5000 -m 2 -r zap-report.html -J zap-report.json
docker compose down
```

TIWAP est accessible sur https://localhost:5000 (certificat auto-signé). Les rapports sont écrits dans `TIWAP/reports/`.

## Licence

TIWAP est distribué sous sa propre licence, voir [TIWAP/LICENSE](TIWAP/LICENSE).
