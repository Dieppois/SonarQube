# SonarQube : analyse de TIWAP

Analyse de sécurité de [TIWAP](https://github.com/tombstoneghost/TIWAP), une application web volontairement vulnérable, avec SonarQube, puis correction d'une injection SQL que l'outil ne détecte pas.

Le détail de la démarche et des résultats est dans [rapport.md](rapport.md).

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

## Licence

TIWAP est distribué sous sa propre licence, voir [TIWAP/LICENSE](TIWAP/LICENSE).
