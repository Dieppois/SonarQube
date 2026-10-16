# Tests de non-régression - injection SQL (sqli_low / sqli_medium)
# À lancer depuis le dossier TIWAP : python -m pytest tests -v
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnerabilities import SQLi


def test_recherche_legitime_par_id():
    assert SQLi.sqli_medium("1") == [(1, "admin")]


def test_injection_userid_ne_retourne_rien():
    assert SQLi.sqli_medium("1' OR '1'='1") == []


def test_injection_login_ne_contourne_pas_le_mot_de_passe():
    assert SQLi.sqli_low("x' OR '1'='1' --", "a") == []
