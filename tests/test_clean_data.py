import sys
import unittest
from pathlib import Path

# Ajoute le dossier src au chemin Python pour pouvoir importer clean_data
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import clean_data


class TestCleaning(unittest.TestCase):

    # Vérifie que les différents formats de date sont bien normalisés
    def test_timestamp_formats(self):
        self.assertEqual(
            clean_data.normalize_timestamp("2026-03-10 02:31:16")[0],
            "2026-03-10 02:31:16"
        )
        self.assertEqual(
            clean_data.normalize_timestamp("10/03/2026 09:19")[0],
            "2026-03-10 09:19:00"
        )
        self.assertEqual(
            clean_data.normalize_timestamp("2026-03-17T12:30:05Z")[0],
            "2026-03-17 12:30:05"
        )

    # Vérifie la normalisation des résultats d'authentification
    def test_auth_result(self):
        for v in ["SUCCESS", "Success", "success"]:
            self.assertEqual(
                clean_data.normalize_auth_result(v),
                "SUCCESS"
            )

        for v in ["FAILED", "Failed", "failed", "FAILURE"]:
            self.assertEqual(
                clean_data.normalize_auth_result(v),
                "FAILURE"
            )

    # Vérifie qu'une IP valide est conservée et qu'une IP invalide est rejetée
    def test_ip(self):
        self.assertEqual(
            clean_data.validate_ip("10.0.0.1"),
            "10.0.0.1"
        )
        self.assertEqual(
            clean_data.validate_ip("192.168.1.256"),
            ""
        )

    # Vérifie que les niveaux de sévérité sont mis en majuscules
    def test_severity(self):
        self.assertEqual(
            clean_data.normalize_severity("High"),
            "HIGH"
        )
        self.assertEqual(
            clean_data.normalize_severity("critical"),
            "CRITICAL"
        )


if __name__ == "__main__":
    unittest.main()