import unittest

from escudobit_vigilante import step

TB = 10**12
LIMIT = 10 * TB


class VigilanteTest(unittest.TestCase):
    def test_primera_vez_empieza_en_cero(self):
        s, alerts, action = step(None, "2026-12", 5 * TB, LIMIT)
        self.assertEqual(0, s["total"])
        self.assertEqual([], alerts)
        self.assertIsNone(action)

    def test_avisa_una_sola_vez_por_nivel(self):
        s, _, _ = step(None, "2026-12", 0, LIMIT)
        s, alerts, action = step(s, "2026-12", 5 * TB, LIMIT)
        self.assertEqual([("nivel", 50)], alerts)
        self.assertIsNone(action)
        s, alerts, _ = step(s, "2026-12", 5 * TB + 1, LIMIT)
        self.assertEqual([], alerts)

    def test_pausa_al_90_y_no_repite(self):
        s, _, _ = step(None, "2026-12", 0, LIMIT)
        s, alerts, action = step(s, "2026-12", 9 * TB, LIMIT)
        self.assertEqual([("nivel", 50), ("nivel", 80), ("nivel", 90)], alerts)
        self.assertEqual("pausar", action)
        self.assertTrue(s["paused"])
        s, alerts, action = step(s, "2026-12", 9 * TB + 10, LIMIT)
        self.assertIsNone(action)
        self.assertEqual([], alerts)

    def test_reinicio_de_la_maquina_no_pierde_la_cuenta(self):
        s, _, _ = step(None, "2026-12", 0, LIMIT)
        s, _, _ = step(s, "2026-12", 3 * TB, LIMIT)
        s, _, _ = step(s, "2026-12", 1 * TB, LIMIT)  # el contador del sistema volvió a cero
        self.assertEqual(4 * TB, s["total"])

    def test_mes_nuevo_reinicia_y_reanuda(self):
        s, _, _ = step(None, "2026-12", 0, LIMIT)
        s, _, _ = step(s, "2026-12", 9 * TB, LIMIT)
        s, alerts, action = step(s, "2027-01", 9 * TB + 100, LIMIT)
        self.assertEqual("reanudar", action)
        self.assertFalse(s["paused"])
        self.assertEqual(100, s["total"])
        self.assertEqual([], s["alerted"])
        self.assertIn(("nuevo_mes", 0), alerts)


if __name__ == "__main__":
    unittest.main()
