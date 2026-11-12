#!/usr/bin/env python3
"""
===========================================================================
 Test de regresión IDOR  ·  P01 - Integrante 3 (Pruebas y verificación)
 App: Portal de Facturas UAO
===========================================================================

Objetivo (Guía P01, §7): un test que FALLE con la aplicación vulnerable y
PASE con la aplicación corregida. Comprueba, como mínimo, que:

  * Benito (Usuario B) puede consultar su propia factura 2001 (200 con datos).
  * Con el MISMO token, las facturas ajenas 1001-1004 responden 403
    y el cuerpo NO contiene ningún dato de esas facturas.
  * El documento ajeno 5001 (ya protegido) sigue respondiendo 403.
  * Sin token la respuesta es 401.
  * Alicia (Usuario A) conserva el acceso legítimo a sus facturas.

Ejecución desde un estado limpio
--------------------------------
El test NO depende de un servidor ya levantado ni de una base existente:
copia la carpeta de la aplicación a un directorio temporal, crea su .env a
partir de .env.example, arranca el servidor en un puerto libre (base SQLite
nueva, sembrada con los mismos identificadores fijos) y lo detiene al final.

    python -m unittest tests.test_regresion_idor -v      (desde la raíz)

Variables opcionales:
    P01_APP_DIR   carpeta de la aplicación a probar (por defecto ./app).
                  scripts/verificar_antes_despues.py la usa para probar
                  la versión vulnerable y la corregida con el mismo test.

Dependencias: solo biblioteca estándar (unittest, urllib, subprocess).
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
APP_DIR = Path(os.environ.get("P01_APP_DIR", RAIZ / "app")).resolve()

# Identificadores FIJOS: los mismos de la matriz de permisos y del script
# scripts/validar_idor.py (no cambiarlos entre la ejecución antes y después).
FACTURA_PROPIA_B = 2001
FACTURAS_AJENAS_A = (1001, 1002, 1003, 1004)
DOCUMENTO_AJENO_A = 5001

# Valores que identifican los datos privados de las facturas de Alicia.
# Ninguno debe aparecer en una respuesta 403.
DATOS_PRIVADOS_A = {
    1001: ("FAC-A-1001", "Servicios de consultoría", "1520000"),
    1002: ("FAC-A-1002", "Licencia de software anual", "980000"),
    1003: ("FAC-A-1003", "Soporte técnico trimestral", "450000"),
    1004: ("FAC-A-1004", "Capacitación en seguridad", "760000"),
}
CAMPOS_DEL_OBJETO = {"numero", "concepto", "monto", "fecha", "propietario_user_id",
                     "titulo", "contenido"}


def _leer_env(ruta: Path) -> dict:
    valores = {}
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if linea and not linea.startswith("#") and "=" in linea:
            k, v = linea.split("=", 1)
            valores[k.strip()] = v.strip().strip('"').strip("'")
    return valores


def _puerto_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServidorLimpio:
    """Arranca una copia aislada de la app con base de datos nueva."""

    def __init__(self, app_dir: Path):
        self.app_dir = app_dir
        self.tmp = Path(tempfile.mkdtemp(prefix="p01_app_"))
        self.proc = None
        self.log = None

    def iniciar(self) -> str:
        destino = self.tmp / "app"
        shutil.copytree(self.app_dir, destino,
                        ignore=shutil.ignore_patterns("*.db", "__pycache__", ".env"))
        shutil.copy(destino / ".env.example", destino / ".env")
        self.credenciales = _leer_env(destino / ".env")

        puerto = _puerto_libre()
        entorno = dict(os.environ, APP_HOST="127.0.0.1", APP_PORT=str(puerto),
                       PYTHONIOENCODING="utf-8")
        self.log = open(self.tmp / "servidor.log", "w", encoding="utf-8")
        self.proc = subprocess.Popen([sys.executable, "app.py"], cwd=destino, env=entorno,
                                     stdout=self.log, stderr=subprocess.STDOUT)
        self.base_url = f"http://127.0.0.1:{puerto}"
        limite = time.time() + 15
        while time.time() < limite:
            if self.proc.poll() is not None:
                raise RuntimeError("La aplicación terminó al arrancar; ver servidor.log")
            try:
                with urllib.request.urlopen(self.base_url + "/api/health", timeout=1):
                    return self.base_url
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("La aplicación no respondió en 15 s")

    def detener(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.log:
            self.log.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestRegresionIDOR(unittest.TestCase):
    """Regresión de CWE-639 en GET /api/invoices/<id> (sesión de Benito)."""

    @classmethod
    def setUpClass(cls):
        cls.servidor = ServidorLimpio(APP_DIR)
        try:
            cls.base_url = cls.servidor.iniciar()
        except Exception:
            cls.servidor.detener()
            raise
        cred = cls.servidor.credenciales
        cls.token_b = cls._login(cred["APP_USER_B"], cred["APP_PASS_B"])
        cls.token_a = cls._login(cred["APP_USER_A"], cred["APP_PASS_A"])

    @classmethod
    def tearDownClass(cls):
        cls.servidor.detener()

    # ----------------------------- utilidades ------------------------------
    @classmethod
    def _http(cls, metodo, ruta, token=None, cuerpo=None):
        datos = json.dumps(cuerpo).encode("utf-8") if cuerpo is not None else None
        headers = {"Accept": "application/json"}
        if cuerpo is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(cls.base_url + ruta, data=datos,
                                     headers=headers, method=metodo)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8")

    @classmethod
    def _login(cls, usuario, clave) -> str:
        st, cuerpo = cls._http("POST", "/api/login",
                               cuerpo={"username": usuario, "password": clave})
        if st != 200:
            raise RuntimeError(f"Login de prueba fallido (HTTP {st})")
        return json.loads(cuerpo)["token"]

    def _assert_sin_datos(self, cuerpo: str, valores_privados=()):
        datos = json.loads(cuerpo)
        filtrados = CAMPOS_DEL_OBJETO & set(datos)
        self.assertFalse(filtrados, f"La respuesta expone campos del objeto: {sorted(filtrados)}")
        for valor in valores_privados:
            self.assertNotIn(valor, cuerpo, f"La respuesta contiene el dato privado {valor!r}")

    # ------------------------- acceso legítimo -----------------------------
    def test_01_factura_propia_200_con_datos(self):
        """Benito consulta su factura 2001 -> 200 con sus datos."""
        st, cuerpo = self._http("GET", f"/api/invoices/{FACTURA_PROPIA_B}", self.token_b)
        self.assertEqual(st, 200)
        datos = json.loads(cuerpo)
        self.assertEqual(datos["id"], FACTURA_PROPIA_B)
        self.assertEqual(datos["numero"], "FAC-B-2001")
        self.assertEqual(datos["propietario_user_id"], 2)

    def test_02_propietaria_conserva_acceso(self):
        """Alicia sigue viendo sus facturas 1001-1004 (el parche no rompe el acceso legítimo)."""
        for fid in FACTURAS_AJENAS_A:
            with self.subTest(factura=fid):
                st, cuerpo = self._http("GET", f"/api/invoices/{fid}", self.token_a)
                self.assertEqual(st, 200)
                self.assertEqual(json.loads(cuerpo)["propietario_user_id"], 1)

    # ------------------------- regresión del IDOR --------------------------
    def test_03_factura_ajena_403_sin_datos(self):
        """Con el token de Benito, las facturas de Alicia -> 403 sin datos del objeto."""
        for fid in FACTURAS_AJENAS_A:
            with self.subTest(factura=fid):
                st, cuerpo = self._http("GET", f"/api/invoices/{fid}", self.token_b)
                self.assertEqual(st, 403, f"factura {fid}: se esperaba 403 y llegó {st}")
                self._assert_sin_datos(cuerpo, DATOS_PRIVADOS_A[fid])

    def test_04_documento_ajeno_sigue_protegido(self):
        """Documento 5001 de Alicia con el token de Benito -> 403 sin datos (antes y después)."""
        st, cuerpo = self._http("GET", f"/api/documents/{DOCUMENTO_AJENO_A}", self.token_b)
        self.assertEqual(st, 403)
        self._assert_sin_datos(cuerpo, ("Contrato marco A", "Cláusulas confidenciales"))

    def test_05_sin_token_401(self):
        """Sin sesión la factura 1001 -> 401 sin datos."""
        st, cuerpo = self._http("GET", "/api/invoices/1001")
        self.assertEqual(st, 401)
        self._assert_sin_datos(cuerpo, DATOS_PRIVADOS_A[1001])

    def test_06_listado_solo_propio(self):
        """El listado de Benito solo incluye su factura 2001."""
        st, cuerpo = self._http("GET", "/api/invoices", self.token_b)
        self.assertEqual(st, 200)
        ids = [f["id"] for f in json.loads(cuerpo)["invoices"]]
        self.assertEqual(ids, [FACTURA_PROPIA_B])


if __name__ == "__main__":
    unittest.main(verbosity=2)
