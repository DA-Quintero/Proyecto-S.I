#!/usr/bin/env python3
"""
===========================================================================
 Verificación antes/después del parche  ·  P01 - Integrante 3
 App: Portal de Facturas UAO
===========================================================================

Ejecuta, desde un estado limpio y con un solo comando, la misma batería de
pruebas sobre las dos versiones de la aplicación:

  ANTES   = app/app.py del commit vulnerable (VULNERABLE_REF, por defecto 262f30c)
  DESPUÉS = app/ del árbol de trabajo actual (con la política del Integrante 2)

Para cada versión:
  1. Copia la app a un directorio temporal con .env de ejemplo y base nueva.
  2. Arranca el servidor en un puerto libre.
  3. Ejecuta scripts/validar_idor.py (mismos identificadores en ambas).
  4. Ejecuta el test de regresión tests/test_regresion_idor.py.
  5. Guarda las salidas reales en scripts/evidencias/.

Al final imprime la tabla comparativa y comprueba el criterio de cierre:
  - antes:   validar_idor.py -> código 1 y el test de regresión FALLA
  - después: validar_idor.py -> código 0 y el test de regresión PASA

Uso (desde la raíz del repositorio; requiere git para extraer la versión vulnerable):
    python scripts/verificar_antes_despues.py

Código de salida: 0 si se cumple el criterio de cierre, 1 si no.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
APP_DIR = RAIZ / "app"
EVIDENCIAS = RAIZ / "scripts" / "evidencias"
VULNERABLE_REF = os.environ.get("P01_VULNERABLE_REF", "262f30c")

sys.path.insert(0, str(RAIZ))
from tests.test_regresion_idor import ServidorLimpio  # noqa: E402

CASOS = [
    ("Objeto propio autorizado", "factura", 2001),
    ("Objeto ajeno que exponía info.", "factura", 1001),
    ("Objeto ajeno que exponía info.", "factura", 1002),
    ("Objeto ajeno que exponía info.", "factura", 1003),
    ("Objeto ajeno que exponía info.", "factura", 1004),
    ("Objeto ajeno ya protegido", "documento", 5001),
]
RUTA = {"factura": "/api/invoices/{}", "documento": "/api/documents/{}"}


def preparar_version_vulnerable(destino: Path) -> Path:
    """Copia app/ y reemplaza app.py por el del commit vulnerable."""
    app = destino / "app"
    shutil.copytree(APP_DIR, app, ignore=shutil.ignore_patterns("*.db", "__pycache__", ".env"))
    try:
        codigo = subprocess.run(["git", "show", f"{VULNERABLE_REF}:app/app.py"], cwd=RAIZ,
                                check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise SystemExit(f"[ERROR] No se pudo extraer la versión vulnerable ({VULNERABLE_REF}) "
                         f"con git: {e}")
    (app / "app.py").write_bytes(codigo)
    return app


def consultar_casos(base_url: str, token: str) -> list:
    """Registra HTTP y si llegaron datos para cada caso (para la tabla comparativa)."""
    filas = []
    for caso, tipo, rid in CASOS:
        req = urllib.request.Request(base_url + RUTA[tipo].format(rid),
                                     headers={"Authorization": "Bearer " + token})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                st, cuerpo = r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            st, cuerpo = e.code, json.loads(e.read())
        datos = bool({"numero", "monto", "contenido"} & set(cuerpo))
        filas.append((caso, f"{tipo} {rid}", st, datos))
    return filas


def login(base_url: str, usuario: str, clave: str) -> str:
    req = urllib.request.Request(base_url + "/api/login", method="POST",
                                 data=json.dumps({"username": usuario, "password": clave}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())["token"]


def ejecutar(cmd, entorno) -> tuple:
    p = subprocess.run(cmd, cwd=RAIZ, env=entorno, capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout + p.stderr)


def verificar(nombre: str, app_dir: Path) -> dict:
    print(f"\n>>> Versión {nombre.upper()}: {app_dir}")
    entorno = dict(os.environ, PYTHONIOENCODING="utf-8")

    # 1-3) Servidor limpio + validar_idor.py + tabla de casos
    servidor = ServidorLimpio(app_dir)
    try:
        base_url = servidor.iniciar()
        cred = servidor.credenciales
        env_script = dict(entorno, APP_BASE_URL=base_url,
                          APP_USER_B=cred["APP_USER_B"], APP_PASS_B=cred["APP_PASS_B"])
        cod_script, salida_script = ejecutar(
            [sys.executable, "scripts/validar_idor.py"], env_script)
        filas = consultar_casos(base_url, login(base_url, cred["APP_USER_B"], cred["APP_PASS_B"]))
    finally:
        servidor.detener()

    # 4) Test de regresión (levanta su propio servidor limpio)
    cod_test, salida_test = ejecutar(
        [sys.executable, "-m", "unittest", "tests.test_regresion_idor", "-v"],
        dict(entorno, P01_APP_DIR=str(app_dir)))

    print(f"    validar_idor.py      -> código {cod_script}")
    print(f"    test de regresión    -> {'PASA' if cod_test == 0 else 'FALLA'} (código {cod_test})")
    return {"script": (cod_script, salida_script), "test": (cod_test, salida_test), "filas": filas}


def guardar(nombre_archivo: str, titulo: str, comando: str, codigo: int, salida: str) -> None:
    EVIDENCIAS.mkdir(parents=True, exist_ok=True)
    cabecera = (f"# {titulo}\n# Fecha: {datetime.now():%Y-%m-%d %H:%M:%S}\n"
                f"# Comando: {comando}\n# Código de salida: {codigo}\n\n")
    (EVIDENCIAS / nombre_archivo).write_text(cabecera + salida, encoding="utf-8")


def main() -> int:
    print("=" * 78)
    print(" VERIFICACIÓN ANTES / DESPUÉS DEL PARCHE · P01 Integrante 3")
    print("=" * 78)
    tmp = Path(tempfile.mkdtemp(prefix="p01_antes_"))
    try:
        antes = verificar("antes", preparar_version_vulnerable(tmp))
        despues = verificar("después", APP_DIR)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    cmd_script = "python scripts/validar_idor.py"
    cmd_test = "python -m unittest tests.test_regresion_idor -v"
    guardar("07_validar_idor_antes.txt", f"validar_idor.py sobre la versión vulnerable "
            f"({VULNERABLE_REF})", cmd_script, *antes["script"])
    guardar("08_validar_idor_despues.txt", "validar_idor.py sobre la versión corregida",
            cmd_script, *despues["script"])
    guardar("09_test_regresion_antes.txt", f"Test de regresión sobre la versión vulnerable "
            f"({VULNERABLE_REF})", cmd_test, *antes["test"])
    guardar("10_test_regresion_despues.txt", "Test de regresión sobre la versión corregida",
            cmd_test, *despues["test"])

    # Tabla comparativa (Guía P01 §5)
    lineas = []
    cab = f"{'caso':<31}| {'recurso':<15}| {'antes':<14}| {'después':<14}| ¿datos ajenos después?"
    lineas += [cab, "-" * len(cab)]
    for (caso, rec, st_a, d_a), (_, _, st_d, d_d) in zip(antes["filas"], despues["filas"]):
        ajeno = "No aplica" if caso.startswith("Objeto propio") else ("SÍ" if d_d else "No")
        lineas.append(f"{caso:<31}| {rec:<15}| {st_a} {'con datos' if d_a else 'sin datos':<10}"
                      f"| {st_d} {'con datos' if d_d else 'sin datos':<10}| {ajeno}")
    lineas.append("-" * len(cab))
    lineas.append(f"{'validar_idor.py (código)':<31}| {'':<15}| {antes['script'][0]:<14}"
                  f"| {despues['script'][0]:<14}|")
    lineas.append(f"{'test de regresión':<31}| {'':<15}| "
                  f"{'FALLA' if antes['test'][0] else 'PASA':<14}| "
                  f"{'FALLA' if despues['test'][0] else 'PASA':<14}|")

    cierre = (antes["script"][0] == 1 and antes["test"][0] != 0
              and despues["script"][0] == 0 and despues["test"][0] == 0)
    lineas.append("")
    lineas.append("CRITERIO DE CIERRE: " + (
        "CUMPLIDO — el mismo token que obtenía facturas ajenas recibe 403 sin datos y el "
        "acceso a la factura propia sigue funcionando." if cierre else
        "NO CUMPLIDO — revisar las salidas guardadas en scripts/evidencias/."))
    tabla = "\n".join(lineas)
    print("\n" + tabla)
    guardar("11_tabla_antes_despues.txt", "Tabla comparativa antes/después",
            "python scripts/verificar_antes_despues.py", 0 if cierre else 1, tabla + "\n")
    print(f"\nEvidencias guardadas en {EVIDENCIAS.relative_to(RAIZ)}/ (07 a 11).")
    return 0 if cierre else 1


if __name__ == "__main__":
    raise SystemExit(main())
