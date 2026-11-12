#!/usr/bin/env python3
"""
===========================================================================
 Script de validación controlada de IDOR  ·  P01 - Integrante 1
 App: Portal de Facturas UAO
===========================================================================

Finalidad (y SOLO esta): validar de forma académica y reproducible si la
aplicación comprueba la propiedad del recurso antes de entregarlo. Recorre
una LISTA FIJA de identificadores ficticios preparados para el proyecto y
clasifica cada caso según la tabla de la Guía P01 (§5):

  Caso                              Esperado (política)   Resultado antes del parche
  --------------------------------  --------------------  --------------------------
  Objeto propio autorizado          200 con datos         200 con datos
  Objeto ajeno que exponía info.    403 sin datos         200 con datos  (IDOR)
  Objeto ajeno ya protegido         403 sin datos         403 sin datos

NO es una herramienta de enumeración ni de extracción masiva: la lista de
identificadores está fijada en el código y se limita a los datos ficticios
del escenario P01. No descubre identificadores ni itera rangos.

Procedimiento (Guía P01, §4 y §5):
  1. Autenticarse como Usuario B.
  2. Consultar un recurso PROPIO de B                 -> control legítimo (200).
  3. Con la MISMA sesión, consultar 4 facturas AJENAS -> prueba de acceso indebido.
  4. Con la MISMA sesión, consultar 1 documento AJENO ya protegido -> contraste (403).
  5. Registrar código HTTP y si se devolvió información del recurso.

Requisitos cubiertos: sesión autenticada de prueba; 1 recurso propio + 3..5
ajenos (aquí 4 facturas); lista fija de identificadores; registro de códigos
HTTP y de si hay datos; salida organizada; manejo de errores de conexión y
autenticación; credenciales por variables de entorno; sin mostrar secretos.

Dependencias: solo biblioteca estándar (urllib, json, os). No usa 'requests'.

Uso (con la app corriendo: python ../app/app.py):
    python validar_idor.py

Variables de entorno (ver app/.env.example):
    APP_USER_B, APP_PASS_B   credenciales del Usuario B (sesión de la prueba)
    APP_BASE_URL             opcional, por defecto http://127.0.0.1:8008
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ---- Carga de .env de la carpeta de la app (para no duplicar credenciales) --
APP_DIR = (Path(__file__).resolve().parent.parent / "app")
sys.path.insert(0, str(APP_DIR))
try:
    import _env  # type: ignore
    _env.cargar_dotenv(APP_DIR / ".env")
except Exception:
    pass  # si no está, se usan las variables del entorno del sistema

BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8008").rstrip("/")
USER_B = os.environ.get("APP_USER_B")
PASS_B = os.environ.get("APP_PASS_B")

# ---- Conjunto de prueba FIJO (coincide con la matriz de permisos) -----------
RECURSO_PROPIO_B = ("factura", 2001)                 # 200 legítimo
RECURSOS_AJENOS_EXPUESTOS = [("factura", i) for i in (1001, 1002, 1003, 1004)]  # IDOR
RECURSO_AJENO_PROTEGIDO = ("documento", 5001)        # 403 ya protegido (contraste)

RUTA = {"factura": "/api/invoices/{}", "documento": "/api/documents/{}"}


# --------------------------- utilidades HTTP --------------------------------
def http_json(metodo, ruta, token=None, cuerpo=None):
    url = BASE_URL + ruta
    datos = json.dumps(cuerpo).encode("utf-8") if cuerpo is not None else None
    headers = {"Accept": "application/json"}
    if cuerpo is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=datos, headers=headers, method=metodo)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, _parse(r.read())
    except urllib.error.HTTPError as e:
        return e.code, _parse(e.read())


def _parse(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return raw.decode("utf-8", "replace")


def enmascarar(valor: str, visibles: int = 4) -> str:
    if not valor:
        return "<vacío>"
    return valor[:visibles] + "…(" + str(len(valor) - visibles) + " ocultos)"


def tiene_datos(payload) -> bool:
    """True si la respuesta contiene información del recurso (número/monto/contenido)."""
    if not isinstance(payload, dict):
        return False
    return bool({"numero", "monto"} & set(payload)) or "contenido" in payload


# --------------------------- evaluación por caso ----------------------------
def evaluar(caso, tipo, rid, esperado_http, es_propio, token):
    st, data = http_json("GET", RUTA[tipo].format(rid), token=token)
    datos = tiene_datos(data)
    if es_propio:
        idor = False
        veredicto = "OK (acceso legítimo)" if (st == 200 and datos) else f"inesperado ({st})"
    else:
        idor = (st == 200 and datos)  # recurso ajeno que entrega datos = IDOR
        if idor:
            veredicto = "IDOR: acceso indebido"
        elif st in (403, 401) and not datos:
            veredicto = "correcto (denegado)"
        else:
            veredicto = f"inesperado ({st})"
    return {"caso": caso, "tipo": tipo, "id": rid, "esperado": esperado_http,
            "http": st, "datos": datos, "idor": idor, "veredicto": veredicto,
            "payload": data if isinstance(data, dict) else {}}


# ------------------------------- main ---------------------------------------
def main() -> int:
    print("=" * 78)
    print(" VALIDACIÓN CONTROLADA DE IDOR · P01 Integrante 1 · Portal de Facturas UAO")
    print("=" * 78)
    print(f" URL base        : {BASE_URL}")

    if not USER_B or not PASS_B:
        print("\n[ERROR] Faltan credenciales APP_USER_B / APP_PASS_B.")
        print("        Copia app/.env.example a .env y define las variables.")
        return 2
    print(f" Usuario sesión  : {USER_B}")

    # 1) Autenticación del Usuario B --------------------------------------
    try:
        st, data = http_json("POST", "/api/login",
                              cuerpo={"username": USER_B, "password": PASS_B})
    except urllib.error.URLError as e:
        print(f"\n[ERROR] No se pudo conectar a la aplicación: {e.reason}")
        print("        ¿Está corriendo 'python app.py' en app?")
        return 3
    if st != 200 or not isinstance(data, dict) or "token" not in data:
        print(f"\n[ERROR] Autenticación fallida (HTTP {st}): {data}")
        return 4
    token = data["token"]
    print(f"\n[OK] Autenticado como '{USER_B}' (user_id={data.get('user_id')}).")
    print(f"     Token de sesión: {enmascarar(token)}")

    # 2-4) Comprobaciones -------------------------------------------------
    filas = []
    t, rid = RECURSO_PROPIO_B
    filas.append(evaluar("Objeto propio autorizado", t, rid, "200 con datos", True, token))
    for t, rid in RECURSOS_AJENOS_EXPUESTOS:
        filas.append(evaluar("Objeto ajeno que exponía info.", t, rid, "403 sin datos", False, token))
    t, rid = RECURSO_AJENO_PROTEGIDO
    filas.append(evaluar("Objeto ajeno ya protegido", t, rid, "403 sin datos", False, token))

    # 5) Tabla de resultados ---------------------------------------------
    print("\n" + "-" * 78)
    print(" RESULTADOS (sesión única del Usuario B)")
    print("-" * 78)
    cab = f"{'caso':<30} | {'recurso':<14} | {'esperado':<13} | {'HTTP':>4} | {'datos':<5} | veredicto"
    print(cab); print("-" * len(cab))
    idor = 0
    for f in filas:
        if f["idor"]:
            idor += 1
        rec = f"{f['tipo']} {f['id']}"
        print(f"{f['caso']:<30} | {rec:<14} | {f['esperado']:<13} | "
              f"{f['http']:>4} | {('SÍ' if f['datos'] else 'no'):<5} | {f['veredicto']}")
    print("-" * len(cab))

    # Evidencia central: una factura ajena filtrada (sin secretos).
    ej = next((f for f in filas if f["idor"]), None)
    if ej:
        p = ej["payload"]
        print(f"\n[EVIDENCIA] Con el token de '{USER_B}' se obtuvo HTTP {ej['http']} y datos de "
              f"la {ej['tipo']} {ej['id']} (propietario Usuario A):")
        print(f"            numero={p.get('numero')}  concepto={p.get('concepto')!r}  "
              f"monto={p.get('monto')}  propietario_user_id={p.get('propietario_user_id')}")

    print("\n" + "=" * 78)
    if idor > 0:
        print(f" RESULTADO: VULNERABLE a IDOR — {idor} factura(s) ajena(s) expuesta(s) con 200 y datos.")
        print(" El endpoint de facturas NO comprueba la propiedad del objeto (CWE-639).")
        print(" (El endpoint de documentos sí la comprueba: 403 en el objeto ajeno protegido.)")
        print("=" * 78)
        return 1   # código != 0: hallazgo presente (útil para el test del Integrante 3)
    print(" RESULTADO: no se expusieron recursos ajenos.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
