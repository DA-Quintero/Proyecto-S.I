"""
===========================================================================
 PORTAL DE FACTURAS UAO  ·  Aplicación de prácticas del Proyecto P01
 Seguridad Informática — Control de acceso e IDOR sobre objetos
===========================================================================

Qué es esta aplicación
----------------------
Backend/API REST que gestiona FACTURAS y DOCUMENTOS pertenecientes a usuarios.
Es la **aplicación base del proyecto P01**: el equipo la construye para demostrar
sobre ella una vulnerabilidad de control de acceso (IDOR), corregirla con una
política centralizada y verificar el parche. (El curso no proporciona una app;
la aplicación a evaluar es esta, creada como parte del proyecto.)

Estado del código en este punto del proyecto (ANTES del parche)
---------------------------------------------------------------
La aplicación es DELIBERADAMENTE VULNERABLE a IDOR (CWE-639) en el endpoint de
detalle de facturas: `GET /api/invoices/<id>` comprueba la AUTENTICACIÓN pero NO
la AUTORIZACIÓN sobre el objeto (no verifica que la factura pertenezca al usuario
de la sesión). Para contraste pedagógico, el endpoint de documentos
`GET /api/documents/<id>` SÍ comprueba la propiedad: muestra que el patrón
correcto existía en el código y que el fallo en facturas es una omisión.

Separación de responsabilidades (Guía P01)
-------------------------------------------
- Integrante 1 (este entregable): construye la app, prepara cuentas/objetos y
  REPRODUCE el fallo. NO implementa el parche ni el test de regresión.
- Integrante 2: implementará la política centralizada de autorización (middleware
  único) sobre el endpoint vulnerable. Punto de extensión señalado en el código.
- Integrante 3: creará el test de regresión (antes falla / después pasa).

Tecnología
----------
Solo biblioteca estándar de Python 3 (http.server, sqlite3, hashlib, secrets,
json). Sin dependencias externas. Sirve además una pequeña interfaz web estática
(carpeta ./web) para la demostración en vivo.

Modelo de datos
---------------
  users(id, username, nombre, salt, password_hash)
  invoices(id, user_id -> users.id, numero, concepto, monto, fecha)
  documents(id, user_id -> users.id, titulo, contenido, fecha)
  sessions(token, user_id -> users.id, created_at)

API
---
  GET  /api/health            -> estado del servicio (sin auth)
  POST /api/login             -> {username, password} => {token, user_id, nombre}
  GET  /api/me                -> perfil del usuario autenticado
  GET  /api/invoices          -> lista SOLO las facturas propias (correcto)
  GET  /api/invoices/<id>     -> VULNERABLE IDOR: no comprueba propiedad
  GET  /api/documents         -> lista SOLO los documentos propios (correcto)
  GET  /api/documents/<id>    -> PROTEGIDO: comprueba propiedad (403 si ajeno)
  GET  /                      -> interfaz web de demostración (web/index.html)
"""
from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import secrets
import sqlite3
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import _env  # cargador de .env local (credenciales por variables de entorno)

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
DB_PATH = BASE_DIR / "facturas.db"
HOST = os.environ.get("APP_HOST", "127.0.0.1")
PORT = int(os.environ.get("APP_PORT", "8008"))

# --- Credenciales de prueba desde variables de entorno ----------------------
_env.cargar_dotenv()
USER_A = _env.requerir("APP_USER_A")
PASS_A = _env.requerir("APP_PASS_A")
USER_B = _env.requerir("APP_USER_B")
PASS_B = _env.requerir("APP_PASS_B")

# Identificadores FIJOS de los objetos ficticios (coinciden con la matriz de
# permisos y con el script de validación). No cambiar sin actualizarlos.
INVOICE_IDS_A = [1001, 1002, 1003, 1004]   # 4 facturas del Usuario A
INVOICE_ID_B = 2001                         # 1 factura del Usuario B
DOCUMENT_ID_A = 5001                        # 1 documento del Usuario A (protegido)
DOCUMENT_ID_B = 5002                        # 1 documento del Usuario B


# --------------------------- Utilidades de seguridad ------------------------
def hash_password(password: str, salt: str) -> str:
    """Deriva el hash de la contraseña con PBKDF2-HMAC-SHA256 (stdlib)."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt.encode("utf-8"), 120_000)
    return dk.hex()


def ahora_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------- Base de datos ----------------------------------
def conectar() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def crear_esquema(con: sqlite3.Connection) -> None:
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            nombre        TEXT NOT NULL,
            salt          TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invoices (
            id       INTEGER PRIMARY KEY,
            user_id  INTEGER NOT NULL REFERENCES users(id),
            numero   TEXT NOT NULL,
            concepto TEXT NOT NULL,
            monto    REAL NOT NULL,
            fecha    TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id       INTEGER PRIMARY KEY,
            user_id  INTEGER NOT NULL REFERENCES users(id),
            titulo   TEXT NOT NULL,
            contenido TEXT NOT NULL,
            fecha    TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL
        );
        """
    )
    con.commit()


def _insertar_usuario(con, uid, username, nombre, password) -> None:
    salt = secrets.token_hex(16)
    con.execute(
        "INSERT INTO users (id, username, nombre, salt, password_hash) "
        "VALUES (?,?,?,?,?)",
        (uid, username, nombre, salt, hash_password(password, salt)),
    )


def sembrar(con: sqlite3.Connection) -> None:
    """Inserta datos ficticios solo si la base está vacía. NO borra nada."""
    if con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]:
        return  # Datos preexistentes: no se sobrescriben.

    _insertar_usuario(con, 1, USER_A, "Alicia Propietaria (Usuario A)", PASS_A)
    _insertar_usuario(con, 2, USER_B, "Benito Probador (Usuario B)", PASS_B)

    con.executemany(
        "INSERT INTO invoices (id, user_id, numero, concepto, monto, fecha) "
        "VALUES (?,?,?,?,?,?)",
        [
            (INVOICE_IDS_A[0], 1, "FAC-A-1001", "Servicios de consultoría",  1520000.00, "2026-01-15"),
            (INVOICE_IDS_A[1], 1, "FAC-A-1002", "Licencia de software anual", 980000.00, "2026-02-03"),
            (INVOICE_IDS_A[2], 1, "FAC-A-1003", "Soporte técnico trimestral", 450000.00, "2026-03-11"),
            (INVOICE_IDS_A[3], 1, "FAC-A-1004", "Capacitación en seguridad",  760000.00, "2026-04-02"),
            (INVOICE_ID_B,     2, "FAC-B-2001", "Auditoría interna de accesos", 310000.00, "2026-04-20"),
        ],
    )
    con.executemany(
        "INSERT INTO documents (id, user_id, titulo, contenido, fecha) "
        "VALUES (?,?,?,?,?)",
        [
            (DOCUMENT_ID_A, 1, "Contrato marco A", "Cláusulas confidenciales del Usuario A.", "2026-01-10"),
            (DOCUMENT_ID_B, 2, "Acta interna B",   "Notas internas del Usuario B.",           "2026-04-18"),
        ],
    )
    con.commit()


# --------------------------- Lógica de aplicación ---------------------------
def autenticar(con, username: str, password: str):
    fila = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if fila is None or hash_password(password, fila["salt"]) != fila["password_hash"]:
        return None
    token = secrets.token_hex(24)
    con.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)",
                (token, fila["id"], ahora_iso()))
    con.commit()
    return {"token": token, "user_id": fila["id"], "nombre": fila["nombre"]}


def usuario_de_token(con, token: str | None):
    if not token:
        return None
    return con.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token = ?", (token,)
    ).fetchone()


# --------------------------- Servidor HTTP ----------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PortalFacturasUAO/1.0"

    # --- helpers ---
    def _json(self, code: int, payload: dict) -> None:
        cuerpo = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(cuerpo)

    def _token(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return auth[len("Bearer "):].strip() if auth.startswith("Bearer ") else None

    def _acceso(self, usuario, estado, extra=""):
        quien = usuario["username"] if usuario else "anónimo"
        sys.stderr.write(
            f"[ACCESO] {ahora_iso()} user={quien} {self.command} {self.path} "
            f"-> {estado} {extra}\n")

    def log_message(self, fmt, *args):
        pass  # se usa _acceso para un log con contexto de autorización

    def _servir_estatico(self, rel: str) -> None:
        # Sirve archivos de ./web evitando salir del directorio (path traversal).
        destino = (WEB_DIR / rel).resolve()
        if not str(destino).startswith(str(WEB_DIR.resolve())) or not destino.is_file():
            return self._json(404, {"error": "Recurso no encontrado"})
        tipo = mimetypes.guess_type(str(destino))[0] or "application/octet-stream"
        datos = destino.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(datos)

    # --- POST ---
    def do_POST(self):
        if self.path == "/api/login":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                return self._json(400, {"error": "JSON inválido"})
            con = conectar()
            try:
                sesion = autenticar(con, data.get("username", ""), data.get("password", ""))
            finally:
                con.close()
            if sesion is None:
                self._acceso(None, 401, "login fallido")
                return self._json(401, {"error": "Credenciales inválidas"})
            self._acceso(None, 200, f"login={data.get('username')}")
            return self._json(200, sesion)
        return self._json(404, {"error": "Ruta no encontrada"})

    # --- GET / HEAD ---
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        # Rutas públicas (sin autenticación): salud e interfaz web.
        if self.path == "/api/health":
            return self._json(200, {"status": "ok", "app": "Portal de Facturas UAO"})
        if self.path in ("/", "/index.html"):
            return self._servir_estatico("index.html")
        if self.path.startswith("/web/"):
            return self._servir_estatico(self.path[len("/web/"):])

        con = conectar()
        try:
            usuario = usuario_de_token(con, self._token())
            if usuario is None:
                self._acceso(None, 401)
                return self._json(401, {"error": "No autenticado"})

            if self.path == "/api/me":
                self._acceso(usuario, 200)
                return self._json(200, {"user_id": usuario["id"],
                                        "username": usuario["username"],
                                        "nombre": usuario["nombre"]})

            # ---- Facturas ----
            if self.path == "/api/invoices":
                filas = con.execute(
                    "SELECT id, numero, concepto, monto, fecha FROM invoices "
                    "WHERE user_id = ? ORDER BY id", (usuario["id"],)).fetchall()
                self._acceso(usuario, 200, "lista propia")
                return self._json(200, {"invoices": [dict(f) for f in filas]})

            if self.path.startswith("/api/invoices/"):
                sid = self.path.rsplit("/", 1)[-1]
                if not sid.isdigit():
                    return self._json(400, {"error": "Identificador inválido"})
                f = con.execute("SELECT * FROM invoices WHERE id = ?", (int(sid),)).fetchone()
                if f is None:
                    self._acceso(usuario, 404)
                    return self._json(404, {"error": "Factura no encontrada"})

                # ===========================================================
                #  VULNERABILIDAD IDOR (CWE-639)  — endpoint de facturas
                #  Se comprueba la AUTENTICACIÓN (usuario is not None) pero
                #  NO la AUTORIZACIÓN sobre el objeto: falta comparar
                #  f["user_id"] con usuario["id"].
                #
                #  >>> PUNTO DE EXTENSIÓN PARA EL INTEGRANTE 2 <<<
                #  La política centralizada de autorización debe insertarse
                #  aquí (y reutilizarse en las demás rutas de objetos), p. ej.:
                #      if f["user_id"] != usuario["id"]:
                #          return self._json(403, {"error": "No autorizado"})
                #  El Integrante 1 NO la implementa, para conservar el estado
                #  vulnerable que se demuestra.
                # ===========================================================
                ajeno = f["user_id"] != usuario["id"]
                self._acceso(usuario, 200,
                             f"factura={f['id']} owner={f['user_id']}"
                             + (" [IDOR: objeto ajeno expuesto]" if ajeno else ""))
                return self._json(200, {"id": f["id"], "numero": f["numero"],
                                        "concepto": f["concepto"], "monto": f["monto"],
                                        "fecha": f["fecha"],
                                        "propietario_user_id": f["user_id"]})

            # ---- Documentos (patrón CORRECTO: comprueba propiedad) ----
            if self.path == "/api/documents":
                filas = con.execute(
                    "SELECT id, titulo, fecha FROM documents WHERE user_id = ? "
                    "ORDER BY id", (usuario["id"],)).fetchall()
                self._acceso(usuario, 200, "lista propia")
                return self._json(200, {"documents": [dict(f) for f in filas]})

            if self.path.startswith("/api/documents/"):
                sid = self.path.rsplit("/", 1)[-1]
                if not sid.isdigit():
                    return self._json(400, {"error": "Identificador inválido"})
                d = con.execute("SELECT * FROM documents WHERE id = ?", (int(sid),)).fetchone()
                if d is None:
                    self._acceso(usuario, 404)
                    return self._json(404, {"error": "Documento no encontrado"})
                # CORRECTO: comprobación de propiedad ANTES de entregar el objeto.
                if d["user_id"] != usuario["id"]:
                    self._acceso(usuario, 403, f"documento={d['id']} owner={d['user_id']} denegado")
                    return self._json(403, {"error": "No autorizado"})
                self._acceso(usuario, 200, f"documento={d['id']}")
                return self._json(200, {"id": d["id"], "titulo": d["titulo"],
                                        "contenido": d["contenido"], "fecha": d["fecha"],
                                        "propietario_user_id": d["user_id"]})

            self._acceso(usuario, 404)
            return self._json(404, {"error": "Ruta no encontrada"})
        finally:
            con.close()


def main() -> None:
    con = conectar()
    try:
        crear_esquema(con)
        sembrar(con)
    finally:
        con.close()
    servidor = ThreadingHTTPServer((HOST, PORT), Handler)
    print("=" * 68)
    print(" PORTAL DE FACTURAS UAO — App de prácticas del Proyecto P01")
    print(" Estado: VULNERABLE a IDOR (antes del parche del Integrante 2)")
    print("=" * 68)
    print(f"  Interfaz web : http://{HOST}:{PORT}/")
    print(f"  API          : http://{HOST}:{PORT}/api/health")
    print(f"  Base de datos: {DB_PATH}")
    print(f"  Facturas  A (ajenas para B): {INVOICE_IDS_A}")
    print(f"  Factura   B (propia)       : [{INVOICE_ID_B}]")
    print(f"  Documento A (protegido)    : [{DOCUMENT_ID_A}]  (demo '403 ya protegido')")
    print("  Ctrl+C para detener.")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[Portal de Facturas UAO] Detenido.")
        servidor.server_close()


if __name__ == "__main__":
    main()
