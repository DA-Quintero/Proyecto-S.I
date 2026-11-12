# P01 · Integrante 1 — Preparación y entorno de pruebas

**Proyecto:** P01 — Control de acceso e IDOR sobre objetos
**Categoría OWASP:** A01:2025 — Broken Access Control · **CWE:** 639 (principal), 284 (general)
**Rol:** Integrante 1 — Hallazgo y reproducción
**Aplicación:** Portal de Facturas UAO (app base del proyecto, `app.py`)
**Fecha:** 2026-11-12

---

## 1. Sobre la aplicación del proyecto

La **aplicación a evaluar la construye el equipo** como parte del P01: el curso no
proporciona una app. Se desarrolló el **Portal de Facturas UAO**, un backend/API REST que
gestiona facturas y documentos con propietario, siguiendo el escenario de la Guía P01 (§3,
«un recurso con propietario, por ejemplo una factura»). En este punto del proyecto la
aplicación se mantiene **deliberadamente vulnerable a IDOR**, que es el estado que el
Integrante 1 debe demostrar (la corrección es del Integrante 2 y la verificación del
Integrante 3).

## 2. Inspección de la arquitectura (cómo funciona la app)

| Elemento | Valor real en la aplicación |
|---|---|
| Lenguaje / runtime | Python 3 (biblioteca estándar, sin dependencias externas) |
| Servidor | `http.server.ThreadingHTTPServer` (HTTP/1.1) |
| Base de datos | SQLite (`facturas.db`), archivo local, sembrado idempotente |
| Autenticación | Token *bearer* emitido en `POST /api/login`, tabla `sessions` |
| Hash de contraseñas | PBKDF2-HMAC-SHA256 con *salt* por usuario (120.000 iteraciones) |
| Interfaz | Web estática de demostración (`web/index.html`) |
| Recursos con propietario | `invoices` (facturas) y `documents` (documentos) |

### Modelo de datos y relaciones de propiedad
```
users(id PK, username UNIQUE, nombre, salt, password_hash)
invoices(id PK, user_id FK -> users.id, numero, concepto, monto, fecha)
documents(id PK, user_id FK -> users.id, titulo, contenido, fecha)
sessions(token PK, user_id FK -> users.id, created_at)
```
La propiedad de cada objeto se define en `invoices.user_id` / `documents.user_id`. Esa es la
relación que el control de autorización **debería** comprobar antes de entregar el recurso.

### Funcionalidades de consulta y su control de acceso
| Método y ruta | Comportamiento | Control de acceso |
|---|---|---|
| `GET /api/health` | Estado del servicio | Público |
| `GET /api/me` | Perfil del usuario autenticado | Solo autenticación |
| `GET /api/invoices` | Lista **solo** facturas propias (`WHERE user_id = <sesión>`) | Correcto |
| `GET /api/invoices/<id>` | Devuelve la factura por `id` | **Defectuoso:** no comprueba propiedad → IDOR |
| `GET /api/documents` | Lista **solo** documentos propios | Correcto |
| `GET /api/documents/<id>` | Devuelve el documento por `id` | **Correcto:** comprueba propiedad (403 si ajeno) |

El contraste `invoices` (vulnerable) vs `documents` (protegido) evidencia que el fallo es una
**comprobación de autorización ausente a nivel de objeto**, no un problema de interfaz: el
patrón correcto ya existía en el código (documentos) y se omitió en facturas.

## 3. Cuentas de prueba (dos cuentas independientes)

Credenciales por **variables de entorno** (`.env`, excluido de Git); plantilla pública en
`.env.example`. Sin contraseñas ni tokens en el código.

| Cuenta | `user_id` | Usuario | Rol en la prueba |
|---|---|---|---|
| **Usuario A** | 1 | `alice` | Propietario de varios recursos (objetos *ajenos* para B) |
| **Usuario B** | 2 | `bob` | Propietario de sus recursos; cuenta usada para el acceso indebido |

## 4. Recursos ficticios (propietarios verificables)

Identificadores **fijos**, idénticos en app, matriz y script.

| Objeto | `id` | Propietario | `user_id` | Detalle |
|---|---|---|---|---|
| Factura | 1001 | Usuario A | 1 | FAC-A-1001 · Servicios de consultoría · 1.520.000 |
| Factura | 1002 | Usuario A | 1 | FAC-A-1002 · Licencia de software anual · 980.000 |
| Factura | 1003 | Usuario A | 1 | FAC-A-1003 · Soporte técnico trimestral · 450.000 |
| Factura | 1004 | Usuario A | 1 | FAC-A-1004 · Capacitación en seguridad · 760.000 |
| Factura | 2001 | Usuario B | 2 | FAC-B-2001 · Auditoría interna de accesos · 310.000 |
| Documento | 5001 | Usuario A | 1 | Contrato marco A (endpoint protegido) |
| Documento | 5002 | Usuario B | 2 | Acta interna B |

Cumple «3–5 recursos del Usuario A» (4 facturas) y «al menos un recurso del Usuario B»
(factura 2001 + documento 5002). Todos con propietario verificable.

## 5. Matriz de permisos esperados (política de referencia, *antes* de probar)

Política: **cada usuario consulta únicamente sus propios recursos**; no hay rol con excepción.
Representa el comportamiento **esperado/correcto**, contrastado luego con el **real**.

| Cuenta (sesión) | Recurso | Propietario | ¿Autorizado? | Operación | HTTP esperado |
|---|---|---|---|---|---|
| Usuario B (`bob`) | factura 2001 | Usuario B | Sí | `GET /api/invoices/2001` | **200 con datos** |
| Usuario B (`bob`) | factura 1001 | Usuario A | No | `GET /api/invoices/1001` | **403 sin datos** |
| Usuario B (`bob`) | factura 1002 | Usuario A | No | `GET /api/invoices/1002` | **403 sin datos** |
| Usuario B (`bob`) | factura 1003 | Usuario A | No | `GET /api/invoices/1003` | **403 sin datos** |
| Usuario B (`bob`) | factura 1004 | Usuario A | No | `GET /api/invoices/1004` | **403 sin datos** |
| Usuario B (`bob`) | documento 5001 | Usuario A | No | `GET /api/documents/5001` | **403 sin datos** |

> En la reproducción se verifica si el comportamiento **real** coincide con el esperado. Un
> `200 con datos` donde se esperaba `403 sin datos` confirma IDOR. El documento 5001 sirve de
> control: su endpoint ya aplica la comprobación, por lo que debe responder 403.

## 6. Configuración y ejecución del entorno

Requisito único: **Python 3.9+** (sin paquetes externos).

```bash
cd app
cp .env.example .env          # PowerShell: Copy-Item .env.example .env
python app.py                 # http://127.0.0.1:8008/
```
La base `facturas.db` se crea y siembra en el primer arranque (idempotente: no borra ni
sobrescribe datos existentes).

---

### Resumen de preparación (Agente 1)
- [x] Aplicación base del proyecto construida (API + UI + BD), con el patrón correcto e incorrecto.
- [x] Arquitectura inspeccionada sobre código real (lenguaje, framework, BD, auth, modelos).
- [x] Relación de propiedad identificada: `invoices.user_id`, `documents.user_id`.
- [x] Dos cuentas independientes por variables de entorno (sin secretos en el código).
- [x] 4 facturas de A + 1 de B + documentos, con propietario verificable e identificadores fijos.
- [x] Matriz de permisos esperados (incluye el caso «objeto ajeno ya protegido»).
- [x] Entorno reproducible documentado.
