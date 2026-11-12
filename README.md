# Proyecto P01 — Control de acceso e IDOR (Seguridad Informática · UAO)

Aplicación base del proyecto **P01** y entorno de reproducción de una vulnerabilidad
**IDOR** (Insecure Direct Object References · OWASP **A01:2025** · **CWE-639**). El curso no
provee una app: la aplicación a evaluar es esta (**Portal de Facturas UAO**), construida por
el equipo. Sobre ella se demuestra el fallo, se implementa la corrección y se verifica el parche.

> **Estado actual del código: VULNERABLE a IDOR, a propósito.** Es el punto de partida del
> proyecto. La corrección (política centralizada) y el test de regresión se añaden en ramas,
> ver *Partes del equipo* más abajo.

## Requisitos
- **Python 3.9 o superior.** Nada más: la aplicación usa solo la biblioteca estándar (sin `pip install`).

## Cómo ejecutar

```bash
# 1) Levantar la aplicación
cd app
cp .env.example .env            # Windows (PowerShell): Copy-Item .env.example .env
python app.py                   # http://127.0.0.1:8008/
```

```bash
# 2) En otra terminal: validación controlada del IDOR
cd scripts
python validar_idor.py          # antes del parche: detecta IDOR y termina con código 1
```

- Interfaz web de demostración: `http://127.0.0.1:8008/`
- Estado del servicio: `GET http://127.0.0.1:8008/api/health`
- La base de datos `app/facturas.db` se crea y siembra sola en el primer arranque (no se versiona).

## Estructura del repositorio

```
.
├── app/                 Aplicación (API REST + interfaz web + SQLite)
│   ├── app.py           Servidor y endpoints
│   ├── _env.py          Carga de credenciales desde .env
│   ├── web/index.html   Interfaz de demostración
│   └── .env.example     Plantilla de credenciales de prueba (copiar a .env)
├── scripts/
│   ├── validar_idor.py  Validación controlada (recorre objetos ajenos con una sesión)
│   └── evidencias/      Salidas reales de referencia (línea base "antes del parche")
└── docs/
    ├── preparacion.md             Arquitectura, cuentas, objetos y matriz de permisos
    └── instrucciones_ejecucion.md Procedimiento y tabla de resultados
```

## Cuentas y objetos de prueba (ficticios)

| Usuario | `user_id` | Facturas | Documentos |
|---|---|---|---|
| A (`alice`) | 1 | 1001, 1002, 1003, 1004 | 5001 |
| B (`bob`) | 2 | 2001 | 5002 |

Las credenciales viven en `app/.env` (local, **no** versionado). Plantilla en `app/.env.example`.

## La vulnerabilidad (resumen)

| Endpoint | Control de acceso |
|---|---|
| `GET /api/invoices/<id>` | **Vulnerable (IDOR):** solo exige autenticación, no comprueba propiedad |
| `GET /api/documents/<id>` | **Correcto:** comprueba propiedad (403 si el objeto es ajeno) |

El contraste demuestra que el patrón correcto ya existía (documentos) y en facturas fue una
**omisión**: una cuenta autenticada obtiene `200` y los datos de facturas de otra cuenta
cambiando el `<id>` en la URL. Detalle y evidencias en `docs/` y `scripts/evidencias/`.

---

## Partes del equipo

Trabajen cada parte en su **propia rama** y abran Pull Request para integrarla.

### Integrante 1 — Hallazgo y reproducción *(incluido en este repo)*
Aplicación, cuentas/objetos, reproducción del IDOR y script de validación.

### Integrante 2 — Política y corrección
- **Dónde:** `app/app.py`, manejador de `GET /api/invoices/<id>`. Busca el comentario
  `>>> PUNTO DE EXTENSIÓN PARA EL INTEGRANTE 2 <<<`.
- **Idea:** comprobar propiedad antes de entregar el objeto, p. ej.
  `if f["user_id"] != usuario["id"]: return self._json(403, {"error": "No autorizado"})`,
  y reutilizar esa comprobación como política única en las rutas de objetos.
- **Validación:** tras el parche, `python scripts/validar_idor.py` debe devolver **código 0**
  y las facturas ajenas pasar a **403 sin datos**. Conserva el diff.

### Integrante 3 — Pruebas y verificación
- Crea el **test de regresión** (falla con la app vulnerable, pasa con la corregida).
- Usa `scripts/validar_idor.py` (código de salida 1 = vulnerable, 0 = corregido) y
  `scripts/evidencias/` como línea base del "antes".
- Mantén los **mismos identificadores** en ambas ejecuciones y guarda las salidas antes/después.

## Nota de alcance
Entorno **académico y local** (127.0.0.1). Datos y credenciales ficticios. No desplegar en
producción ni exponer a Internet.
