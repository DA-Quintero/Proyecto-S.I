# Proyecto P01 — Control de acceso e IDOR (Seguridad Informática · UAO)

Aplicación base del proyecto **P01** y entorno de reproducción de una vulnerabilidad
**IDOR** (Insecure Direct Object References · OWASP **A01:2025** · **CWE-639**). El curso no
provee una app: la aplicación a evaluar es esta (**Portal de Facturas UAO**), construida por
el equipo. Sobre ella se demuestra el fallo, se implementa la corrección y se verifica el parche.

> **Estado actual del código: CORREGIDO.**
> El Integrante 2 implementó una política centralizada de
> autorización para impedir el acceso indebido a recursos ajenos.
> Ahora las rutas de detalle de facturas y documentos comprueban
> que el recurso pertenezca al usuario autenticado antes de
> entregar sus datos.

> La vulnerabilidad original y sus resultados se conservan
> como evidencia para comparar el antes y el después del parche.

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
│   ├── verificar_antes_despues.py  Ejecuta script + test sobre ambas versiones
│   └── evidencias/      Salidas reales de referencia (línea base "antes del parche")
├── tests/
│   └── test_regresion_idor.py  Test de regresión (falla antes, pasa después)
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
| `GET /api/invoices/<id>` | Corregido: verifica la propiedad y responde 403 ante un objeto ajeno. |
| `GET /api/documents/<id>` | Protegido: utiliza la misma política centralizada. |

El contraste demuestra que el patrón correcto ya existía (documentos) y en facturas fue una
**omisión**: una cuenta autenticada obtiene `200` y los datos de facturas de otra cuenta
cambiando el `<id>` en la URL. Detalle y evidencias en `docs/` y `scripts/evidencias/`.

---

## Partes del equipo

Trabajen cada parte en su **propia rama** y abran Pull Request para integrarla.

### Integrante 1 — Hallazgo y reproducción *(incluido en este repo)*
Aplicación, cuentas/objetos, reproducción del IDOR y script de validación.

### Integrante 2 — Política y corrección (completada)

Se implementó la función `_autorizar_objeto()` dentro de
`app/app.py`, encargada de comprobar que el usuario autenticado
sea propietario del recurso solicitado.

La política se utiliza tanto en las facturas como en los
documentos, evitando repetir las comprobaciones de propiedad
en cada ruta.

**Resultados de la validación:**
- Factura propia 2001: HTTP 200.
- Facturas ajenas 1001, 1002, 1003 y 1004: HTTP 403.
- Documento ajeno 5001: HTTP 403.
- No se exponen datos de los recursos ajenos.
- Script de validación: código de salida 0.

**Evidencias:**
- `docs/diff_autorizacion.txt`
- `scripts/evidencias/05_antes_parche_integrante2.txt`
- `scripts/evidencias/06_despues_parche_integrante2.txt`

### Integrante 3 — Pruebas y verificación (completada)

Test de regresión y verificación del mismo script antes y después del parche,
desde un estado limpio (copia temporal de la app, `.env` de ejemplo y base nueva).

```bash
python scripts/verificar_antes_despues.py            # antes (262f30c) vs. después, guarda evidencias 07–11
python -m unittest tests.test_regresion_idor -v      # solo el test, sobre la versión actual
```

| | Antes del parche | Después del parche |
|---|---|---|
| Factura propia 2001 | 200 con datos | 200 con datos |
| Facturas ajenas 1001–1004 | 200 con datos | 403 sin datos |
| Documento ajeno 5001 | 403 | 403 |
| `validar_idor.py` | código 1 | código 0 |
| Test de regresión | FALLA (4 fallos) | PASA (6/6) |

**Evidencias:** `scripts/evidencias/07` a `11` · **Documentación:** `docs/pruebas_y_verificacion_integrante3.md`

## Nota de alcance
Entorno **académico y local** (127.0.0.1). Datos y credenciales ficticios. No desplegar en
producción ni exponer a Internet.
