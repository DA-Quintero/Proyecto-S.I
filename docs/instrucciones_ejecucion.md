# P01 · Integrante 1 — Desarrollo técnico: procedimiento, script y resultados

**Rol:** Integrante 1 — Reproducción del IDOR y script de validación
**App:** Portal de Facturas UAO (`app/app.py`)
**Fecha de ejecución:** 2026-11-12

---

## 1. Procedimiento de reproducción controlada (Guía P01, §4)

Con una sola sesión del Usuario B:

1. Autenticación como **Usuario B** (`POST /api/login`).
2. Consulta de un recurso **propio** de B (`GET /api/invoices/2001`) → acceso legítimo.
3. Registro de la petición y respuesta legítima.
4. Identificación de cómo se selecciona el recurso: por el **identificador numérico** en la
   ruta `GET /api/invoices/<id>` (clave controlada por el cliente).
5. Reutilización de la **misma sesión de B** cambiando el `<id>` por el de facturas del
   **Usuario A** (1001–1004).
6. Ejecución de la comprobación sobre cada identificador ajeno y registro de resultados.
7. Caso de contraste: consulta de un documento ajeno ya protegido (`GET /api/documents/5001`).
8. Repetición **solo** con los identificadores ficticios preparados (lista fija).

> Sin enumeración masiva ni escaneo: lista fija de identificadores limitada al escenario.

## 2. Tabla de reproducción (mapeada a la tabla de la Guía P01, §5)

| Caso (Guía) | Sesión | Recurso | Propietario | Esperado (política) | HTTP real | ¿Datos? | Veredicto |
|---|---|---|---|---|---|---|---|
| Objeto propio autorizado | B | factura 2001 | B | 200 con datos | **200** | Sí | Correcto (legítimo) |
| Objeto ajeno que exponía info. | B | factura 1001 | A | 403 sin datos | **200** | Sí | **IDOR** |
| Objeto ajeno que exponía info. | B | factura 1002 | A | 403 sin datos | **200** | Sí | **IDOR** |
| Objeto ajeno que exponía info. | B | factura 1003 | A | 403 sin datos | **200** | Sí | **IDOR** |
| Objeto ajeno que exponía info. | B | factura 1004 | A | 403 sin datos | **200** | Sí | **IDOR** |
| Objeto ajeno ya protegido | B | documento 5001 | A | 403 sin datos | **403** | No | Correcto (denegado) |
| Control negativo (sin token) | — | factura 1001 | A | 401 | **401** | No | Correcto (exige auth) |

**Evidencia central (Guía §4):** con el token de `bob` se recibió **HTTP 200 y los datos** de
facturas cuyo propietario es el Usuario A (`propietario_user_id: 1`), recursos para los que
`bob` **no** tiene permiso. El documento 5001 (endpoint ya protegido) devolvió **403 sin
datos**, y sin token la respuesta es **401**: el servidor aplica autenticación, pero **no**
autorización sobre la factura.

Este cuadro deja preparada la comparación **antes/después** que ejecutará el Integrante 3:
tras el parche, las filas de IDOR deben pasar a **403 sin datos**, y las demás no deben cambiar.

## 3. Cómo ejecutar (desde estado limpio)

Requiere **Python 3.9+**, sin paquetes externos.

```bash
# Terminal 1 — levantar la app
cd app
cp .env.example .env           # PowerShell: Copy-Item .env.example .env
python app.py                  # http://127.0.0.1:8008/
```

```bash
# Terminal 2 — ejecutar la validación controlada
cd scripts
python validar_idor.py
```

Comando único de validación: **`python validar_idor.py`**
Código de salida: `1` si detecta IDOR (facturas ajenas expuestas), `0` si no; `2/3/4` ante
errores de credenciales/conexión/autenticación. (El Integrante 3 puede apoyarse en este código
para el test: antes del parche debe devolver `1`; después, `0`.)

## 4. Demostración visual (interfaz web)

La app sirve una interfaz en `http://127.0.0.1:8008/` para la demo en vivo:
1. Iniciar sesión como **Usuario B**.
2. En «Mis facturas» solo aparece la 2001 (propia).
3. En «Consultar factura por ID», escribir **1001** (ajena) → la app muestra **HTTP 200** con
   los datos de la factura del Usuario A: el IDOR es visible sin herramientas.
4. En «Consultar documento por ID», escribir **5001** (ajeno) → **HTTP 403**: contraste del
   endpoint ya protegido.

Captura real en `evidencias/03_demo_ui_idor.jpg`.

## 5. Qué hace y qué NO hace el script

`validar_idor.py`: usa una **sesión autenticada** de B; consulta **un recurso propio** + **4
ajenos** (rango 3–5) + **1 ajeno ya protegido**; mantiene una **lista fija** de identificadores;
registra **códigos HTTP** y si se devolvió **información del recurso**; muestra una **tabla**
organizada por caso; **gestiona errores** de conexión y autenticación; **enmascara el token** y
no imprime contraseñas. **No** es una herramienta de enumeración ni de extracción: su alcance
se limita a la validación académica de esta aplicación.

## 6. Evidencias generadas (ejecución real)

| Archivo | Contenido |
|---|---|
| `evidencias/01_salida_validar_idor.txt` | Salida completa del script (tabla de 3 casos de la Guía). |
| `evidencias/02_transcripts_http.txt` | Transcripts HTTP crudos: login, factura propia (200), listado acotado, factura ajena (IDOR 200), documento propio (200), documento ajeno (403) y sin token (401). Token enmascarado. |
| `evidencias/03_demo_ui_idor.jpg` | Captura de la interfaz: factura ajena 1001 → 200 con datos de A; documento ajeno 5001 → 403. |
| `evidencias/04_log_acceso_servidor.txt` | Log de acceso del propio servidor marcando el IDOR (200 ajeno) y el 403 del endpoint protegido. |

## 7. Límite de responsabilidades (Guía §5.3)

El Integrante 1 **no** implementa la política centralizada de autorización ni corrige el código
(Integrante 2), ni desarrolla el test de regresión (Integrante 3). En `app.py` se **señala** el
punto de extensión y la comprobación de propiedad ausente, pero **no** se aplica, para conservar
la separación de responsabilidades y el estado vulnerable necesario para la demostración.
