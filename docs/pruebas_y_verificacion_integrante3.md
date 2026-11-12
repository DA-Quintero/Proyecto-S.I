# Pruebas y verificación del parche

**Proyecto P01 — Control de acceso e IDOR sobre objetos**

**Responsabilidad:** Integrante 3 — Pruebas y verificación

## 1. Objetivo

Esta etapa comprueba que el parche del Integrante 2 cierra el IDOR sin romper el acceso legítimo. La Guía P01 pide tres cosas: un test de regresión que falle con la aplicación original y pase con la corregida, el mismo script ejecutado antes y después del parche, y una ejecución que se pueda repetir desde un estado limpio con un comando documentado.

## 2. Preparación del entorno de pruebas

Las pruebas no dependen de un servidor que alguien haya dejado corriendo ni de una base de datos con cambios previos. Cada ejecución:

1. Copia la carpeta `app/` a un directorio temporal.
2. Crea su `.env` a partir de `.env.example` (credenciales ficticias de `alice` y `bob`).
3. Arranca el servidor en un puerto libre, con una base SQLite nueva sembrada con los mismos identificadores fijos.
4. Ejecuta las pruebas y, al terminar, detiene el servidor y borra el directorio temporal.

Para la versión **antes** se usa el `app/app.py` del commit vulnerable `262f30c`, extraído con `git show`. Para la versión **después** se usa el `app/` actual, que ya contiene `_autorizar_objeto()`. Los dos casos usan los mismos datos iniciales, las mismas cuentas y los mismos identificadores: factura propia 2001, facturas ajenas 1001 a 1004 y documento ajeno 5001.

## 3. Test de regresión

Archivo: `tests/test_regresion_idor.py` (solo `unittest` de la biblioteca estándar).

| Test | Qué comprueba | Antes | Después |
|---|---|---|---|
| `test_01_factura_propia_200_con_datos` | Benito obtiene su factura 2001 con 200 y sus datos | PASA | PASA |
| `test_02_propietaria_conserva_acceso` | Alicia sigue viendo sus facturas 1001–1004 | PASA | PASA |
| `test_03_factura_ajena_403_sin_datos` | Con el token de Benito, las facturas 1001–1004 dan **403** y el cuerpo no trae ningún campo ni valor de la factura | **FALLA** (4 subtests: 200 ≠ 403) | PASA |
| `test_04_documento_ajeno_sigue_protegido` | El documento 5001 sigue en 403 sin datos | PASA | PASA |
| `test_05_sin_token_401` | Sin sesión la respuesta es 401 | PASA | PASA |
| `test_06_listado_solo_propio` | El listado de Benito solo incluye la 2001 | PASA | PASA |

El test central es el `test_03`. No se limita al código HTTP: también revisa que la respuesta 403 no contenga los campos del objeto (`numero`, `concepto`, `monto`, `fecha`, `propietario_user_id`) ni los valores privados de Alicia (por ejemplo `FAC-A-1001` o `Servicios de consultoría`). Así se verifica la condición de la guía: «403 sin información del objeto».

Los tests 01 y 02 cubren el otro lado: que el parche no bloquee de más. Si alguien endureciera la política hasta negar también los objetos propios, el test de regresión lo detectaría.

Resultado sobre la versión vulnerable (extracto de `scripts/evidencias/09_test_regresion_antes.txt`):

```
FAIL: test_03_factura_ajena_403_sin_datos (...) (factura=1001)
AssertionError: 200 != 403 : factura 1001: se esperaba 403 y llegó 200
...
Ran 6 tests in 0.789s
FAILED (failures=4)
```

Resultado sobre la versión corregida (`scripts/evidencias/10_test_regresion_despues.txt`):

```
Ran 6 tests in 0.792s
OK
```

## 4. Resultados comparativos

Salida real de `python scripts/verificar_antes_despues.py`, también guardada en `scripts/evidencias/11_tabla_antes_despues.txt`:

| Caso | Recurso | Antes del parche | Después del parche | ¿Datos ajenos después? |
|---|---|---|---|---|
| Objeto propio autorizado | factura 2001 | 200 con datos | 200 con datos | No aplica |
| Objeto ajeno que exponía info. | factura 1001 | 200 con datos | 403 sin datos | No |
| Objeto ajeno que exponía info. | factura 1002 | 200 con datos | 403 sin datos | No |
| Objeto ajeno que exponía info. | factura 1003 | 200 con datos | 403 sin datos | No |
| Objeto ajeno que exponía info. | factura 1004 | 200 con datos | 403 sin datos | No |
| Objeto ajeno ya protegido | documento 5001 | 403 sin datos | 403 sin datos | No |
| `validar_idor.py` (código de salida) | — | 1 (IDOR) | 0 | — |
| Test de regresión | — | FALLA | PASA | — |

La tabla coincide con la de la Guía P01 §5: el objeto propio mantiene el 200, los objetos ajenos que se exponían pasan a 403 sin datos y el objeto que ya estaba protegido no cambia.

## 5. Verificación del cierre técnico

La guía define el cierre así: el mismo token que obtenía un objeto ajeno recibe 403 para ese identificador, la respuesta no trae sus datos y el acceso autorizado al objeto propio sigue funcionando.

- **Códigos HTTP:** las facturas 1001–1004 pasaron de 200 a 403 con la sesión de Benito.
- **Ausencia de datos ajenos:** el cuerpo de cada 403 es `{"error": "No autorizado"}`. El test comprueba que no aparezca ningún campo ni valor de la factura.
- **Acceso legítimo:** la factura 2001 sigue con 200 para Benito, y Alicia sigue viendo sus cuatro facturas.

El script imprime al final `CRITERIO DE CIERRE: CUMPLIDO` y termina con código 0 solo si se cumplen las cuatro condiciones (script 1 → 0 y test falla → pasa).

## 6. Instrucciones de ejecución

Requisitos: Python 3.9 o superior y git (para extraer la versión vulnerable). No hay paquetes que instalar.

**Verificación completa antes y después (comando de la demostración):**

```bash
python scripts/verificar_antes_despues.py
```

Se ejecuta desde la raíz del repositorio. No hace falta levantar la app antes ni crear `.env`: el script prepara cada versión desde cero. Las salidas quedan en `scripts/evidencias/` (archivos 07 a 11) y se sobrescriben en cada ejecución.

**Solo el test de regresión, sobre la versión actual:**

```bash
python -m unittest tests.test_regresion_idor -v
```

**Solo el test de regresión, sobre otra carpeta de la app:**

```bash
P01_APP_DIR=ruta/a/la/app python -m unittest tests.test_regresion_idor -v
```

En PowerShell: `$env:P01_APP_DIR="ruta\a\la\app"; python -m unittest tests.test_regresion_idor -v`.

**Script del Integrante 1 contra la app levantada a mano** (igual que antes):

```bash
cd app && cp .env.example .env && python app.py      # terminal 1
cd scripts && python validar_idor.py                  # terminal 2
```

### Evidencias generadas

| Archivo | Contenido |
|---|---|
| `07_validar_idor_antes.txt` | Salida de `validar_idor.py` sobre la versión vulnerable (código 1) |
| `08_validar_idor_despues.txt` | Salida de `validar_idor.py` sobre la versión corregida (código 0) |
| `09_test_regresion_antes.txt` | Test de regresión sobre la versión vulnerable (FAILED, 4 fallos) |
| `10_test_regresion_despues.txt` | Test de regresión sobre la versión corregida (OK) |
| `11_tabla_antes_despues.txt` | Tabla comparativa y criterio de cierre |

## 7. Conclusiones

El parche cierra el IDOR demostrado: el mismo token de Benito que antes recibía las facturas de Alicia ahora recibe 403, sin ningún dato de esas facturas, y su propia factura sigue disponible. El resultado se obtuvo con salida real, con los mismos identificadores en las dos versiones y desde un estado limpio.

El test de regresión deja una protección para el futuro. Si un cambio posterior elimina la llamada a `_autorizar_objeto()` en la ruta de facturas, el `test_03` vuelve a fallar con los mismos 4 errores que muestra la versión original. Esto responde a la pregunta de la guía sobre qué control habría evitado reintroducir el error: un test de autorización por objeto que se ejecute en cada cambio, idealmente en CI antes de integrar a `main`.

Límites de lo verificado: las pruebas cubren lectura de facturas y documentos, que son las únicas operaciones de la aplicación. No se midieron tiempos de respuesta. Las rutas nuevas, o las de modificación y borrado, tendrán que añadirse al test cuando existan.
