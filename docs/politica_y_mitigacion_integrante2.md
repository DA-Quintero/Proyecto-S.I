# Política de autorización y mitigación de IDOR

**Proyecto P01 — Control de acceso e IDOR sobre objetos**

**Responsabilidad:** Integrante 2 — Política y corrección

## 1. Objetivo de la corrección

Esta etapa del proyecto tuvo como objetivo corregir la vulnerabilidad de control de acceso identificada en el Portal de Facturas UAO. Durante las pruebas iniciales se comprobó que un usuario autenticado podía consultar facturas pertenecientes a otra cuenta simplemente cambiando el identificador del recurso en la dirección de la petición.

Para solucionar este problema se implementó una política centralizada de autorización que verifica la propiedad de cada recurso antes de entregar su información.

## 2. Política de permisos

La aplicación utiliza dos usuarios de prueba: Alicia (usuario A) y Benito (usuario B). Cada uno tiene recursos asociados a su cuenta y únicamente debe poder consultar aquellos de los que es propietario.

| Usuario | Recurso | Propietario | HTTP esperado |
|---|---|---|---|
| Benito | Factura 2001 | Benito | 200 |
| Benito | Factura 1001 | Alicia | 403 |
| Benito | Factura 1002 | Alicia | 403 |
| Benito | Factura 1003 | Alicia | 403 |
| Benito | Factura 1004 | Alicia | 403 |
| Benito | Documento 5001 | Alicia | 403 |

La política establece que un usuario debe estar autenticado para acceder a las rutas protegidas. Además, el servidor debe comprobar que el recurso solicitado le pertenece. Si no tiene permiso, la aplicación debe denegar la solicitud sin revelar los datos del objeto.

## 3. Implementación de la corrección

La corrección se realizó en el archivo `app/app.py`, mediante la función `_autorizar_objeto()`.

Esta función recibe el usuario autenticado, el recurso solicitado y la acción que se pretende realizar. Su responsabilidad es comprobar que la acción sea de lectura y que el identificador del propietario coincida con el identificador del usuario autenticado.

Cuando ambas condiciones se cumplen, la función permite continuar con la solicitud. En caso contrario, registra el intento de acceso denegado y devuelve una respuesta HTTP 403 con un mensaje de error que no contiene información privada.

La función se incorporó en las rutas de detalle de facturas y documentos, evitando mantener comprobaciones de propiedad independientes en cada una.

## 4. Comparación antes y después del parche

Antes de implementar la corrección, el servidor comprobaba que Benito hubiera iniciado sesión, pero no verificaba si las facturas solicitadas le pertenecían.

Después del parche, las peticiones pasan por la política centralizada y solamente se entregan los recursos autorizados.

| Recurso | Antes | Después |
|---|---|---|
| Factura 2001 | 200 | 200 |
| Factura 1001 | 200 | 403 |
| Factura 1002 | 200 | 403 |
| Factura 1003 | 200 | 403 |
| Factura 1004 | 200 | 403 |
| Documento 5001 | 403 | 403 |

Para comprobar la corrección se utilizó el script `validar_idor.py`, desarrollado durante la primera etapa del proyecto. Después de aplicar el parche, el script finalizó con código de salida 0 e informó que no se expusieron recursos ajenos.

El archivo `diff_autorizacion.txt` conserva las diferencias entre las versiones vulnerable y corregida.

## 5. Coste de la mitigación

La corrección incorpora una comprobación adicional antes de entregar cada recurso. Esta operación supone un coste mínimo de procesamiento, ya que compara el identificador del usuario autenticado con el del propietario del objeto recuperado.

En la implementación actual no fue necesario agregar dependencias externas ni realizar una consulta adicional a la base de datos para comprobar la propiedad, porque el identificador del propietario ya se encuentra disponible en el recurso consultado.

En términos de mantenimiento, centralizar la autorización también facilita la aplicación de cambios futuros y reduce la duplicación de código.

## 6. Riesgo residual

Aunque la corrección impide el acceso indebido demostrado en las rutas evaluadas, no garantiza que toda la aplicación esté libre de problemas de autorización.

Todavía podrían aparecer vulnerabilidades si se agregan nuevas rutas sin aplicar la política o si en el futuro se implementan operaciones de modificación y eliminación sin los controles correspondientes.

Por este motivo, es importante mantener las verificaciones de autorización en el servidor y complementar la corrección con pruebas de regresión que detecten posibles fallos cuando se modifique el código.

## 7. Relación con el laboratorio PortSwigger

Como parte de esta etapa también se resolvió el laboratorio *User role controlled by request parameter* de PortSwigger Web Security Academy.

En este ejercicio se demostró cómo una aplicación puede permitir la elevación de privilegios cuando confía en un parámetro enviado por el navegador para determinar si un usuario tiene permisos administrativos.

Al modificar la cookie `Admin` de `false` a `true`, fue posible acceder al panel de administración con una cuenta que originalmente no tenía esos privilegios. El laboratorio se completó satisfactoriamente.

Aunque el laboratorio aborda permisos administrativos y el proyecto principal se centra en la propiedad de los recursos, ambos casos muestran la importancia de realizar las comprobaciones de autorización en el servidor, utilizando información confiable.

## 8. Conclusión

La implementación de la política centralizada permitió corregir el acceso indebido identificado en el Portal de Facturas UAO. Las pruebas posteriores demostraron que Benito conserva el acceso a sus recursos, mientras que las solicitudes sobre las facturas de Alicia son rechazadas con HTTP 403 y sin revelar información privada.

Esta corrección muestra la diferencia entre autenticar a una persona y verificar que realmente tenga permiso para consultar un recurso. También deja una base reutilizable para mantener las reglas de autorización en futuras funcionalidades de la aplicación.