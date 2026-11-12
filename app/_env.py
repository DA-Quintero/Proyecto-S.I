"""
Cargador mínimo de variables de entorno desde un archivo .env.

Objetivo académico (P01 - Integrante 1):
    Evitar que las credenciales de prueba queden escritas directamente en el
    código fuente. Las credenciales se leen de variables de entorno; si existe
    un archivo .env junto al proyecto, se carga automáticamente.

No sobrescribe variables ya definidas en el entorno real del sistema.
No imprime los valores de las credenciales.
"""
from __future__ import annotations
import os
from pathlib import Path


def cargar_dotenv(ruta: str | os.PathLike | None = None) -> bool:
    """Carga pares CLAVE=VALOR de un archivo .env a os.environ.

    Devuelve True si cargó un archivo, False si no existe.
    Las variables ya presentes en el entorno tienen prioridad (no se pisan).
    """
    if ruta is None:
        ruta = Path(__file__).resolve().parent / ".env"
    ruta = Path(ruta)
    if not ruta.exists():
        return False

    for linea in ruta.read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#") or "=" not in linea:
            continue
        clave, valor = linea.split("=", 1)
        clave = clave.strip()
        valor = valor.strip().strip('"').strip("'")
        # Respeta las variables ya definidas en el sistema.
        os.environ.setdefault(clave, valor)
    return True


def requerir(clave: str) -> str:
    """Devuelve el valor de una variable de entorno obligatoria o aborta."""
    valor = os.environ.get(clave)
    if not valor:
        raise SystemExit(
            f"[ERROR] Falta la variable de entorno '{clave}'.\n"
            f"        Copia .env.example a .env y define las credenciales de prueba.\n"
            f"        (No se imprime ningún valor por seguridad.)"
        )
    return valor
