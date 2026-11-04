"""Versión de línea de comandos.

Ejemplos:
    python cli.py --desde 2025-01-01 --hasta 2025-03-31
    python cli.py --desde 2024-01-01 --hasta 2024-12-31 --fuentes nvd kev --max 3000
    python cli.py --desde 2023-06-01 --hasta 2023-06-30 --palabra apache
"""

import argparse
import os
from datetime import date, timedelta

from cve_tool import exportar_csv, exportar_excel
from cve_tool.fuentes import consultar, fecha_minima, iterar_mensajes, marca_tiempo, token_github

ALIAS = {"nvd": "NVD", "github": "GitHub Advisory", "kev": "CISA KEV"}


def main() -> None:
    hoy = date.today()
    p = argparse.ArgumentParser(description="Consulta CVE en NVD, GitHub Advisory y CISA KEV y exporta a Excel/CSV.")
    p.add_argument("--desde", type=date.fromisoformat, default=hoy - timedelta(days=30),
                   help=f"Fecha inicial AAAA-MM-DD (mínimo {fecha_minima(hoy)})")
    p.add_argument("--hasta", type=date.fromisoformat, default=hoy, help="Fecha final AAAA-MM-DD")
    p.add_argument("--fuentes", nargs="+", choices=ALIAS, default=list(ALIAS), help="Bases de datos a consultar")
    p.add_argument("--max", type=int, default=1000, help="Máximo de registros por fuente")
    p.add_argument("--palabra", help="Filtrar por palabra clave (producto, proveedor, descripción)")
    p.add_argument("--sin-epss", action="store_true", help="No consultar puntajes EPSS")
    p.add_argument("--salida", default="salidas", help="Carpeta de salida")
    a = p.parse_args()

    resultado = consultar(
        [ALIAS[f] for f in a.fuentes], a.desde, a.hasta, a.max, a.palabra,
        nvd_api_key=os.environ.get("NVD_API_KEY"), github_token=token_github(),
        enriquecer_epss=not a.sin_epss,
    )
    for m in iterar_mensajes(resultado):
        print("-", m)
    if resultado.datos.empty:
        return
    parametros = {
        "Fecha inicial": str(a.desde), "Fecha final": str(a.hasta),
        "Fuentes": ", ".join(ALIAS[f] for f in a.fuentes),
        "Palabra clave": a.palabra or "(ninguna)", "Máximo por fuente": str(a.max),
        "Fecha de consulta": hoy.isoformat(),
    }
    base = f"{a.salida}/cve_{a.desde}_{a.hasta}_{marca_tiempo()}"
    print("Excel:", exportar_excel(resultado.datos, base + ".xlsx", parametros))
    print("CSV (Power BI):", exportar_csv(resultado.datos, base + ".csv"))


if __name__ == "__main__":
    main()
