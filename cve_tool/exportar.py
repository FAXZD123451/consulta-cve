"""Exportación de resultados a Excel (con tablas y gráficas nativas) y CSV para Power BI."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from openpyxl.chart import BarChart, LineChart, PieChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

from .fuentes import ORDEN_SEVERIDAD

TITULO = Font(bold=True, size=14, color="1F3864")
SUBTITULO = Font(bold=True, size=11, color="1F3864")
ENCABEZADO = PatternFill("solid", fgColor="1F3864")
COLORES_SEVERIDAD = {"CRITICAL": "7B1FA2", "HIGH": "D32F2F", "MEDIUM": "F57C00",
                     "LOW": "FBC02D", "NONE": "9E9E9E", "N/D": "BDBDBD"}


# --------------------------------------------------------------------------- resúmenes

def resumen_severidad(df: pd.DataFrame) -> pd.DataFrame:
    unicas = df.drop_duplicates("cve_id")
    conteo = unicas["severidad"].value_counts()
    orden = [s for s in ORDEN_SEVERIDAD if s in conteo.index]
    return pd.DataFrame({"Severidad": orden, "Cantidad": [int(conteo[s]) for s in orden]})


def resumen_mensual(df: pd.DataFrame) -> pd.DataFrame:
    tabla = df.pivot_table(index="mes", columns="fuente", values="cve_id", aggfunc="count", fill_value=0)
    tabla = tabla.sort_index().reset_index().rename(columns={"mes": "Mes"})
    tabla.columns.name = None
    return tabla


def top(df: pd.DataFrame, columna: str, n: int = 10, separar: bool = False) -> pd.DataFrame:
    serie = df.drop_duplicates("cve_id")[columna].fillna("")
    if separar:
        serie = serie.str.split(", ").explode()
    serie = serie[serie.str.strip() != ""]
    conteo = serie.value_counts().head(n)
    return pd.DataFrame({columna.capitalize(): conteo.index, "Cantidad": conteo.values.astype(int)})


def fuente_por_severidad(df: pd.DataFrame) -> pd.DataFrame:
    tabla = df.pivot_table(index="fuente", columns="severidad", values="cve_id", aggfunc="count", fill_value=0)
    tabla = tabla[[s for s in ORDEN_SEVERIDAD if s in tabla.columns]]
    tabla = tabla.reset_index().rename(columns={"fuente": "Fuente"})
    tabla.columns.name = None
    return tabla


def indicadores(df: pd.DataFrame) -> dict[str, object]:
    unicas = df.drop_duplicates("cve_id")
    return {
        "CVE únicas": len(unicas),
        "Registros (todas las fuentes)": len(df),
        "Críticas": int((unicas["severidad"] == "CRITICAL").sum()),
        "Altas": int((unicas["severidad"] == "HIGH").sum()),
        "Explotadas activamente (KEV)": int((unicas["explotada_activamente"] == "Sí").sum()),
        "Usadas en ransomware": int((unicas["ransomware"] == "Sí").sum()),
        "CVSS promedio": round(float(unicas["puntaje_cvss"].mean()), 2) if unicas["puntaje_cvss"].notna().any() else "N/D",
        "EPSS promedio (%)": round(float(unicas["epss"].mean()) * 100, 2) if unicas["epss"].notna().any() else "N/D",
    }


# --------------------------------------------------------------------------- Excel

def _encabezado(ws, fila: int, col: int, columnas: int) -> None:
    for c in range(col, col + columnas):
        celda = ws.cell(row=fila, column=c)
        celda.font = Font(bold=True, color="FFFFFF")
        celda.fill = ENCABEZADO
        celda.alignment = Alignment(horizontal="center")


def _escribir_tabla(writer, ws, tabla: pd.DataFrame, fila: int, col: int, titulo: str) -> tuple[int, int]:
    """Escribe una tabla con título; devuelve (fila_encabezado, fila_final) en base 1."""
    ws.cell(row=fila, column=col, value=titulo).font = SUBTITULO
    tabla.to_excel(writer, sheet_name=ws.title, startrow=fila, startcol=col - 1, index=False)
    _encabezado(ws, fila + 1, col, len(tabla.columns))
    return fila + 1, fila + 1 + len(tabla)


def exportar_excel(df: pd.DataFrame, ruta, parametros: dict[str, str]):
    """Escribe el libro en `ruta` (ruta de archivo o buffer en memoria, p. ej. io.BytesIO)."""
    if isinstance(ruta, (str, Path)):
        ruta = Path(ruta)
        ruta.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(ruta, engine="openpyxl") as writer:
        # ---- Hoja 1: datos completos como Tabla de Excel (Power BI la detecta directamente)
        df.to_excel(writer, sheet_name="CVEs", index=False)
        ws = writer.sheets["CVEs"]
        ultima = f"{get_column_letter(len(df.columns))}{len(df) + 1}"
        if len(df):
            tabla = Table(displayName="TablaCVE", ref=f"A1:{ultima}")
            tabla.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True)
            ws.add_table(tabla)
        ws.freeze_panes = "B2"
        anchos = {"cve_id": 18, "fuente": 16, "descripcion": 80, "vector_cvss": 30, "url": 45,
                  "producto": 28, "proveedor": 22, "cwe": 18}
        for i, col in enumerate(df.columns, 1):
            ws.column_dimensions[get_column_letter(i)].width = anchos.get(col, 14)
        for fila in ws.iter_rows(min_row=2, min_col=df.columns.get_loc("severidad") + 1,
                                 max_col=df.columns.get_loc("severidad") + 1):
            for celda in fila:
                color = COLORES_SEVERIDAD.get(celda.value)
                if color:
                    celda.font = Font(bold=True, color=color)

        # ---- Hoja 2: resumen con indicadores y gráficas
        pd.DataFrame().to_excel(writer, sheet_name="Resumen")
        rs = writer.sheets["Resumen"]
        rs["A1"] = "Resumen de vulnerabilidades CVE"
        rs["A1"].font = TITULO
        rs["A2"] = f"Rango: {parametros.get('Fecha inicial')} a {parametros.get('Fecha final')}  |  " \
                   f"Fuentes: {parametros.get('Fuentes')}"
        fila = 4
        for nombre, valor in indicadores(df).items():
            rs.cell(row=fila, column=1, value=nombre).font = Font(bold=True)
            rs.cell(row=fila, column=2, value=valor)
            fila += 1
        rs.column_dimensions["A"].width = 30
        rs.column_dimensions["B"].width = 14

        sev = resumen_severidad(df)
        f0, f1 = _escribir_tabla(writer, rs, sev, 14, 1, "CVE por severidad")
        if len(sev):
            pie = PieChart()
            pie.title = "Distribución por severidad"
            pie.add_data(Reference(rs, min_col=2, min_row=f0, max_row=f1), titles_from_data=True)
            pie.set_categories(Reference(rs, min_col=1, min_row=f0 + 1, max_row=f1))
            pie.dataLabels = DataLabelList(showPercent=True)
            pie.height, pie.width = 8, 12
            rs.add_chart(pie, "J4")

        fps = fuente_por_severidad(df)
        f0, f1 = _escribir_tabla(writer, rs, fps, 24, 1, "Fuente por severidad")
        if len(fps):
            barras = BarChart()
            barras.type, barras.grouping, barras.overlap = "col", "stacked", 100
            barras.title = "Severidad por base de datos"
            barras.add_data(Reference(rs, min_col=2, max_col=len(fps.columns), min_row=f0, max_row=f1),
                            titles_from_data=True)
            barras.set_categories(Reference(rs, min_col=1, min_row=f0 + 1, max_row=f1))
            barras.height, barras.width = 8, 12
            rs.add_chart(barras, "R4")

        prov = top(df, "proveedor")
        f0, f1 = _escribir_tabla(writer, rs, prov, 32, 1, "Top 10 proveedores / ecosistemas")
        if len(prov):
            bp = BarChart()
            bp.type = "bar"
            bp.title = "Top 10 proveedores"
            bp.legend = None
            bp.add_data(Reference(rs, min_col=2, min_row=f0, max_row=f1), titles_from_data=True)
            bp.set_categories(Reference(rs, min_col=1, min_row=f0 + 1, max_row=f1))
            bp.height, bp.width = 9, 12
            rs.add_chart(bp, "J22")

        cwe = top(df, "cwe", separar=True)
        f0, f1 = _escribir_tabla(writer, rs, cwe, 46, 1, "Top 10 tipos de debilidad (CWE)")
        if len(cwe):
            bc = BarChart()
            bc.type = "bar"
            bc.title = "Top 10 CWE"
            bc.legend = None
            bc.add_data(Reference(rs, min_col=2, min_row=f0, max_row=f1), titles_from_data=True)
            bc.set_categories(Reference(rs, min_col=1, min_row=f0 + 1, max_row=f1))
            bc.height, bc.width = 9, 12
            rs.add_chart(bc, "R22")

        men = resumen_mensual(df)
        f0, f1 = _escribir_tabla(writer, rs, men, 60, 1, "CVE publicadas por mes y fuente")
        if len(men):
            linea = LineChart()
            linea.title = "Tendencia mensual de CVE"
            linea.y_axis.title = "CVE"
            linea.add_data(Reference(rs, min_col=2, max_col=len(men.columns), min_row=f0, max_row=f1),
                           titles_from_data=True)
            linea.set_categories(Reference(rs, min_col=1, min_row=f0 + 1, max_row=f1))
            linea.height, linea.width = 9, 24
            rs.add_chart(linea, "J41")

        # ---- Hoja 3: parámetros de la consulta
        pd.DataFrame(list(parametros.items()), columns=["Parámetro", "Valor"]).to_excel(
            writer, sheet_name="Consulta", index=False)
        cs = writer.sheets["Consulta"]
        _encabezado(cs, 1, 1, 2)
        cs.column_dimensions["A"].width = 28
        cs.column_dimensions["B"].width = 90
    return ruta


def exportar_csv(df: pd.DataFrame, ruta: str | Path) -> Path:
    """CSV UTF-8 con BOM: Power BI y Excel lo abren con tildes correctas."""
    ruta = Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(ruta, index=False, encoding="utf-8-sig")
    return ruta
