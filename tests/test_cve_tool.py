"""Pruebas sin conexión a internet: validación de fechas, normalización y exportación."""

import io
import sys
from datetime import date
from pathlib import Path

import openpyxl
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cve_tool.exportar import exportar_excel, indicadores  # noqa: E402
from cve_tool.fuentes import (COLUMNAS, fecha_minima, normalizar_github, normalizar_kev,  # noqa: E402
                              normalizar_nvd, validar_rango, ventanas)

HOY = date(2026, 11, 4)

NVD = {"cve": {
    "id": "CVE-2026-0001", "published": "2026-10-01T10:00:00.000", "lastModified": "2026-10-02T00:00:00.000",
    "descriptions": [{"lang": "en", "value": "Buffer overflow in Foo."}],
    "affected": [{"affectedData": [{"vendor": "acme", "product": "foo"}]}],
    "metrics": {
        "cvssMetricV40": [{"type": "Secondary", "cvssData": {"version": "4.0", "baseScore": 6.9, "baseSeverity": "MEDIUM"}}],
        "cvssMetricV31": [{"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                                                            "vectorString": "CVSS:3.1/AV:N"}}],
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}, {"lang": "en", "value": "NVD-CWE-Other"}]}],
}}

GITHUB = {
    "ghsa_id": "GHSA-xxxx", "cve_id": "CVE-2026-0002", "summary": "XSS in bar", "severity": "moderate",
    "published_at": "2026-10-03T00:00:00Z", "updated_at": "2026-10-04T00:00:00Z",
    "html_url": "https://github.com/advisories/GHSA-xxxx",
    "cvss_severities": {"cvss_v3": {"score": 6.1, "vector_string": "CVSS:3.1/AV:N"}, "cvss_v4": {"score": 0.0}},
    "cwes": [{"cwe_id": "CWE-79"}],
    "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "bar"}}],
}

KEV = {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Foo", "vulnerabilityName": "Acme Foo RCE",
       "dateAdded": "2026-10-05", "shortDescription": "Allows RCE.", "knownRansomwareCampaignUse": "Known",
       "cwes": ["CWE-787"]}


def test_fecha_minima_cinco_anios():
    assert fecha_minima(HOY) == date(2021, 11, 4)
    assert fecha_minima(date(2028, 2, 29)) == date(2023, 2, 28)


def test_validar_rango():
    validar_rango(date(2022, 1, 1), date(2026, 1, 1), HOY)
    with pytest.raises(ValueError):
        validar_rango(date(2020, 1, 1), date(2026, 1, 1), HOY)  # más de 5 años
    with pytest.raises(ValueError):
        validar_rango(date(2026, 5, 1), date(2026, 1, 1), HOY)  # invertido
    with pytest.raises(ValueError):
        validar_rango(date(2026, 1, 1), date(2027, 1, 1), HOY)  # futuro


def test_ventanas_cubren_todo_el_rango():
    tramos = ventanas(date(2025, 1, 1), date(2025, 12, 31))
    assert tramos[0][0] == date(2025, 1, 1) and tramos[-1][1] == date(2025, 12, 31)
    assert all((fin - ini).days < 120 for ini, fin in tramos)


def test_normalizar_nvd_prefiere_cvss31():
    fila = normalizar_nvd(NVD)
    assert set(fila) == set(COLUMNAS)
    assert (fila["severidad"], fila["puntaje_cvss"], fila["cwe"]) == ("CRITICAL", 9.8, "CWE-787")
    assert (fila["proveedor"], fila["producto"]) == ("acme", "foo")


def test_normalizar_github_y_kev():
    g = normalizar_github(GITHUB)
    assert (g["severidad"], g["puntaje_cvss"], g["proveedor"]) == ("MEDIUM", 6.1, "npm")
    k = normalizar_kev(KEV)
    assert (k["explotada_activamente"], k["ransomware"], k["fecha_publicacion"]) == ("Sí", "Sí", "2026-10-05")


def test_exportar_excel_crea_hojas_y_graficas():
    df = pd.DataFrame([normalizar_nvd(NVD), normalizar_github(GITHUB), normalizar_kev(KEV)], columns=COLUMNAS)
    df["mes"] = df["fecha_publicacion"].str[:7]
    df["puntaje_cvss"] = pd.to_numeric(df["puntaje_cvss"])
    df["epss"] = pd.to_numeric(df["epss"])
    assert indicadores(df)["CVE únicas"] == 2
    buffer = io.BytesIO()
    exportar_excel(df, buffer, {"Fecha inicial": "2026-10-01", "Fecha final": "2026-10-31", "Fuentes": "todas"})
    libro = openpyxl.load_workbook(io.BytesIO(buffer.getvalue()))
    assert libro.sheetnames == ["CVEs", "Resumen", "Consulta"]
    assert "TablaCVE" in libro["CVEs"].tables
    assert len(libro["Resumen"]._charts) == 5
