"""Conectores a las bases de datos públicas que registran CVE.

Cada conector devuelve una lista de diccionarios con el mismo esquema
(ver COLUMNAS), para poder unir los resultados de varias fuentes en una
sola tabla y exportarla a Excel / Power BI.

Fuentes disponibles:
    - NVD (NIST National Vulnerability Database)       API REST 2.0
    - GitHub Advisory Database                          API REST
    - CISA KEV (Known Exploited Vulnerabilities)        feed JSON
Enriquecimiento opcional:
    - EPSS (FIRST.org): probabilidad de explotación en los próximos 30 días
"""

from __future__ import annotations

import math
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Callable, Iterator

import pandas as pd
import requests

URL_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
URL_GITHUB = "https://api.github.com/advisories"
URL_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URL_EPSS = "https://api.first.org/data/v1/epss"

FUENTES = {
    "NVD": "NIST National Vulnerability Database (todas las CVE publicadas)",
    "GitHub Advisory": "GitHub Advisory Database (vulnerabilidades en paquetes de software)",
    "CISA KEV": "CISA Known Exploited Vulnerabilities (CVE explotadas activamente)",
}

COLUMNAS = [
    "cve_id", "fuente", "fecha_publicacion", "fecha_actualizacion", "anio", "mes",
    "severidad", "puntaje_cvss", "version_cvss", "vector_cvss", "cwe",
    "proveedor", "producto", "descripcion", "explotada_activamente",
    "ransomware", "epss", "epss_percentil", "url",
]

ORDEN_SEVERIDAD = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "N/D"]
AÑOS_MAXIMOS = 5
DIAS_VENTANA = 120  # la API de NVD no permite rangos mayores a 120 días
TIMEOUT = 60

Progreso = Callable[[str], None]


@dataclass
class ResultadoConsulta:
    datos: pd.DataFrame
    mensajes: list[str] = field(default_factory=list)
    # total de registros que existen en cada fuente para el rango (aunque se descargue menos)
    totales: dict[str, int] = field(default_factory=dict)


# --------------------------------------------------------------------------- utilidades

def fecha_minima(hoy: date | None = None) -> date:
    """Primer día permitido: hoy menos cinco años."""
    hoy = hoy or date.today()
    try:
        return hoy.replace(year=hoy.year - AÑOS_MAXIMOS)
    except ValueError:  # 29 de febrero
        return hoy.replace(year=hoy.year - AÑOS_MAXIMOS, day=28)


def validar_rango(inicio: date, fin: date, hoy: date | None = None) -> None:
    hoy = hoy or date.today()
    if inicio > fin:
        raise ValueError("La fecha inicial no puede ser mayor que la final.")
    if inicio < fecha_minima(hoy):
        raise ValueError(f"Solo se permiten fechas desde {fecha_minima(hoy)} (últimos {AÑOS_MAXIMOS} años).")
    if fin > hoy:
        raise ValueError("La fecha final no puede estar en el futuro.")


def ventanas(inicio: date, fin: date, dias: int = DIAS_VENTANA) -> list[tuple[date, date]]:
    """Divide [inicio, fin] en tramos de como máximo `dias` días."""
    tramos = []
    actual = inicio
    while actual <= fin:
        tope = min(actual + timedelta(days=dias - 1), fin)
        tramos.append((actual, tope))
        actual = tope + timedelta(days=1)
    return tramos


def ventanas_muestreo(inicio: date, fin: date) -> list[tuple[date, date]]:
    """Tramos para repartir el cupo de descarga: ~10 tramos, de entre 7 y 120 días."""
    dias = (fin - inicio).days + 1
    return ventanas(inicio, fin, max(7, min(DIAS_VENTANA, math.ceil(dias / 10))))


def token_github() -> str | None:
    """Token de GitHub desde la variable GITHUB_TOKEN o desde `gh auth token`."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    if shutil.which("gh"):
        try:
            salida = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10)
            if salida.returncode == 0 and salida.stdout.strip():
                return salida.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def _get(sesion: requests.Session, url: str, params: dict | None = None, headers: dict | None = None,
         intentos: int = 4, espera: float = 6.0) -> requests.Response:
    """GET con reintentos ante límites de peticiones o errores temporales."""
    for intento in range(intentos):
        try:
            resp = sesion.get(url, params=params, headers=headers, timeout=TIMEOUT)
        except requests.RequestException:
            if intento == intentos - 1:
                raise
            time.sleep(espera * (intento + 1))
            continue
        if resp.status_code in (429, 500, 502, 503, 504) or (
                resp.status_code == 403 and "nvd.nist.gov" in url):
            time.sleep(espera * (intento + 1))
            continue
        return resp
    return resp


def _texto(valor, limite: int = 1000) -> str:
    texto = " ".join(str(valor or "").split())
    return texto if len(texto) <= limite else texto[: limite - 1] + "…"


def _fila(**campos) -> dict:
    fila = dict.fromkeys(COLUMNAS)
    fila.update(campos)
    return fila


def _coincide(palabra: str | None, *textos) -> bool:
    if not palabra:
        return True
    palabra = palabra.lower()
    return any(palabra in str(t or "").lower() for t in textos)


# --------------------------------------------------------------------------- NVD

def _cvss_nvd(metricas: dict) -> tuple[str, float | None, str, str]:
    """Elige la mejor métrica CVSS disponible (3.1 > 3.0 > 4.0 > 2.0, primero la 'Primary')."""
    for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        lista = metricas.get(clave) or []
        if not lista:
            continue
        lista = sorted(lista, key=lambda m: m.get("type") != "Primary")
        m = lista[0]
        datos = m.get("cvssData", {})
        severidad = datos.get("baseSeverity") or m.get("baseSeverity") or "N/D"
        return severidad.upper(), datos.get("baseScore"), datos.get("version", ""), datos.get("vectorString", "")
    return "N/D", None, "", ""


def _proveedor_nvd(cve: dict) -> tuple[str, str]:
    for afectado in cve.get("affected") or []:
        for dato in afectado.get("affectedData") or []:
            if dato.get("vendor") or dato.get("product"):
                return dato.get("vendor", ""), dato.get("product", "")
    # respaldo: primer CPE de las configuraciones  cpe:2.3:a:proveedor:producto:...
    for conf in cve.get("configurations") or []:
        for nodo in conf.get("nodes") or []:
            for match in nodo.get("cpeMatch") or []:
                partes = match.get("criteria", "").split(":")
                if len(partes) > 4:
                    return partes[3], partes[4]
    return "", ""


def normalizar_nvd(item: dict) -> dict:
    cve = item["cve"]
    descripcion = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    severidad, puntaje, version, vector = _cvss_nvd(cve.get("metrics", {}))
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    proveedor, producto = _proveedor_nvd(cve)
    return _fila(
        cve_id=cve["id"], fuente="NVD",
        fecha_publicacion=cve.get("published", "")[:10],
        fecha_actualizacion=cve.get("lastModified", "")[:10],
        severidad=severidad, puntaje_cvss=puntaje, version_cvss=version, vector_cvss=vector,
        cwe=", ".join(cwes), proveedor=proveedor, producto=producto,
        descripcion=_texto(descripcion),
        url=f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
    )


def consultar_nvd(inicio: date, fin: date, maximo: int, palabra: str | None = None,
                  api_key: str | None = None, progreso: Progreso = print,
                  sesion: requests.Session | None = None) -> tuple[list[dict], int]:
    """Descarga CVE publicadas en NVD entre `inicio` y `fin`.

    Si hay más registros que `maximo`, el cupo se reparte entre los tramos de
    120 días para que la muestra cubra todo el rango (útil para las gráficas).
    """
    sesion = sesion or requests.Session()
    headers = {"apiKey": api_key} if api_key else None
    pausa = 0.7 if api_key else 6.5  # límite público: 5 peticiones cada 30 s
    tramos = ventanas_muestreo(inicio, fin)
    cupo = math.ceil(maximo / len(tramos))
    filas, total_real = [], 0
    for n, (desde, hasta) in enumerate(tramos, 1):
        indice, obtenidas = 0, 0
        while obtenidas < cupo:
            params = {
                "pubStartDate": f"{desde.isoformat()}T00:00:00.000",
                "pubEndDate": f"{hasta.isoformat()}T23:59:59.999",
                "resultsPerPage": min(2000, cupo - obtenidas),
                "startIndex": indice,
            }
            if palabra:
                params["keywordSearch"] = palabra
            progreso(f"NVD: tramo {n}/{len(tramos)} ({desde} a {hasta}), registros {indice}+")
            resp = _get(sesion, URL_NVD, params=params, headers=headers)
            resp.raise_for_status()
            datos = resp.json()
            if indice == 0:
                total_real += datos.get("totalResults", 0)
            lote = datos.get("vulnerabilities", [])
            filas.extend(normalizar_nvd(v) for v in lote)
            obtenidas += len(lote)
            indice += len(lote)
            time.sleep(pausa)
            if not lote or indice >= datos.get("totalResults", 0):
                break
    return filas[:maximo], total_real


def cvss_de_kev_en_nvd(inicio: date, fin: date, api_key: str | None = None, progreso: Progreso = print,
                       sesion: requests.Session | None = None) -> dict[str, tuple]:
    """Severidad/CVSS desde NVD para las CVE agregadas a KEV en el rango (KEV no trae CVSS)."""
    sesion = sesion or requests.Session()
    headers = {"apiKey": api_key} if api_key else None
    pausa = 0.7 if api_key else 6.5
    resultado: dict[str, tuple] = {}
    tramos = ventanas(inicio, fin, dias=90)  # NVD limita kevStartDate/kevEndDate a 90 días
    for n, (desde, hasta) in enumerate(tramos, 1):
        progreso(f"NVD: CVSS de vulnerabilidades KEV, tramo {n}/{len(tramos)}")
        params = {"kevStartDate": f"{desde}T00:00:00.000",
                  "kevEndDate": f"{hasta}T23:59:59.999", "resultsPerPage": 2000}
        # hasKev es un parámetro sin valor; requests omite los None, así que va en la URL
        resp = _get(sesion, f"{URL_NVD}?hasKev", params=params, headers=headers)
        if resp.status_code == 200:
            for v in resp.json().get("vulnerabilities", []):
                resultado[v["cve"]["id"]] = _cvss_nvd(v["cve"].get("metrics", {}))
        time.sleep(pausa)
    return resultado


# --------------------------------------------------------------------------- GitHub Advisory

def normalizar_github(adv: dict) -> dict:
    cvss = adv.get("cvss_severities") or {}
    puntaje, vector, version = None, "", ""
    for clave, ver in (("cvss_v3", "3.x"), ("cvss_v4", "4.0")):
        dato = cvss.get(clave) or {}
        if dato.get("score"):
            puntaje, vector, version = dato["score"], dato.get("vector_string") or "", ver
            break
    if puntaje is None and (adv.get("cvss") or {}).get("score"):
        puntaje, vector = adv["cvss"]["score"], adv["cvss"].get("vector_string") or ""
    paquetes = adv.get("vulnerabilities") or []
    ecosistema = paquetes[0]["package"].get("ecosystem", "") if paquetes and paquetes[0].get("package") else ""
    nombres = sorted({p["package"]["name"] for p in paquetes if p.get("package")})
    severidad = (adv.get("severity") or "").upper()
    severidad = {"MODERATE": "MEDIUM", "UNKNOWN": "N/D", "": "N/D"}.get(severidad, severidad)
    return _fila(
        cve_id=adv.get("cve_id") or adv.get("ghsa_id"), fuente="GitHub Advisory",
        fecha_publicacion=(adv.get("published_at") or "")[:10],
        fecha_actualizacion=(adv.get("updated_at") or "")[:10],
        severidad=severidad, puntaje_cvss=puntaje, version_cvss=version, vector_cvss=vector,
        cwe=", ".join(c["cwe_id"] for c in adv.get("cwes") or []),
        proveedor=ecosistema, producto=_texto(", ".join(nombres), 200),
        descripcion=_texto(adv.get("summary")), url=adv.get("html_url", ""),
    )


def consultar_github(inicio: date, fin: date, maximo: int, palabra: str | None = None,
                     token: str | None = None, progreso: Progreso = print,
                     sesion: requests.Session | None = None) -> tuple[list[dict], int, str | None]:
    """Descarga avisos revisados de GitHub que tienen identificador CVE."""
    sesion = sesion or requests.Session()
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    tramos = ventanas_muestreo(inicio, fin)
    cupo = math.ceil(maximo / len(tramos))
    filas, aviso, revisados = [], None, 0
    for n, (desde, hasta) in enumerate(reversed(tramos), 1):
        url = URL_GITHUB
        params = {"published": f"{desde}..{hasta}", "type": "reviewed", "per_page": 100}
        obtenidas = 0
        while url and obtenidas < cupo:
            progreso(f"GitHub Advisory: tramo {n}/{len(tramos)} ({desde} a {hasta}), {obtenidas} CVE")
            resp = _get(sesion, url, params=params, headers=headers, espera=3)
            if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
                aviso = ("GitHub Advisory: se alcanzó el límite de peticiones de GitHub "
                         "(60/hora sin token). Configure un token para descargar más.")
                return filas[:maximo], revisados, aviso
            resp.raise_for_status()
            for adv in resp.json():
                revisados += 1
                if not adv.get("cve_id") or adv.get("withdrawn_at"):
                    continue
                if not _coincide(palabra, adv.get("summary"), adv.get("description"), adv.get("cve_id")):
                    continue
                filas.append(normalizar_github(adv))
                obtenidas += 1
                if obtenidas >= cupo:
                    break
            url = resp.links.get("next", {}).get("url")
            params = None  # la URL "next" ya incluye los parámetros
    return filas[:maximo], revisados, aviso


# --------------------------------------------------------------------------- CISA KEV

def descargar_kev(sesion: requests.Session | None = None) -> list[dict]:
    sesion = sesion or requests.Session()
    resp = _get(sesion, URL_KEV)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


def normalizar_kev(v: dict) -> dict:
    return _fila(
        cve_id=v["cveID"], fuente="CISA KEV",
        fecha_publicacion=v.get("dateAdded", ""), fecha_actualizacion=v.get("dateAdded", ""),
        severidad="N/D", cwe=", ".join(v.get("cwes") or []),
        proveedor=v.get("vendorProject", ""), producto=v.get("product", ""),
        descripcion=_texto(f"{v.get('vulnerabilityName', '')}. {v.get('shortDescription', '')}"),
        explotada_activamente="Sí",
        ransomware="Sí" if v.get("knownRansomwareCampaignUse") == "Known" else "No",
        url=f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
    )


def consultar_kev(inicio: date, fin: date, maximo: int, palabra: str | None = None,
                  catalogo: list[dict] | None = None, progreso: Progreso = print) -> tuple[list[dict], int]:
    progreso("CISA KEV: descargando catálogo de vulnerabilidades explotadas")
    catalogo = catalogo if catalogo is not None else descargar_kev()
    seleccion = [
        v for v in catalogo
        if inicio.isoformat() <= v.get("dateAdded", "") <= fin.isoformat()
        and _coincide(palabra, v.get("cveID"), v.get("vendorProject"), v.get("product"),
                      v.get("vulnerabilityName"), v.get("shortDescription"))
    ]
    seleccion.sort(key=lambda v: v["dateAdded"], reverse=True)
    return [normalizar_kev(v) for v in seleccion[:maximo]], len(seleccion)


# --------------------------------------------------------------------------- EPSS

def consultar_epss(cves: list[str], progreso: Progreso = print,
                   sesion: requests.Session | None = None) -> dict[str, tuple[float, float]]:
    sesion = sesion or requests.Session()
    cves = sorted({c for c in cves if c and c.startswith("CVE-")})
    resultado: dict[str, tuple[float, float]] = {}
    for i in range(0, len(cves), 100):
        lote = cves[i:i + 100]
        progreso(f"EPSS: puntajes {i + len(lote)}/{len(cves)}")
        resp = _get(sesion, URL_EPSS, params={"cve": ",".join(lote), "limit": 100}, espera=2)
        if resp.status_code != 200:
            continue
        for d in resp.json().get("data", []):
            resultado[d["cve"]] = (float(d["epss"]), float(d["percentile"]))
    return resultado


# --------------------------------------------------------------------------- consulta principal

def consultar(fuentes: list[str], inicio: date, fin: date, maximo_por_fuente: int = 1000,
              palabra: str | None = None, nvd_api_key: str | None = None,
              github_token: str | None = None, enriquecer_epss: bool = True,
              progreso: Progreso = print) -> ResultadoConsulta:
    """Consulta las fuentes elegidas y devuelve una tabla unificada."""
    validar_rango(inicio, fin)
    if not fuentes:
        raise ValueError("Seleccione al menos una base de datos.")
    desconocidas = set(fuentes) - set(FUENTES)
    if desconocidas:
        raise ValueError(f"Fuentes no válidas: {', '.join(desconocidas)}")

    palabra = (palabra or "").strip() or None
    sesion = requests.Session()
    sesion.headers["User-Agent"] = "consulta-cve (proyecto academico)"
    filas: list[dict] = []
    mensajes: list[str] = []
    totales: dict[str, int] = {}

    catalogo_kev: list[dict] | None = None
    try:
        catalogo_kev = descargar_kev(sesion)
    except requests.RequestException as e:
        mensajes.append(f"No se pudo descargar el catálogo CISA KEV: {e}")

    if "NVD" in fuentes:
        try:
            datos, totales["NVD"] = consultar_nvd(inicio, fin, maximo_por_fuente, palabra,
                                                  nvd_api_key, progreso, sesion)
            filas += datos
        except requests.RequestException as e:
            mensajes.append(f"Error consultando NVD: {e}")
    if "GitHub Advisory" in fuentes:
        try:
            datos, revisados, aviso = consultar_github(inicio, fin, maximo_por_fuente, palabra,
                                                        github_token, progreso, sesion)
            filas += datos
            mensajes.append(f"GitHub Advisory: {len(datos)} CVE de {revisados} avisos revisados.")
            if aviso:
                mensajes.append(aviso)
        except requests.RequestException as e:
            mensajes.append(f"Error consultando GitHub Advisory: {e}")
    if "CISA KEV" in fuentes and catalogo_kev is not None:
        datos, totales["CISA KEV"] = consultar_kev(inicio, fin, maximo_por_fuente, palabra,
                                                   catalogo_kev, progreso)
        try:
            cvss = cvss_de_kev_en_nvd(inicio, fin, nvd_api_key, progreso, sesion) if datos else {}
        except requests.RequestException as e:
            cvss = {}
            mensajes.append(f"No se pudo completar el CVSS de KEV desde NVD: {e}")
        for fila in datos:
            if fila["cve_id"] in cvss:
                fila["severidad"], fila["puntaje_cvss"], fila["version_cvss"], fila["vector_cvss"] = cvss[fila["cve_id"]]
        filas += datos

    df = pd.DataFrame(filas, columns=COLUMNAS)
    if df.empty:
        return ResultadoConsulta(df, mensajes or ["No se encontraron CVE con esos filtros."], totales)

    # Marcar las CVE que aparecen en el catálogo de explotadas (CISA KEV)
    if catalogo_kev is not None:
        kev = {v["cveID"]: v for v in catalogo_kev}
        df["explotada_activamente"] = df["cve_id"].map(lambda c: "Sí" if c in kev else "No")
        df["ransomware"] = df["cve_id"].map(
            lambda c: ("Sí" if kev[c].get("knownRansomwareCampaignUse") == "Known" else "No") if c in kev else "No")

    # Completar severidad/CVSS de KEV con lo que traigan otras fuentes para la misma CVE
    conocidas = df[df["severidad"] != "N/D"].drop_duplicates("cve_id").set_index("cve_id")
    faltan = (df["severidad"] == "N/D") & df["cve_id"].isin(conocidas.index)
    if faltan.any():
        for col in ("severidad", "puntaje_cvss", "version_cvss", "vector_cvss"):
            df[col] = df[col].astype(object).where(~faltan, df["cve_id"].map(conocidas[col]))

    if enriquecer_epss:
        try:
            epss = consultar_epss(df["cve_id"].tolist(), progreso, sesion)
            df["epss"] = df["cve_id"].map(lambda c: epss.get(c, (None, None))[0])
            df["epss_percentil"] = df["cve_id"].map(lambda c: epss.get(c, (None, None))[1])
        except requests.RequestException as e:
            mensajes.append(f"No se pudo consultar EPSS: {e}")

    fechas = pd.to_datetime(df["fecha_publicacion"], errors="coerce")
    df["fecha_publicacion"] = fechas.dt.date
    df["fecha_actualizacion"] = pd.to_datetime(df["fecha_actualizacion"], errors="coerce").dt.date
    df["anio"] = fechas.dt.year.astype("Int64")
    df["mes"] = fechas.dt.strftime("%Y-%m")
    df["puntaje_cvss"] = pd.to_numeric(df["puntaje_cvss"], errors="coerce")
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    df["epss_percentil"] = pd.to_numeric(df["epss_percentil"], errors="coerce")
    df["severidad"] = df["severidad"].fillna("N/D")
    df = df.sort_values(["fecha_publicacion", "cve_id"], ascending=[False, True]).reset_index(drop=True)
    return ResultadoConsulta(df, mensajes, totales)


def iterar_mensajes(resultado: ResultadoConsulta) -> Iterator[str]:
    for fuente, total in resultado.totales.items():
        descargadas = int((resultado.datos["fuente"] == fuente).sum()) if not resultado.datos.empty else 0
        yield f"{fuente}: {descargadas} registros descargados (total publicado en el rango: {total})."
    yield from resultado.mensajes


def marca_tiempo() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")
