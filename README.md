# Consulta y visualización de vulnerabilidades CVE

Programa en Python que se conecta a bases de datos públicas de vulnerabilidades,
consulta las CVE publicadas en un rango de fechas (dentro de los últimos 5 años),
unifica los datos importantes y los presenta de forma **dinámica y gráfica**.
Los resultados se exportan a **Excel** (con tablas y gráficas) y **CSV** para **Power BI**.

## Bases de datos consultadas

| Base de datos | Qué aporta | Acceso |
|---|---|---|
| **NVD** – NIST National Vulnerability Database | Todas las CVE publicadas: descripción, CVSS, severidad, CWE, proveedor/producto | API REST 2.0 (`services.nvd.nist.gov`) |
| **GitHub Advisory Database** | CVE en paquetes de software (npm, PyPI, Maven, Go…), CVSS y CWE | API REST (`api.github.com/advisories`) |
| **CISA KEV** – Known Exploited Vulnerabilities | CVE que se están explotando activamente y uso en ransomware | Feed JSON oficial de CISA |
| **EPSS** – FIRST.org *(enriquecimiento)* | Probabilidad de que la CVE sea explotada en los próximos 30 días | API REST (`api.first.org`) |

Todas las CVE se marcan además con si están en el catálogo KEV, y se les agrega su puntaje EPSS.

## Datos que se extraen

`cve_id`, `fuente`, `fecha_publicacion`, `fecha_actualizacion`, `anio`, `mes`, `severidad`,
`puntaje_cvss`, `version_cvss`, `vector_cvss`, `cwe`, `proveedor`, `producto`, `descripcion`,
`explotada_activamente`, `ransomware`, `epss`, `epss_percentil`, `url`.

## Instalación

```bash
pip install -r requirements.txt
```

También se puede abrir en **GitHub Codespaces** (botón *Code → Codespaces → Create codespace*):
el contenedor instala todo automáticamente.

## Uso

### 1. Aplicación gráfica (recomendada para la presentación)

```bash
streamlit run app.py
```

Se abre en el navegador (`http://localhost:8501`). En el panel izquierdo:

1. **Rango de fechas**: solo permite fechas de los últimos 5 años.
2. **Bases de datos**: marcar NVD, GitHub Advisory y/o CISA KEV.
3. **Opciones**: palabra clave (ej. `apache`), máximo de registros por fuente, EPSS.
4. Presionar **Consultar**.

La aplicación muestra indicadores (total, críticas, altas, explotadas, CVSS y EPSS promedio),
gráficas interactivas (tendencia mensual, severidad, proveedores, CWE, mapa de riesgo CVSS vs EPSS),
filtros sobre los resultados, la tabla de detalle y botones para **descargar Excel y CSV**.

### 2. Línea de comandos

```bash
python cli.py --desde 2025-01-01 --hasta 2025-06-30 --fuentes nvd github kev --max 2000
python cli.py --desde 2024-01-01 --hasta 2024-12-31 --palabra microsoft
```

Los archivos quedan en la carpeta `salidas/`.

## Archivo Excel generado

| Hoja | Contenido |
|---|---|
| `CVEs` | Todos los registros como **Tabla de Excel** (`TablaCVE`) con filtros y severidad coloreada |
| `Resumen` | Indicadores + 5 gráficas: severidad (torta), severidad por fuente (barras apiladas), top proveedores, top CWE y tendencia mensual (líneas) |
| `Consulta` | Parámetros usados (fechas, fuentes, palabra clave, fecha de consulta) |

## Visualizar en Power BI

1. *Inicio → Obtener datos → Libro de Excel* y elegir el `.xlsx` (marcar la tabla **TablaCVE**),
   o *Obtener datos → Texto/CSV* y elegir el `.csv`.
2. Revisar tipos en *Transformar datos*: `fecha_publicacion` = Fecha, `puntaje_cvss`, `epss` = Número decimal.
3. Visualizaciones sugeridas:
   - **Tarjetas**: Recuento distinto de `cve_id`; Promedio de `puntaje_cvss`.
   - **Gráfico de líneas**: Eje `mes`, Valores recuento de `cve_id`, Leyenda `fuente`.
   - **Gráfico de anillo**: Leyenda `severidad`, Valores recuento de `cve_id`.
   - **Barras horizontales**: Eje `proveedor` (filtro Top N = 10), Valores recuento de `cve_id`.
   - **Dispersión**: X `puntaje_cvss`, Y `epss`, Leyenda `severidad`, Detalles `cve_id`.
   - **Segmentaciones**: `fuente`, `severidad`, `explotada_activamente`, `fecha_publicacion` (entre).

## Límites de las APIs

- **NVD**: sin API key permite 5 peticiones cada 30 s (el programa espera entre peticiones).
  Con una clave gratuita (<https://nvd.nist.gov/developers/request-an-api-key>) es ~10 veces más rápido:
  definir la variable `NVD_API_KEY` o escribirla en la app.
- **GitHub**: sin token permite 60 peticiones por hora. Con `GITHUB_TOKEN` (o sesión iniciada en `gh`) 5000/hora.
- NVD publica más de 100 CVE por día. Si el rango tiene más registros que el máximo elegido,
  el programa reparte la descarga en todo el período para que las gráficas representen el rango completo,
  e informa cuántas CVE existen en total.

## Muestra de resultados

En [`muestras/`](muestras) hay una consulta real del 2026-05-01 al 2026-11-03 con las tres bases de datos
(6.181 registros: 3.000 de NVD, 3.000 de GitHub Advisory y 181 de CISA KEV, con EPSS):

- `muestra_resultados_CVE.xlsx`: datos, resumen con gráficas y parámetros de la consulta.
- `muestra_resultados_CVE.csv`: mismos datos para importar en Power BI.

## Estructura

```
app.py                  Aplicación gráfica (Streamlit + Plotly)
cli.py                  Versión de línea de comandos
cve_tool/fuentes.py     Conectores a NVD, GitHub Advisory, CISA KEV y EPSS
cve_tool/exportar.py    Exportación a Excel (tablas + gráficas) y CSV
tests/                  Pruebas automáticas (pytest), se ejecutan en GitHub Actions
```

## Pruebas

```bash
pytest -q
```
