"""Aplicación gráfica: consulta de CVE con filtros, gráficas interactivas y exportación.

Ejecutar con:
    streamlit run app.py
"""

import io
import os
from datetime import date, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st

from cve_tool import FUENTES, consultar, exportar_excel, fecha_minima
from cve_tool.exportar import fuente_por_severidad, indicadores, resumen_mensual, top
from cve_tool.fuentes import ORDEN_SEVERIDAD, iterar_mensajes, token_github

COLORES = {"CRITICAL": "#7B1FA2", "HIGH": "#D32F2F", "MEDIUM": "#F57C00",
           "LOW": "#FBC02D", "NONE": "#9E9E9E", "N/D": "#BDBDBD"}

st.set_page_config(page_title="Consulta de vulnerabilidades CVE", page_icon="🛡️", layout="wide")
st.title("🛡️ Consulta y visualización de vulnerabilidades CVE")
st.caption("Fuentes: NVD (NIST) · GitHub Advisory Database · CISA KEV · enriquecido con EPSS (FIRST.org)")

hoy = date.today()
minimo = fecha_minima(hoy)

# --------------------------------------------------------------------------- panel lateral
with st.sidebar:
    st.header("1. Rango de fechas")
    rango = st.date_input("Fecha de publicación", value=(hoy - timedelta(days=30), hoy),
                          min_value=minimo, max_value=hoy, format="YYYY-MM-DD")
    st.caption(f"Permitido: {minimo} a {hoy} (últimos 5 años)")

    st.header("2. Bases de datos")
    fuentes = [f for f in FUENTES if st.checkbox(f, value=True, help=FUENTES[f])]

    st.header("3. Opciones")
    palabra = st.text_input("Palabra clave (opcional)", placeholder="ej: apache, windows, wordpress")
    maximo = st.slider("Máximo de registros por fuente", 100, 10000, 1000, step=100,
                       help="NVD publica ~100 CVE por día. Si el rango tiene más, se toma una muestra "
                            "repartida en todo el período.")
    epss = st.checkbox("Agregar probabilidad de explotación (EPSS)", value=True)
    with st.expander("Claves de API (opcional, aceleran la consulta)"):
        nvd_key = st.text_input("NVD API key", value=os.environ.get("NVD_API_KEY", ""), type="password")
        gh_token = st.text_input("GitHub token", value="", type="password",
                                 help="Si se deja vacío se usa GITHUB_TOKEN o `gh auth token`.")
    consultar_btn = st.button("🔎 Consultar", type="primary", use_container_width=True)

# --------------------------------------------------------------------------- consulta
if consultar_btn:
    if not isinstance(rango, (tuple, list)) or len(rango) != 2:
        st.error("Seleccione la fecha inicial y la fecha final.")
    elif not fuentes:
        st.error("Seleccione al menos una base de datos.")
    else:
        inicio, fin = rango
        with st.status("Consultando bases de datos…", expanded=True) as estado:
            linea = st.empty()
            try:
                resultado = consultar(fuentes, inicio, fin, maximo, palabra,
                                      nvd_api_key=nvd_key or None,
                                      github_token=gh_token or token_github(),
                                      enriquecer_epss=epss, progreso=lambda m: linea.write(m))
            except Exception as e:  # mostrar cualquier error de red o validación en pantalla
                estado.update(label="Error en la consulta", state="error")
                st.exception(e)
                st.stop()
            linea.empty()
            for m in iterar_mensajes(resultado):
                st.write("•", m)
            estado.update(label=f"Consulta terminada: {len(resultado.datos)} registros", state="complete")
        st.session_state["datos"] = resultado.datos
        st.session_state["parametros"] = {
            "Fecha inicial": str(inicio), "Fecha final": str(fin), "Fuentes": ", ".join(fuentes),
            "Palabra clave": palabra or "(ninguna)", "Máximo por fuente": str(maximo),
            "Fecha de consulta": hoy.isoformat(),
        }

df: pd.DataFrame | None = st.session_state.get("datos")
if df is None:
    st.info("👈 Elija el rango de fechas y las bases de datos, y presione **Consultar**.")
    st.stop()
if df.empty:
    st.warning("La consulta no devolvió resultados. Pruebe con otro rango o sin palabra clave.")
    st.stop()

# --------------------------------------------------------------------------- filtros sobre resultados
st.subheader("Filtros sobre los resultados")
c1, c2, c3 = st.columns(3)
sev_presentes = [s for s in ORDEN_SEVERIDAD if s in df["severidad"].unique()]
f_sev = c1.multiselect("Severidad", sev_presentes, default=sev_presentes)
f_fuente = c2.multiselect("Fuente", sorted(df["fuente"].unique()), default=sorted(df["fuente"].unique()))
f_kev = c3.selectbox("Explotada activamente", ["Todas", "Sí", "No"])
vista = df[df["severidad"].isin(f_sev) & df["fuente"].isin(f_fuente)]
if f_kev != "Todas":
    vista = vista[vista["explotada_activamente"] == f_kev]

# --------------------------------------------------------------------------- indicadores
kpi = indicadores(vista) if len(vista) else {}
cols = st.columns(6)
for col, clave in zip(cols, ["CVE únicas", "Críticas", "Altas", "Explotadas activamente (KEV)",
                             "CVSS promedio", "EPSS promedio (%)"]):
    col.metric(clave.replace(" activamente (KEV)", " (KEV)"), kpi.get(clave, 0))

if vista.empty:
    st.warning("Ningún registro coincide con los filtros.")
    st.stop()

# --------------------------------------------------------------------------- gráficas
tab1, tab2, tab3, tab4 = st.tabs(["📈 Tendencia", "🎯 Severidad", "🏢 Proveedores y CWE", "⚠️ Riesgo"])

with tab1:
    mensual = resumen_mensual(vista).melt(id_vars="Mes", var_name="Fuente", value_name="CVE")
    fig = px.line(mensual, x="Mes", y="CVE", color="Fuente", markers=True,
                  title="CVE publicadas por mes y base de datos")
    st.plotly_chart(fig, use_container_width=True)
    diario = vista.groupby(["fecha_publicacion", "severidad"]).size().reset_index(name="CVE")
    fig = px.bar(diario, x="fecha_publicacion", y="CVE", color="severidad",
                 color_discrete_map=COLORES, category_orders={"severidad": ORDEN_SEVERIDAD},
                 title="CVE por fecha de publicación y severidad")
    st.plotly_chart(fig, use_container_width=True)

with tab2:
    a, b = st.columns(2)
    unicas = vista.drop_duplicates("cve_id")
    conteo = unicas["severidad"].value_counts().reindex(sev_presentes).dropna().reset_index()
    conteo.columns = ["Severidad", "CVE"]
    a.plotly_chart(px.pie(conteo, names="Severidad", values="CVE", hole=0.45, color="Severidad",
                          color_discrete_map=COLORES, category_orders={"Severidad": ORDEN_SEVERIDAD},
                          title="Distribución por severidad"),
                   use_container_width=True)
    fps = fuente_por_severidad(vista).melt(id_vars="Fuente", var_name="Severidad", value_name="CVE")
    b.plotly_chart(px.bar(fps, x="Fuente", y="CVE", color="Severidad", color_discrete_map=COLORES,
                          category_orders={"Severidad": ORDEN_SEVERIDAD}, title="Severidad por base de datos"),
                   use_container_width=True)
    st.plotly_chart(px.histogram(unicas.dropna(subset=["puntaje_cvss"]), x="puntaje_cvss", nbins=20,
                                 title="Distribución del puntaje CVSS", labels={"puntaje_cvss": "CVSS"}),
                    use_container_width=True)

with tab3:
    a, b = st.columns(2)
    prov = top(vista, "proveedor", 15)
    a.plotly_chart(px.bar(prov, x="Cantidad", y="Proveedor", orientation="h", title="Top 15 proveedores / ecosistemas")
                   .update_yaxes(autorange="reversed"), use_container_width=True)
    cwe = top(vista, "cwe", 15, separar=True)
    b.plotly_chart(px.bar(cwe, x="Cantidad", y="Cwe", orientation="h", title="Top 15 tipos de debilidad (CWE)")
                   .update_yaxes(autorange="reversed"), use_container_width=True)

with tab4:
    riesgo = vista.drop_duplicates("cve_id").dropna(subset=["puntaje_cvss", "epss"])
    if riesgo.empty:
        st.info("No hay registros con CVSS y EPSS para graficar.")
    else:
        fig = px.scatter(riesgo, x="puntaje_cvss", y="epss", color="severidad", symbol="explotada_activamente",
                         color_discrete_map=COLORES, hover_data=["cve_id", "proveedor", "producto"],
                         title="Impacto (CVSS) vs. probabilidad de explotación (EPSS)",
                         labels={"puntaje_cvss": "CVSS", "epss": "EPSS"})
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("**Top 15 CVE de mayor riesgo** (mayor EPSS)")
        st.dataframe(riesgo.nlargest(15, "epss")[["cve_id", "severidad", "puntaje_cvss", "epss",
                                                 "explotada_activamente", "proveedor", "producto", "descripcion"]],
                     hide_index=True, use_container_width=True)

# --------------------------------------------------------------------------- tabla y exportación
st.subheader(f"Detalle ({len(vista)} registros)")
st.dataframe(vista, hide_index=True, use_container_width=True,
             column_config={"url": st.column_config.LinkColumn("url"),
                            "epss": st.column_config.NumberColumn(format="%.4f")})

st.subheader("Exportar para Excel / Power BI")
parametros = st.session_state["parametros"]
nombre = f"cve_{parametros['Fecha inicial']}_{parametros['Fecha final']}"
excel = io.BytesIO()
exportar_excel(vista, excel, parametros)
a, b = st.columns(2)
a.download_button("⬇️ Descargar Excel (datos + resumen con gráficas)", excel.getvalue(), f"{nombre}.xlsx",
                  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)
b.download_button("⬇️ Descargar CSV (para Power BI)", vista.to_csv(index=False).encode("utf-8-sig"),
                  f"{nombre}.csv", "text/csv", use_container_width=True)
st.caption("En Power BI: Obtener datos → Excel (tabla **TablaCVE**) o Texto/CSV. Ver README para el paso a paso.")
