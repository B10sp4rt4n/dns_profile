"""
ProspectScan - Identificación de Oportunidades de Seguridad
Producto SaaS B2B - Análisis integral de dominios corporativos
"""

import pandas as pd
import dns.resolver
import streamlit as st
import re
import requests
import whois
import concurrent.futures
from functools import lru_cache
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple
from enum import Enum
from datetime import datetime

# ============================================================================
# CONFIGURACIÓN
# ============================================================================

st.set_page_config(
    page_title="ProspectScan",
    page_icon="🎯",
    layout="wide"
)

DNS_TIMEOUT = 5
REQUEST_TIMEOUT = 10
MAX_WORKERS = 10

DOMINIOS_PERSONALES = frozenset([
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com",
    "protonmail.com", "icloud.com", "aol.com", "live.com"
])


# ============================================================================
# ENUMS Y ESTADOS
# ============================================================================

class Postura(Enum):
    AVANZADA = "Avanzada"
    INTERMEDIA = "Intermedia"
    BASICA = "Básica"


class EstadoSPF(Enum):
    OK = "OK"
    DEBIL = "Débil"
    AUSENTE = "Ausente"


class EstadoDMARC(Enum):
    REJECT = "Reject"
    QUARANTINE = "Quarantine"
    NONE = "None"
    AUSENTE = "Ausente"


class EstadoHTTPS(Enum):
    FORZADO = "Forzado"
    DISPONIBLE = "Disponible"
    NO_DISPONIBLE = "No disponible"


class EstadoHeader(Enum):
    PRESENTE = "Presente"
    DEBIL = "Débil"
    AUSENTE = "Ausente"


# ============================================================================
# CATÁLOGOS DE VENDORS
# ============================================================================

VENDORS_CORREO_MX = {
    r'outlook|protection\.outlook|microsoft': "Microsoft 365",
    r'google|googlemail|smtp\.google': "Google Workspace",
    r'zoho': "Zoho Mail",
    r'secureserver|domaincontrol': "GoDaddy",
}

VENDORS_SEGURIDAD_MX = {
    r'proofpoint|pphosted': "Proofpoint",
    r'mimecast': "Mimecast",
    r'barracuda|barracudanetworks': "Barracuda",
    r'iphmx|ironport': "Cisco IronPort",
}

VENDORS_SEGURIDAD_SPF = {
    r'include:_spf\.proofpoint\.com': "Proofpoint",
    r'include:.*mimecast': "Mimecast",
    r'include:.*barracuda': "Barracuda",
}

VENDORS_ENVIO_SPF = {
    r'include:sendgrid\.net': "SendGrid",
    r'include:.*mailgun\.org': "Mailgun",
    r'include:amazonses\.com': "Amazon SES",
    r'include:.*mailchimp\.com': "Mailchimp",
    r'include:.*hubspot\.com': "HubSpot",
    r'include:.*salesforce\.com': "Salesforce",
}

CDN_WAF_HEADERS = {
    r'cloudflare': "Cloudflare",
    r'akamai': "Akamai",
    r'fastly': "Fastly",
    r'cloudfront': "CloudFront",
    r'sucuri': "Sucuri",
    r'incapsula|imperva': "Imperva",
}


# ============================================================================
# ESTRUCTURAS DE DATOS
# ============================================================================

@dataclass
class ResultadoIdentidad:
    spf_raw: str
    estado_spf: EstadoSPF
    dmarc_raw: str
    estado_dmarc: EstadoDMARC
    vendor_correo: Optional[str]
    vendors_seguridad: List[str]
    vendors_envio: List[str]
    postura: Postura


@dataclass
class ResultadoExposicion:
    https: EstadoHTTPS
    hsts: EstadoHeader
    csp: EstadoHeader
    x_frame: EstadoHeader
    cdn_waf: Optional[str]
    servidor: Optional[str]
    postura: Postura
    error: Optional[str]


@dataclass
class ResultadoSuperficie:
    dominio: str
    identidad: ResultadoIdentidad
    exposicion: ResultadoExposicion
    postura_general: Postura
    recomendaciones: List[str]


# ============================================================================
# FUNCIONES DNS (IDENTIDAD)
# ============================================================================

@lru_cache(maxsize=1024)
def obtener_mx(dominio: str) -> List[str]:
    try:
        resp = dns.resolver.resolve(dominio, 'MX', lifetime=DNS_TIMEOUT)
        return [r.exchange.to_text().rstrip('.').lower() for r in resp]
    except Exception:
        return []


@lru_cache(maxsize=1024)
def obtener_spf(dominio: str) -> str:
    try:
        resp = dns.resolver.resolve(dominio, 'TXT', lifetime=DNS_TIMEOUT)
        for r in resp:
            txt = b''.join(r.strings).decode()
            if "v=spf1" in txt.lower():
                return txt
    except Exception:
        pass
    return ""


@lru_cache(maxsize=1024)
def obtener_dmarc(dominio: str) -> str:
    try:
        resp = dns.resolver.resolve(f"_dmarc.{dominio}", 'TXT', lifetime=DNS_TIMEOUT)
        for r in resp:
            txt = b''.join(r.strings).decode()
            if "v=DMARC1" in txt.upper():
                return txt
    except Exception:
        pass
    return ""


def evaluar_spf(spf: str) -> EstadoSPF:
    if not spf:
        return EstadoSPF.AUSENTE
    spf_lower = spf.lower()
    if "+all" in spf_lower or "?all" in spf_lower:
        return EstadoSPF.DEBIL
    if "~all" not in spf_lower and "-all" not in spf_lower:
        return EstadoSPF.DEBIL
    return EstadoSPF.OK


def evaluar_dmarc(dmarc: str) -> EstadoDMARC:
    if not dmarc:
        return EstadoDMARC.AUSENTE
    dmarc_lower = dmarc.lower()
    if "p=reject" in dmarc_lower:
        return EstadoDMARC.REJECT
    if "p=quarantine" in dmarc_lower:
        return EstadoDMARC.QUARANTINE
    if "p=none" in dmarc_lower:
        return EstadoDMARC.NONE
    return EstadoDMARC.AUSENTE


def detectar_vendor_correo(mx: List[str]) -> Optional[str]:
    for registro in mx:
        for patron, nombre in VENDORS_CORREO_MX.items():
            if re.search(patron, registro, re.IGNORECASE):
                return nombre
    if mx:
        return "Infraestructura propia"
    return None


def detectar_vendors_seguridad(mx: List[str], spf: str) -> List[str]:
    vendors = set()
    for registro in mx:
        for patron, nombre in VENDORS_SEGURIDAD_MX.items():
            if re.search(patron, registro, re.IGNORECASE):
                vendors.add(nombre)
    if spf:
        for patron, nombre in VENDORS_SEGURIDAD_SPF.items():
            if re.search(patron, spf, re.IGNORECASE):
                vendors.add(nombre)
    return list(vendors)


def detectar_vendors_envio(spf: str) -> List[str]:
    vendors = set()
    if spf:
        for patron, nombre in VENDORS_ENVIO_SPF.items():
            if re.search(patron, spf, re.IGNORECASE):
                vendors.add(nombre)
    return list(vendors)


def calcular_postura_identidad(
    estado_spf: EstadoSPF,
    estado_dmarc: EstadoDMARC,
    vendors_seguridad: List[str]
) -> Postura:
    puntos = 0
    if estado_spf == EstadoSPF.OK:
        puntos += 2
    elif estado_spf == EstadoSPF.DEBIL:
        puntos += 1
    if estado_dmarc == EstadoDMARC.REJECT:
        puntos += 3
    elif estado_dmarc == EstadoDMARC.QUARANTINE:
        puntos += 2
    elif estado_dmarc == EstadoDMARC.NONE:
        puntos += 1
    if vendors_seguridad:
        puntos += 2
    if puntos >= 6:
        return Postura.AVANZADA
    elif puntos >= 3:
        return Postura.INTERMEDIA
    return Postura.BASICA


def analizar_identidad(dominio: str) -> ResultadoIdentidad:
    mx = obtener_mx(dominio)
    spf = obtener_spf(dominio)
    dmarc = obtener_dmarc(dominio)
    
    estado_spf = evaluar_spf(spf)
    estado_dmarc = evaluar_dmarc(dmarc)
    vendor_correo = detectar_vendor_correo(mx)
    vendors_seguridad = detectar_vendors_seguridad(mx, spf)
    vendors_envio = detectar_vendors_envio(spf)
    postura = calcular_postura_identidad(estado_spf, estado_dmarc, vendors_seguridad)
    
    return ResultadoIdentidad(
        spf_raw=spf or "No encontrado",
        estado_spf=estado_spf,
        dmarc_raw=dmarc or "No encontrado",
        estado_dmarc=estado_dmarc,
        vendor_correo=vendor_correo,
        vendors_seguridad=vendors_seguridad,
        vendors_envio=vendors_envio,
        postura=postura
    )


# ============================================================================
# FUNCIONES HTTP (EXPOSICIÓN)
# ============================================================================

def hacer_request(dominio: str) -> Optional[requests.Response]:
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)'}
    for proto in ["https", "http"]:
        try:
            return requests.get(
                f"{proto}://{dominio}",
                timeout=REQUEST_TIMEOUT,
                headers=headers,
                allow_redirects=True,
                verify=(proto == "https")
            )
        except Exception:
            continue
    return None


def evaluar_https(dominio: str) -> EstadoHTTPS:
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)'}
    https_ok = False
    try:
        requests.get(f"https://{dominio}", timeout=REQUEST_TIMEOUT, headers=headers, verify=True)
        https_ok = True
    except Exception:
        pass
    
    if not https_ok:
        return EstadoHTTPS.NO_DISPONIBLE
    
    try:
        resp = requests.get(f"http://{dominio}", timeout=REQUEST_TIMEOUT, headers=headers, allow_redirects=True)
        if resp.url.startswith("https://"):
            return EstadoHTTPS.FORZADO
    except Exception:
        return EstadoHTTPS.FORZADO
    
    return EstadoHTTPS.DISPONIBLE


def evaluar_hsts(headers: Dict) -> EstadoHeader:
    hsts = headers.get('Strict-Transport-Security', '')
    if not hsts:
        return EstadoHeader.AUSENTE
    match = re.search(r'max-age=(\d+)', hsts)
    if match and int(match.group(1)) < 31536000:
        return EstadoHeader.DEBIL
    return EstadoHeader.PRESENTE


def evaluar_csp(headers: Dict) -> EstadoHeader:
    csp = headers.get('Content-Security-Policy', '')
    if not csp:
        return EstadoHeader.AUSENTE
    if "unsafe-inline" in csp and "unsafe-eval" in csp:
        return EstadoHeader.DEBIL
    return EstadoHeader.PRESENTE


def evaluar_xframe(headers: Dict) -> EstadoHeader:
    return EstadoHeader.PRESENTE if headers.get('X-Frame-Options') else EstadoHeader.AUSENTE


def detectar_cdn_waf(headers: Dict) -> Optional[str]:
    server = headers.get('Server', '').lower()
    all_h = ' '.join(str(v) for v in headers.values()).lower()
    
    for patron, nombre in CDN_WAF_HEADERS.items():
        if re.search(patron, server, re.IGNORECASE) or re.search(patron, all_h, re.IGNORECASE):
            return nombre
    
    if 'cf-ray' in headers:
        return "Cloudflare"
    if 'x-sucuri-id' in headers:
        return "Sucuri"
    return None


def detectar_servidor(headers: Dict) -> Optional[str]:
    server = headers.get('Server', '')
    if server:
        return server.split('/')[0].title()
    return None


def calcular_postura_exposicion(
    https: EstadoHTTPS,
    hsts: EstadoHeader,
    csp: EstadoHeader,
    x_frame: EstadoHeader,
    cdn_waf: Optional[str]
) -> Postura:
    puntos = 0
    if https == EstadoHTTPS.FORZADO:
        puntos += 2
    elif https == EstadoHTTPS.DISPONIBLE:
        puntos += 1
    if hsts == EstadoHeader.PRESENTE:
        puntos += 2
    elif hsts == EstadoHeader.DEBIL:
        puntos += 1
    if csp == EstadoHeader.PRESENTE:
        puntos += 2
    elif csp == EstadoHeader.DEBIL:
        puntos += 1
    if x_frame == EstadoHeader.PRESENTE:
        puntos += 1
    if cdn_waf:
        puntos += 1
    
    if puntos >= 6:
        return Postura.AVANZADA
    elif puntos >= 3:
        return Postura.INTERMEDIA
    return Postura.BASICA


def analizar_exposicion(dominio: str) -> ResultadoExposicion:
    https = evaluar_https(dominio)
    resp = hacer_request(dominio)
    
    if not resp:
        return ResultadoExposicion(
            https=https,
            hsts=EstadoHeader.AUSENTE,
            csp=EstadoHeader.AUSENTE,
            x_frame=EstadoHeader.AUSENTE,
            cdn_waf=None,
            servidor=None,
            postura=Postura.BASICA,
            error="No se pudo conectar"
        )
    
    h = dict(resp.headers)
    hsts = evaluar_hsts(h)
    csp = evaluar_csp(h)
    x_frame = evaluar_xframe(h)
    cdn_waf = detectar_cdn_waf(h)
    servidor = detectar_servidor(h)
    postura = calcular_postura_exposicion(https, hsts, csp, x_frame, cdn_waf)
    
    return ResultadoExposicion(
        https=https,
        hsts=hsts,
        csp=csp,
        x_frame=x_frame,
        cdn_waf=cdn_waf,
        servidor=servidor,
        postura=postura,
        error=None
    )


# ============================================================================
# POSTURA GENERAL Y RECOMENDACIONES
# ============================================================================

def calcular_postura_general(identidad: Postura, exposicion: Postura) -> Postura:
    valores = {Postura.AVANZADA: 3, Postura.INTERMEDIA: 2, Postura.BASICA: 1}
    suma = valores[identidad] + valores[exposicion]
    
    if suma >= 5:
        return Postura.AVANZADA
    elif suma >= 3:
        return Postura.INTERMEDIA
    return Postura.BASICA


def generar_recomendaciones(resultado: 'ResultadoSuperficie') -> List[str]:
    recs = []
    
    # Identidad
    if resultado.identidad.estado_dmarc in [EstadoDMARC.AUSENTE, EstadoDMARC.NONE]:
        recs.append("Implementar política DMARC con enforcement para proteger la identidad del dominio.")
    
    if resultado.identidad.estado_spf != EstadoSPF.OK:
        recs.append("Fortalecer la configuración SPF para prevenir suplantación de remitentes.")
    
    if not resultado.identidad.vendors_seguridad:
        recs.append("Considerar un gateway de seguridad de correo para filtrado avanzado de amenazas.")
    
    # Exposición
    if resultado.exposicion.https != EstadoHTTPS.FORZADO:
        recs.append("Forzar el uso de HTTPS en todas las conexiones web.")
    
    if resultado.exposicion.hsts != EstadoHeader.PRESENTE:
        recs.append("Habilitar HSTS para prevenir ataques de downgrade de protocolo.")
    
    if resultado.exposicion.csp != EstadoHeader.PRESENTE:
        recs.append("Implementar Content Security Policy para mitigar riesgos de inyección de código.")
    
    if not resultado.exposicion.cdn_waf:
        recs.append("Evaluar la implementación de un WAF o CDN con capacidades de protección.")
    
    return recs[:3]


# ============================================================================
# ANÁLISIS COMPLETO
# ============================================================================

def analizar_dominio(dominio: str) -> ResultadoSuperficie:
    identidad = analizar_identidad(dominio)
    exposicion = analizar_exposicion(dominio)
    postura_general = calcular_postura_general(identidad.postura, exposicion.postura)
    
    resultado = ResultadoSuperficie(
        dominio=dominio,
        identidad=identidad,
        exposicion=exposicion,
        postura_general=postura_general,
        recomendaciones=[]
    )
    resultado.recomendaciones = generar_recomendaciones(resultado)
    
    return resultado


# ============================================================================
# CONVERSIÓN A DATAFRAMES
# ============================================================================

def resultado_a_ejecutivo(r: ResultadoSuperficie) -> Dict:
    return {
        "Dominio": r.dominio,
        "Postura Identidad": r.identidad.postura.value,
        "Postura Exposición": r.exposicion.postura.value,
        "Vendor Correo": r.identidad.vendor_correo or "No detectado",
        "Seguridad Correo": ", ".join(r.identidad.vendors_seguridad) or "Sin gateway",
        "CDN/WAF": r.exposicion.cdn_waf or "Sin protección",
        "Superficie Digital": r.postura_general.value,
        "Recomendaciones": " | ".join(r.recomendaciones) if r.recomendaciones else "Sin recomendaciones"
    }


def resultado_a_tecnico(r: ResultadoSuperficie) -> Dict:
    return {
        "Dominio": r.dominio,
        # Identidad
        "SPF (Raw)": r.identidad.spf_raw,
        "Estado SPF": r.identidad.estado_spf.value,
        "DMARC (Raw)": r.identidad.dmarc_raw,
        "Estado DMARC": r.identidad.estado_dmarc.value,
        "Vendor Correo": r.identidad.vendor_correo or "No detectado",
        "Vendors Seguridad": ", ".join(r.identidad.vendors_seguridad) or "Ninguno",
        "Vendors Envío": ", ".join(r.identidad.vendors_envio) or "Ninguno",
        "Postura Identidad": r.identidad.postura.value,
        # Exposición
        "HTTPS": r.exposicion.https.value,
        "HSTS": r.exposicion.hsts.value,
        "CSP": r.exposicion.csp.value,
        "X-Frame-Options": r.exposicion.x_frame.value,
        "CDN/WAF": r.exposicion.cdn_waf or "No detectado",
        "Servidor": r.exposicion.servidor or "No detectado",
        "Postura Exposición": r.exposicion.postura.value,
        # General
        "Superficie Digital": r.postura_general.value
    }


# ============================================================================
# UTILIDADES
# ============================================================================

def validar_email(email: str) -> bool:
    if not isinstance(email, str):
        return False
    return bool(re.match(r'^[\w\.\-\+]+@[a-zA-Z\d\.\-]+\.[a-zA-Z]{2,}$', email))


def extraer_dominio(email: str) -> str:
    if validar_email(email):
        return email.split("@")[-1].lower().strip()
    return ""


def es_corporativo(dominio: str) -> bool:
    return dominio and dominio not in DOMINIOS_PERSONALES


# ============================================================================
# INTERFAZ STREAMLIT
# ============================================================================

def main():
    # Header ejecutivo
    st.set_page_config(page_title="Diagnóstico de Superficie Digital", page_icon="🎯", layout="wide")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("🎯 ProspectScan")
        st.markdown("**Identifica oportunidades de seguridad en tus prospectos en segundos**")
    with col2:
        st.image("https://via.placeholder.com/150x80/4a90e2/ffffff?text=LOGO", width=150)
    
    # Value proposition
    with st.container():
        st.markdown("""
        <div style="background-color: #2c3e50; padding: 20px; border-radius: 10px; margin: 20px 0; color: white;">
        <h3 style="color: white;">🚀 Para equipos de ventas y partners de ciberseguridad</h3>
        <p style="color: white;">Analiza la postura de seguridad de tus prospectos antes de la primera llamada. 
        Identifica gaps de correo y web que justifican tu solución.</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Upload mejorado
    col1, col2 = st.columns([2, 1])
    with col1:
        archivo = st.file_uploader(
            "📁 Sube tu lista de prospectos (CSV)",
            type="csv",
            help="CSV con columna de correos corporativos. Ej: ZoomInfo, LinkedIn, CRM export"
        )
    with col2:
        st.markdown("**Ejemplos de uso:**")
        st.markdown("• Lista de prospectos de LinkedIn")
        st.markdown("• Exportación de CRM")
        st.markdown("• Base de partners/resellers")
        st.markdown("• Leads de marketing")
    
    if not archivo:
        st.info("👆 Sube tu lista de prospectos para identificar oportunidades")
        
        # Demo interactivo
        with st.expander("🚀 Ver ejemplo con dominios conocidos"):
            if st.button("Analizar Amazon, Microsoft, Dropbox"):
                demo_dominios = ["amazon.com", "microsoft.com", "dropbox.com"]
                st.info("Ejecutando análisis demo...")
                # Aquí podríamos hacer el análisis real para la demo
        
        # Value props
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            **🎯 Casos de uso:**
            - Calificar leads antes de llamadas
            - Priorizar prospectos por gaps de seguridad
            - Preparar argumentos técnicos de venta
            - Reportes para partners/resellers
            """)
        with col2:
            st.markdown("""
            **📊 Lo que obtienes:**
            - Postura de seguridad por prospecto
            - Vendors actuales detectados
            - Gaps específicos identificados
            - Recomendaciones comerciales
            """)
        return
    
    try:
        df = pd.read_csv(archivo).rename(columns=lambda x: x.strip())
        
        email_cols = [c for c in df.columns if 'email' in c.lower() or 'correo' in c.lower()]
        if not email_cols:
            st.error("❌ No se encontró columna de correo electrónico")
            return
        
        col_email = email_cols[0]
        st.success(f"✅ Columna detectada: **{col_email}**")
        
        df["_dominio"] = df[col_email].apply(extraer_dominio)
        dominios = [d for d in df["_dominio"].dropna().unique() if es_corporativo(d)]
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Total emails", len(df))
        c2.metric("Emails personales", len(df[df["_dominio"].isin(DOMINIOS_PERSONALES)]))
        c3.metric("Dominios corporativos", len(dominios))
        
        if not dominios:
            st.warning("⚠️ No se encontraron dominios corporativos")
            return
        
        st.markdown("---")
        st.subheader("🔍 Diagnóstico en progreso")
        
        progreso = st.progress(0)
        estado = st.empty()
        resultados: List[ResultadoSuperficie] = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futuros = {executor.submit(analizar_dominio, d): d for d in dominios}
            for i, futuro in enumerate(concurrent.futures.as_completed(futuros)):
                dom = futuros[futuro]
                try:
                    resultados.append(futuro.result())
                except Exception as e:
                    st.warning(f"Error en {dom}: {e}")
                progreso.progress((i + 1) / len(dominios))
                estado.text(f"Analizando: {dom}")
        
        estado.text("✅ Diagnóstico completado")
        
        df_ejecutivo = pd.DataFrame([resultado_a_ejecutivo(r) for r in resultados])
        df_tecnico = pd.DataFrame([resultado_a_tecnico(r) for r in resultados])
        
        # === RESUMEN EJECUTIVO ===
        st.markdown("---")
        st.subheader("� Oportunidades Comerciales Identificadas")
        
        # KPIs comerciales
        total = len(resultados)
        oportunidades = len([r for r in resultados if r.postura_general == Postura.BASICA])
        sin_gateway = len([r for r in resultados if not r.identidad.vendors_seguridad])
        sin_waf = len([r for r in resultados if not r.exposicion.cdn_waf])
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🎯 Total analizados", total)
        col2.metric("🔥 Postura básica", oportunidades, help="Prospectos con mayor potencial")
        col3.metric("📧 Sin gateway email", sin_gateway, help="Oportunidad para seguridad de correo")
        col4.metric("🌐 Sin WAF/CDN", sin_waf, help="Oportunidad para protección web")
        
        # Filtros ejecutivos
        st.markdown("#### 🎯 Prioriza tus prospectos")
        filtro = st.selectbox(
            "Mostrar:",
            ["Todos los dominios", "Solo postura básica (alta prioridad)", "Sin gateway de correo", "Sin protección web"],
            help="Filtra para enfocarte en las mejores oportunidades"
        )
        
        df_mostrar = df_ejecutivo.copy()
        if filtro == "Solo postura básica (alta prioridad)":
            df_mostrar = df_mostrar[df_mostrar["Superficie Digital"] == "Básica"]
        elif filtro == "Sin gateway de correo":
            df_mostrar = df_mostrar[df_mostrar["Seguridad Correo"] == "Sin gateway"]
        elif filtro == "Sin protección web":
            df_mostrar = df_mostrar[df_mostrar["CDN/WAF"] == "Sin protección"]
        
        # Tabla mejorada con colores
        if not df_mostrar.empty:
            st.dataframe(
                df_mostrar.style.applymap(
                    lambda x: 'background-color: #ffebee' if x == 'Básica' 
                    else 'background-color: #fff3e0' if x == 'Intermedia'
                    else 'background-color: #e8f5e8' if x == 'Avanzada'
                    else '',
                    subset=['Superficie Digital']
                ),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.warning("No hay dominios que cumplan el filtro seleccionado")
        
        # Call to action
        st.markdown("""
        <div style="background-color: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0;">
        💡 <strong>Próximo paso:</strong> Contacta los dominios con postura "Básica" - 
        tienen los mayores gaps de seguridad y necesidad de tus soluciones.
        </div>
        """, unsafe_allow_html=True)
        
        # Exportación comercial
        col1, col2 = st.columns(2)
        with col1:
            csv_ej = df_ejecutivo.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Exportar Lista de Prospectos", 
                csv_ej, 
                f"oportunidades_comerciales_{datetime.now().strftime('%Y%m%d')}.csv", 
                "text/csv",
                help="CSV listo para importar a tu CRM"
            )
        with col2:
            # Template de email
            template_email = """Hola [NOMBRE],

Hice un análisis de seguridad de [DOMINIO] y encontré algunas oportunidades:

• [GAPS_DETECTADOS]

¿Tienes 15 minutos esta semana para revisar los hallazgos?

Saludos,
[TU_NOMBRE]"""
            
            st.download_button(
                "📧 Template de Email", 
                template_email.encode("utf-8"), 
                "template_prospecting.txt", 
                "text/plain",
                help="Plantilla para contactar prospectos"
            )
        
        # === ANEXO TÉCNICO ===
        st.markdown("---")
        st.subheader("🔧 Anexo Técnico")
        
        with st.expander("Ver detalle técnico completo"):
            st.dataframe(df_tecnico, use_container_width=True, hide_index=True)
        
        csv_tec = df_tecnico.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Descargar Anexo Técnico", csv_tec, "anexo_tecnico_superficie.csv", "text/csv")
        
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")


if __name__ == "__main__":
    main()
