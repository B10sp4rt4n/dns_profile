"""
Diagnóstico de Postura Web Corporativa v1
Producto SaaS B2B - Análisis de dominios corporativos
"""

import pandas as pd
import streamlit as st
import re
import requests
import concurrent.futures
from functools import lru_cache
from dataclasses import dataclass
from typing import Optional, List, Dict
from enum import Enum
from urllib.parse import urlparse

# ============================================================================
# CONFIGURACIÓN Y CONSTANTES
# ============================================================================

st.set_page_config(page_title="Diagnóstico de Postura Web Corporativa", layout="wide")

REQUEST_TIMEOUT = 10
MAX_WORKERS = 10
DOMINIOS_PERSONALES = frozenset([
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", 
    "protonmail.com", "icloud.com", "aol.com", "live.com"
])


class EstadoHeader(Enum):
    PRESENTE = "Presente"
    AUSENTE = "Ausente"
    DEBIL = "Débil"


class EstadoHTTPS(Enum):
    FORZADO = "Forzado"
    DISPONIBLE = "Disponible"
    NO_DISPONIBLE = "No disponible"


class PosturaGeneral(Enum):
    AVANZADA = "Avanzada"
    INTERMEDIA = "Intermedia"
    BASICA = "Básica"


# ============================================================================
# CATÁLOGOS DE TECNOLOGÍAS
# ============================================================================

TECNOLOGIAS_SERVER = {
    r'nginx': "Nginx",
    r'apache': "Apache",
    r'cloudflare': "Cloudflare",
    r'microsoft-iis': "Microsoft IIS",
    r'litespeed': "LiteSpeed",
    r'openresty': "OpenResty",
    r'gunicorn': "Gunicorn",
    r'uvicorn': "Uvicorn",
}

TECNOLOGIAS_POWERED = {
    r'php': "PHP",
    r'asp\.net': "ASP.NET",
    r'express': "Express.js",
    r'next\.js': "Next.js",
    r'wordpress': "WordPress",
    r'drupal': "Drupal",
}

CDN_WAF_DETECTADOS = {
    r'cloudflare': ("Cloudflare", "CDN/WAF"),
    r'akamai': ("Akamai", "CDN"),
    r'fastly': ("Fastly", "CDN"),
    r'cloudfront': ("CloudFront", "CDN"),
    r'sucuri': ("Sucuri", "WAF"),
    r'incapsula|imperva': ("Imperva", "WAF"),
    r'stackpath': ("StackPath", "CDN/WAF"),
}


# ============================================================================
# ESTRUCTURAS DE DATOS
# ============================================================================

@dataclass
class HeadersSeguridad:
    hsts: EstadoHeader
    hsts_raw: str
    csp: EstadoHeader
    csp_raw: str
    x_frame_options: EstadoHeader
    x_content_type: EstadoHeader
    x_xss_protection: EstadoHeader
    referrer_policy: EstadoHeader


@dataclass
class ResultadoAnalisis:
    dominio: str
    https: EstadoHTTPS
    servidor: Optional[str]
    tecnologia: Optional[str]
    cdn_waf: Optional[str]
    headers: HeadersSeguridad
    postura: PosturaGeneral
    error: Optional[str]


# ============================================================================
# FUNCIONES DE ANÁLISIS
# ============================================================================

def hacer_request(dominio: str) -> Optional[requests.Response]:
    """Intenta conectar al dominio via HTTPS, luego HTTP."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)'
    }
    
    # Intentar HTTPS primero
    try:
        resp = requests.get(
            f"https://{dominio}", 
            timeout=REQUEST_TIMEOUT, 
            headers=headers,
            allow_redirects=True,
            verify=True
        )
        return resp
    except Exception:
        pass
    
    # Intentar HTTP
    try:
        resp = requests.get(
            f"http://{dominio}", 
            timeout=REQUEST_TIMEOUT, 
            headers=headers,
            allow_redirects=True
        )
        return resp
    except Exception:
        return None


def evaluar_https(dominio: str) -> EstadoHTTPS:
    """Evalúa si el dominio fuerza HTTPS."""
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)'}
    
    # Verificar si HTTPS está disponible
    https_disponible = False
    try:
        resp = requests.get(
            f"https://{dominio}", 
            timeout=REQUEST_TIMEOUT, 
            headers=headers,
            allow_redirects=False,
            verify=True
        )
        https_disponible = True
    except Exception:
        pass
    
    if not https_disponible:
        return EstadoHTTPS.NO_DISPONIBLE
    
    # Verificar si HTTP redirige a HTTPS
    try:
        resp = requests.get(
            f"http://{dominio}", 
            timeout=REQUEST_TIMEOUT, 
            headers=headers,
            allow_redirects=True
        )
        if resp.url.startswith("https://"):
            return EstadoHTTPS.FORZADO
    except Exception:
        # Si HTTP falla pero HTTPS funciona, consideramos HTTPS forzado
        return EstadoHTTPS.FORZADO
    
    return EstadoHTTPS.DISPONIBLE


def detectar_servidor(headers: Dict) -> Optional[str]:
    """Detecta el servidor web."""
    server = headers.get('Server', '').lower()
    
    for patron, nombre in TECNOLOGIAS_SERVER.items():
        if re.search(patron, server, re.IGNORECASE):
            return nombre
    
    if server:
        return server.split('/')[0].title()
    return None


def detectar_tecnologia(headers: Dict) -> Optional[str]:
    """Detecta la tecnología/framework."""
    powered = headers.get('X-Powered-By', '').lower()
    
    for patron, nombre in TECNOLOGIAS_POWERED.items():
        if re.search(patron, powered, re.IGNORECASE):
            return nombre
    
    if powered:
        return powered.split('/')[0].title()
    return None


def detectar_cdn_waf(headers: Dict, dominio: str) -> Optional[str]:
    """Detecta CDN o WAF."""
    # Buscar en headers
    all_headers = ' '.join(str(v) for v in headers.values()).lower()
    server = headers.get('Server', '').lower()
    
    for patron, (nombre, tipo) in CDN_WAF_DETECTADOS.items():
        if re.search(patron, server, re.IGNORECASE):
            return f"{nombre} ({tipo})"
        if re.search(patron, all_headers, re.IGNORECASE):
            return f"{nombre} ({tipo})"
    
    # Headers específicos de CDN/WAF
    if 'cf-ray' in headers:
        return "Cloudflare (CDN/WAF)"
    if 'x-amz-cf-id' in headers:
        return "CloudFront (CDN)"
    if 'x-sucuri-id' in headers:
        return "Sucuri (WAF)"
    
    return None


def evaluar_header_hsts(headers: Dict) -> tuple[EstadoHeader, str]:
    """Evalúa Strict-Transport-Security."""
    hsts = headers.get('Strict-Transport-Security', '')
    
    if not hsts:
        return EstadoHeader.AUSENTE, ""
    
    # Verificar max-age mínimo recomendado (31536000 = 1 año)
    match = re.search(r'max-age=(\d+)', hsts)
    if match:
        max_age = int(match.group(1))
        if max_age < 31536000:
            return EstadoHeader.DEBIL, hsts
    
    return EstadoHeader.PRESENTE, hsts


def evaluar_header_csp(headers: Dict) -> tuple[EstadoHeader, str]:
    """Evalúa Content-Security-Policy."""
    csp = headers.get('Content-Security-Policy', '')
    
    if not csp:
        return EstadoHeader.AUSENTE, ""
    
    # CSP muy permisivo
    if "unsafe-inline" in csp and "unsafe-eval" in csp:
        return EstadoHeader.DEBIL, csp[:100] + "..." if len(csp) > 100 else csp
    
    return EstadoHeader.PRESENTE, csp[:100] + "..." if len(csp) > 100 else csp


def evaluar_header_simple(headers: Dict, nombre: str) -> EstadoHeader:
    """Evalúa presencia de un header simple."""
    return EstadoHeader.PRESENTE if headers.get(nombre) else EstadoHeader.AUSENTE


def analizar_headers_seguridad(headers: Dict) -> HeadersSeguridad:
    """Analiza todos los headers de seguridad."""
    hsts_estado, hsts_raw = evaluar_header_hsts(headers)
    csp_estado, csp_raw = evaluar_header_csp(headers)
    
    return HeadersSeguridad(
        hsts=hsts_estado,
        hsts_raw=hsts_raw,
        csp=csp_estado,
        csp_raw=csp_raw,
        x_frame_options=evaluar_header_simple(headers, 'X-Frame-Options'),
        x_content_type=evaluar_header_simple(headers, 'X-Content-Type-Options'),
        x_xss_protection=evaluar_header_simple(headers, 'X-XSS-Protection'),
        referrer_policy=evaluar_header_simple(headers, 'Referrer-Policy')
    )


def calcular_postura_general(
    https: EstadoHTTPS,
    headers: HeadersSeguridad,
    cdn_waf: Optional[str]
) -> PosturaGeneral:
    """Calcula la postura general del dominio."""
    puntos = 0
    
    # HTTPS
    if https == EstadoHTTPS.FORZADO:
        puntos += 2
    elif https == EstadoHTTPS.DISPONIBLE:
        puntos += 1
    
    # HSTS
    if headers.hsts == EstadoHeader.PRESENTE:
        puntos += 2
    elif headers.hsts == EstadoHeader.DEBIL:
        puntos += 1
    
    # CSP
    if headers.csp == EstadoHeader.PRESENTE:
        puntos += 2
    elif headers.csp == EstadoHeader.DEBIL:
        puntos += 1
    
    # Otros headers (1 punto cada uno)
    if headers.x_frame_options == EstadoHeader.PRESENTE:
        puntos += 1
    if headers.x_content_type == EstadoHeader.PRESENTE:
        puntos += 1
    if headers.referrer_policy == EstadoHeader.PRESENTE:
        puntos += 1
    
    # CDN/WAF
    if cdn_waf:
        puntos += 1
    
    # Clasificación
    if puntos >= 8:
        return PosturaGeneral.AVANZADA
    elif puntos >= 4:
        return PosturaGeneral.INTERMEDIA
    return PosturaGeneral.BASICA


# ============================================================================
# FUNCIÓN PRINCIPAL DE ANÁLISIS
# ============================================================================

def analizar_dominio(dominio: str) -> ResultadoAnalisis:
    """Analiza un dominio y retorna el resultado completo."""
    # Evaluar HTTPS
    estado_https = evaluar_https(dominio)
    
    # Hacer request para obtener headers
    resp = hacer_request(dominio)
    
    if not resp:
        return ResultadoAnalisis(
            dominio=dominio,
            https=estado_https,
            servidor=None,
            tecnologia=None,
            cdn_waf=None,
            headers=HeadersSeguridad(
                hsts=EstadoHeader.AUSENTE, hsts_raw="",
                csp=EstadoHeader.AUSENTE, csp_raw="",
                x_frame_options=EstadoHeader.AUSENTE,
                x_content_type=EstadoHeader.AUSENTE,
                x_xss_protection=EstadoHeader.AUSENTE,
                referrer_policy=EstadoHeader.AUSENTE
            ),
            postura=PosturaGeneral.BASICA,
            error="No se pudo conectar"
        )
    
    headers_dict = dict(resp.headers)
    
    # Detecciones
    servidor = detectar_servidor(headers_dict)
    tecnologia = detectar_tecnologia(headers_dict)
    cdn_waf = detectar_cdn_waf(headers_dict, dominio)
    
    # Headers de seguridad
    headers_seg = analizar_headers_seguridad(headers_dict)
    
    # Postura general
    postura = calcular_postura_general(estado_https, headers_seg, cdn_waf)
    
    return ResultadoAnalisis(
        dominio=dominio,
        https=estado_https,
        servidor=servidor,
        tecnologia=tecnologia,
        cdn_waf=cdn_waf,
        headers=headers_seg,
        postura=postura,
        error=None
    )


def resultado_a_dict_tecnico(resultado: ResultadoAnalisis) -> Dict:
    """Convierte resultado a diccionario para DataFrame técnico."""
    return {
        "Dominio": resultado.dominio,
        "HTTPS": resultado.https.value,
        "Servidor": resultado.servidor or "No detectado",
        "Tecnología": resultado.tecnologia or "No detectada",
        "CDN/WAF": resultado.cdn_waf or "No detectado",
        "HSTS": resultado.headers.hsts.value,
        "HSTS (Raw)": resultado.headers.hsts_raw or "N/A",
        "CSP": resultado.headers.csp.value,
        "CSP (Raw)": resultado.headers.csp_raw or "N/A",
        "X-Frame-Options": resultado.headers.x_frame_options.value,
        "X-Content-Type-Options": resultado.headers.x_content_type.value,
        "X-XSS-Protection": resultado.headers.x_xss_protection.value,
        "Referrer-Policy": resultado.headers.referrer_policy.value,
        "Postura General": resultado.postura.value,
        "Error": resultado.error or ""
    }


def resultado_a_dict_ejecutivo(resultado: ResultadoAnalisis) -> Dict:
    """Convierte resultado a diccionario para resumen ejecutivo."""
    return {
        "Dominio": resultado.dominio,
        "HTTPS": resultado.https.value,
        "Servidor": resultado.servidor or "-",
        "CDN/WAF": resultado.cdn_waf or "Sin protección",
        "HSTS": resultado.headers.hsts.value,
        "CSP": resultado.headers.csp.value,
        "Postura": resultado.postura.value
    }


# ============================================================================
# UTILIDADES
# ============================================================================

def validar_email(email: str) -> bool:
    """Valida formato básico de email."""
    if not isinstance(email, str):
        return False
    return bool(re.match(r'^[\w\.\-\+]+@[a-zA-Z\d\.\-]+\.[a-zA-Z]{2,}$', email))


def extraer_dominio(email: str) -> str:
    """Extrae el dominio de un email."""
    if validar_email(email):
        return email.split("@")[-1].lower().strip()
    return ""


def es_dominio_corporativo(dominio: str) -> bool:
    """Determina si un dominio es corporativo (no personal)."""
    return dominio and dominio not in DOMINIOS_PERSONALES


# ============================================================================
# INTERFAZ STREAMLIT
# ============================================================================

def main():
    st.title("🌐 Diagnóstico de Postura Web Corporativa")
    st.markdown("**v1** — Análisis de seguridad web de dominios corporativos")
    
    st.markdown("---")
    
    archivo = st.file_uploader(
        "📁 Sube tu archivo CSV con correos electrónicos", 
        type="csv",
        help="El archivo debe contener una columna con direcciones de correo electrónico"
    )
    
    if not archivo:
        st.info("👆 Sube un archivo CSV para comenzar el análisis")
        return
    
    try:
        # Cargar datos
        df = pd.read_csv(archivo).rename(columns=lambda x: x.strip())
        
        # Detectar columna de email
        email_cols = [col for col in df.columns if 'email' in col.lower() or 'correo' in col.lower()]
        if not email_cols:
            st.error("❌ No se encontró columna de correo electrónico (email/correo)")
            return
        
        col_email = email_cols[0]
        st.success(f"✅ Columna detectada: **{col_email}**")
        
        # Extraer dominios corporativos únicos
        df["_dominio"] = df[col_email].apply(extraer_dominio)
        dominios_corporativos = [
            d for d in df["_dominio"].dropna().unique() 
            if es_dominio_corporativo(d)
        ]
        
        total_emails = len(df)
        emails_personales = len(df[df["_dominio"].isin(DOMINIOS_PERSONALES)])
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Total de emails", total_emails)
        col2.metric("Emails personales", emails_personales)
        col3.metric("Dominios corporativos", len(dominios_corporativos))
        
        if not dominios_corporativos:
            st.warning("⚠️ No se encontraron dominios corporativos para analizar")
            return
        
        st.markdown("---")
        st.subheader("🔍 Análisis en progreso")
        
        progreso = st.progress(0)
        estado = st.empty()
        
        resultados: List[ResultadoAnalisis] = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futuros = {
                executor.submit(analizar_dominio, dom): dom 
                for dom in dominios_corporativos
            }
            
            for i, futuro in enumerate(concurrent.futures.as_completed(futuros)):
                dominio = futuros[futuro]
                try:
                    resultado = futuro.result()
                    resultados.append(resultado)
                except Exception as e:
                    st.warning(f"Error analizando {dominio}: {str(e)}")
                
                progreso.progress((i + 1) / len(dominios_corporativos))
                estado.text(f"Analizando: {dominio}")
        
        estado.text("✅ Análisis completado")
        
        # Crear DataFrames
        df_tecnico = pd.DataFrame([resultado_a_dict_tecnico(r) for r in resultados])
        df_ejecutivo = pd.DataFrame([resultado_a_dict_ejecutivo(r) for r in resultados])
        
        st.markdown("---")
        
        # Resumen ejecutivo
        st.subheader("📋 Resumen Ejecutivo")
        
        # Métricas de postura
        posturas = df_ejecutivo["Postura"].value_counts()
        col1, col2, col3 = st.columns(3)
        col1.metric("🟢 Avanzada", posturas.get("Avanzada", 0))
        col2.metric("🟡 Intermedia", posturas.get("Intermedia", 0))
        col3.metric("🔴 Básica", posturas.get("Básica", 0))
        
        # Métricas de HTTPS
        st.markdown("#### Estado HTTPS")
        https_counts = df_ejecutivo["HTTPS"].value_counts()
        col1, col2, col3 = st.columns(3)
        col1.metric("🔒 Forzado", https_counts.get("Forzado", 0))
        col2.metric("🔓 Disponible", https_counts.get("Disponible", 0))
        col3.metric("❌ No disponible", https_counts.get("No disponible", 0))
        
        st.dataframe(
            df_ejecutivo,
            use_container_width=True,
            hide_index=True
        )
        
        csv_ejecutivo = df_ejecutivo.to_csv(index=False).encode("utf-8")
        st.download_button(
            "📥 Descargar Resumen Ejecutivo",
            csv_ejecutivo,
            "resumen_ejecutivo_web.csv",
            "text/csv"
        )
        
        # Diagnóstico técnico
        st.markdown("---")
        st.subheader("🔧 Diagnóstico Técnico Completo")
        
        with st.expander("Ver diagnóstico técnico detallado"):
            st.dataframe(
                df_tecnico,
                use_container_width=True,
                hide_index=True
            )
        
        csv_tecnico = df_tecnico.to_csv(index=False).encode("utf-8")
        st.download_button(
            "📥 Descargar Diagnóstico Técnico",
            csv_tecnico,
            "diagnostico_tecnico_web.csv",
            "text/csv"
        )
        
    except Exception as e:
        st.error(f"❌ Error procesando archivo: {str(e)}")


if __name__ == "__main__":
    main()
