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
import io
import os
from functools import lru_cache
import plotly.express as px
import plotly.graph_objects as go

# Cache en Neon (opcional, funciona sin él)
import contextlib
try:
    from db_cache import (
        get_cached_dominios, save_to_cache, get_cache_stats,
        init_db, query_all_cached, get_single_domain
    )
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple
from enum import Enum
from datetime import datetime
from urllib.parse import urlparse

# ============================================================================
# CONFIGURACIÓN
# ============================================================================

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
    """Obtiene registros MX del dominio."""
    try:
        resp = dns.resolver.resolve(dominio, 'MX', lifetime=DNS_TIMEOUT)
        return [r.exchange.to_text().rstrip('.').lower() for r in resp]
    except dns.resolver.NXDOMAIN:
        return []  # Dominio no existe
    except dns.resolver.NoAnswer:
        return []  # Sin registros MX
    except dns.resolver.Timeout:
        return []  # Timeout
    except Exception:
        return []


@lru_cache(maxsize=1024)
def obtener_spf(dominio: str) -> str:
    """Obtiene registro SPF del dominio."""
    try:
        resp = dns.resolver.resolve(dominio, 'TXT', lifetime=DNS_TIMEOUT)
        for r in resp:
            txt = b''.join(r.strings).decode()
            if "v=spf1" in txt.lower():
                return txt
        return ""  # Hay TXT pero no SPF
    except dns.resolver.NXDOMAIN:
        return ""  # Dominio no existe
    except dns.resolver.NoAnswer:
        return ""  # Sin registros TXT
    except dns.resolver.Timeout:
        return ""  # Timeout
    except Exception:
        return ""


@lru_cache(maxsize=1024)
def obtener_dmarc(dominio: str) -> str:
    """Obtiene registro DMARC del dominio."""
    try:
        resp = dns.resolver.resolve(f"_dmarc.{dominio}", 'TXT', lifetime=DNS_TIMEOUT)
        for r in resp:
            txt = b''.join(r.strings).decode()
            if "v=dmarc1" in txt.lower():
                return txt
        return ""  # Registro existe pero no es DMARC válido
    except dns.resolver.NXDOMAIN:
        return ""  # No existe _dmarc.dominio
    except dns.resolver.NoAnswer:
        return ""  # Sin registros TXT
    except dns.resolver.Timeout:
        return ""  # Timeout
    except Exception:
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
                # Importante: si empezamos en http y redirige a https,
                # requests hereda verify. Dejamos verify=True para evitar
                # InsecureRequestWarning en redirects.
                verify=True,
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


def extraer_dominio(url_o_email: str) -> str:
    """Extrae el dominio de una URL o email."""
    if not isinstance(url_o_email, str):
        return ""
    
    url_o_email = url_o_email.strip().lower()
    
    # Si es email
    if "@" in url_o_email and validar_email(url_o_email):
        return url_o_email.split("@")[-1]
    
    # Si es URL
    if url_o_email.startswith(("http://", "https://")):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url_o_email)
            return parsed.netloc.replace("www.", "")
        except:
            pass
    
    # Si es dominio directo (ej: empresa.com)
    if "." in url_o_email and not " " in url_o_email:
        # Limpiar www. si existe
        dominio = url_o_email.replace("www.", "")
        # Limpiar trailing slash
        dominio = dominio.rstrip("/")
        return dominio
    
    return ""


def es_corporativo(dominio: str) -> bool:
    return dominio and dominio not in DOMINIOS_PERSONALES


# ============================================================================
# INTERFAZ STREAMLIT
# ============================================================================

# =============================
# Contrato df_resultados
# =============================

SINONIMOS = {
    "sin dmarc": "none",
    "basica": "básica",
    "avanzada": "avanzada",
    "sin cdn": "none",
    "microsoft": "microsoft 365",
    "cloudflare": "cloudflare",
}


def normalizar_busqueda(texto: str) -> str:
    texto = (texto or "").strip().lower()
    return SINONIMOS.get(texto, texto)


def _puntuar_columna_para_dominios(serie: pd.Series, max_muestra: int = 25) -> int:
    """Devuelve un puntaje basado en cuántos valores producen dominios corporativos."""
    if serie is None:
        return 0

    puntaje = 0
    vistos = set()
    for valor in serie.dropna().astype(str).head(max_muestra):
        d = extraer_dominio(valor)
        if d and es_corporativo(d) and d not in vistos:
            vistos.add(d)
            puntaje += 1
    return puntaje


def _detectar_columna_dominio(df: pd.DataFrame) -> Optional[str]:
    if df is None or df.empty or df.shape[1] == 0:
        return None

    columnas = list(df.columns)

    # 1) Prioridad por nombre (si existe)
    for preferida in ("dominio", "domain"):
        for c in columnas:
            if str(c).strip().lower() == preferida:
                return c

    # 2) Heurística por contenido: escoger la columna con más dominios corporativos
    mejor_col = None
    mejor_score = 0
    for c in columnas:
        score = _puntuar_columna_para_dominios(df[c])
        if score > mejor_score:
            mejor_score = score
            mejor_col = c

    if mejor_col and mejor_score >= 1:
        return mejor_col

    # 3) Fallback por keywords en el nombre
    keywords = ("email", "correo", "mail", "url", "website", "web", "site", "domain", "dominio")
    for c in columnas:
        name = str(c).strip().lower()
        if any(k in name for k in keywords):
            return c

    # 4) Último recurso: primera columna
    return columnas[0] if columnas else None


def ingesta_csv(archivo) -> List[str]:
    """Compat: preferir ingesta_archivo()."""
    return ingesta_archivo(archivo)


def _leer_tabla_desde_upload(archivo) -> pd.DataFrame:
    """Lee CSV/XLSX desde UploadedFile de Streamlit con heurísticas robustas."""
    nombre = getattr(archivo, "name", "") or ""
    ext = os.path.splitext(nombre)[1].lower()
    data = archivo.getvalue() if hasattr(archivo, "getvalue") else archivo.read()

    if ext == ".xlsx":
        # Requiere openpyxl
        return pd.read_excel(io.BytesIO(data), engine="openpyxl")

    # Default: CSV
    last_error: Optional[Exception] = None
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = data.decode(enc)
            try:
                return pd.read_csv(io.StringIO(text))
            except Exception:
                # Autodetecta separador (coma, punto y coma, tab, etc.)
                return pd.read_csv(io.StringIO(text), sep=None, engine="python")
        except Exception as e:
            last_error = e
            continue

    raise ValueError("No se pudo leer el archivo como CSV/XLSX") from last_error


def ingesta_archivo(archivo) -> List[str]:
    """Ingesta AUP-safe: acepta CSV/XLSX y devuelve SOLO dominios."""
    df = _leer_tabla_desde_upload(archivo)
    df = df.rename(columns=lambda x: str(x).strip())
    if df is None or df.empty:
        return []

    col = _detectar_columna_dominio(df)
    if not col:
        return []

    candidatos = df[col].astype(str)

    dominios = []
    for valor in candidatos:
        d = extraer_dominio(valor)
        if d and es_corporativo(d):
            dominios.append(d)

    # Únicos y orden estable
    vistos = set()
    salida = []
    for d in dominios:
        if d not in vistos:
            vistos.add(d)
            salida.append(d)
    return salida


@lru_cache(maxsize=512)
def obtener_fecha_creacion_dominio(dominio: str) -> Optional[datetime]:
    try:
        # python-whois puede imprimir errores de socket a stdout/stderr.
        # Silenciamos para no ensuciar logs/UI.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            w = whois.whois(dominio)
        created = w.creation_date
        if isinstance(created, list):
            created = min([d for d in created if isinstance(d, datetime)], default=None)
        if isinstance(created, datetime):
            return created
    except Exception:
        return None
    return None


def calcular_score_seguridad(row) -> int:
    """Calcula score de seguridad 0-100 basado en controles implementados."""
    score = 0
    
    # Identidad (50 puntos máx)
    if row.get("spf_estado") == "OK":
        score += 15
    elif row.get("spf_estado") == "Débil":
        score += 5
    
    if row.get("dmarc_estado") == "Reject":
        score += 25
    elif row.get("dmarc_estado") == "Quarantine":
        score += 15
    elif row.get("dmarc_estado") == "None":
        score += 5
    
    if row.get("correo_gateway") != "None":
        score += 10
    
    # Exposición (50 puntos máx)
    if row.get("https_estado") == "Forzado":
        score += 15
    elif row.get("https_estado") == "Parcial":
        score += 5
    
    if row.get("hsts"):
        score += 10
    
    if row.get("csp"):
        score += 10
    
    if row.get("cdn_waf") != "None":
        score += 15
    
    return min(score, 100)


def get_score_color(score: int) -> str:
    """Retorna color basado en el score."""
    if score >= 70:
        return "#4ECDC4"  # Verde
    elif score >= 40:
        return "#FFE66D"  # Amarillo
    return "#FF6B6B"  # Rojo


def get_score_emoji(score: int) -> str:
    """Retorna emoji basado en el score."""
    if score >= 70:
        return "🟢"
    elif score >= 40:
        return "🟡"
    return "🔴"


def map_correo_proveedor(vendor_correo: Optional[str]) -> str:
    if vendor_correo in ("Microsoft 365", "Google Workspace"):
        return vendor_correo
    return "Otro"


def map_correo_gateway(vendors_seguridad: List[str]) -> str:
    if not vendors_seguridad:
        return "None"
    # Contrato: solo Proofpoint | Mimecast | None
    if "Proofpoint" in vendors_seguridad:
        return "Proofpoint"
    if "Mimecast" in vendors_seguridad:
        return "Mimecast"
    return "None"


def map_correo_envio(vendors_envio: List[str]) -> str:
    if not vendors_envio:
        return "None"
    # Contrato: solo SendGrid | Mailgun | None
    if "SendGrid" in vendors_envio:
        return "SendGrid"
    if "Mailgun" in vendors_envio:
        return "Mailgun"
    return "None"


def map_spf_estado(estado: EstadoSPF) -> str:
    if estado == EstadoSPF.OK:
        return "OK"
    if estado == EstadoSPF.AUSENTE:
        return "Ausente"
    return "Error"


def map_dmarc_estado(estado: EstadoDMARC) -> str:
    if estado == EstadoDMARC.REJECT:
        return "Reject"
    if estado == EstadoDMARC.QUARANTINE:
        return "Quarantine"
    if estado == EstadoDMARC.NONE:
        return "None"
    return "Ausente"


def map_https_estado(estado: EstadoHTTPS) -> str:
    if estado == EstadoHTTPS.FORZADO:
        return "Forzado"
    if estado == EstadoHTTPS.DISPONIBLE:
        return "Parcial"
    return "Ausente"


def map_cdn_waf(valor: Optional[str]) -> str:
    if valor in ("Cloudflare", "Akamai"):
        return valor
    return "None"


def map_header_bool(estado: EstadoHeader) -> bool:
    return estado == EstadoHeader.PRESENTE


def resultado_a_df_resultados(r: ResultadoSuperficie) -> Dict:
    created = obtener_fecha_creacion_dominio(r.dominio)
    fecha = created.date().isoformat() if created else "N/D"

    row_data = {
        "dominio": r.dominio,
        "postura_identidad": r.identidad.postura.value,
        "postura_exposicion": r.exposicion.postura.value,
        "postura_general": r.postura_general.value,
        # Identidad (Correo)
        "correo_proveedor": map_correo_proveedor(r.identidad.vendor_correo),
        "correo_gateway": map_correo_gateway(r.identidad.vendors_seguridad),
        "correo_envio": map_correo_envio(r.identidad.vendors_envio),
        "spf_estado": map_spf_estado(r.identidad.estado_spf),
        "dmarc_estado": map_dmarc_estado(r.identidad.estado_dmarc),
        # Exposición (Web)
        "https_estado": map_https_estado(r.exposicion.https),
        "cdn_waf": map_cdn_waf(r.exposicion.cdn_waf),
        "hsts": map_header_bool(r.exposicion.hsts),
        "csp": map_header_bool(r.exposicion.csp),
        # Contexto
        "dominio_antiguedad": fecha,
    }
    # Calcular score
    row_data["score"] = calcular_score_seguridad(row_data)
    return row_data


DF_RESULT_COLUMNS = [
    "dominio",
    "score",
    "postura_identidad",
    "postura_exposicion",
    "postura_general",
    "correo_proveedor",
    "correo_gateway",
    "correo_envio",
    "spf_estado",
    "dmarc_estado",
    "https_estado",
    "cdn_waf",
    "hsts",
    "csp",
    "dominio_antiguedad",
]


def analizar_dominios(dominios: List[str]) -> pd.DataFrame:
    if not dominios:
        return pd.DataFrame(columns=DF_RESULT_COLUMNS)

    # 1) Intentar obtener del cache
    df_cached = pd.DataFrame(columns=DF_RESULT_COLUMNS)
    pendientes = list(dominios)

    if CACHE_AVAILABLE:
        try:
            df_cached, pendientes = get_cached_dominios(dominios)
            if not df_cached.empty:
                st.success(f"✅ {len(df_cached)} dominios desde cache (sin re-análisis)")
        except Exception:
            pass  # Continuar sin cache

    # 2) Analizar solo los pendientes
    df_nuevos = pd.DataFrame(columns=DF_RESULT_COLUMNS)
    if pendientes:
        if CACHE_AVAILABLE and not df_cached.empty:
            st.info(f"🔍 Analizando {len(pendientes)} dominios nuevos...")

        progreso = st.progress(0)
        estado = st.empty()
        total_pendientes = len(pendientes)
        completados = 0

        resultados: List[ResultadoSuperficie] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futuros = {executor.submit(analizar_dominio, d): d for d in pendientes}
            for futuro in concurrent.futures.as_completed(futuros):
                completados += 1
                dom = futuros[futuro]
                estado.text(f"Analizando: {dom} ({completados}/{total_pendientes})")
                progreso.progress(min(completados / max(total_pendientes, 1), 1.0))
                try:
                    resultados.append(futuro.result())
                except Exception as e:
                    st.warning(f"Fallo analizando {dom}: {e}")
                    continue

        estado.text("✅ Diagnóstico completado")
        progreso.progress(1.0)

        if resultados:
            df_nuevos = pd.DataFrame([resultado_a_df_resultados(r) for r in resultados])

            # 3) Guardar nuevos en cache
            if CACHE_AVAILABLE and not df_nuevos.empty:
                try:
                    save_to_cache(df_nuevos)
                except Exception:
                    pass  # No bloquear si falla el cache

    # 4) Combinar cached + nuevos
    df_resultados = pd.concat([df_cached, df_nuevos], ignore_index=True)
    if not df_resultados.empty:
        df_resultados = df_resultados.sort_values("dominio").reset_index(drop=True)
    return df_resultados


def generar_graficos_cache(df: pd.DataFrame):
    """Genera gráficos de valor para el dashboard de cache."""
    if df.empty:
        return

    # Colores consistentes para el branding
    COLORES_POSTURA = {
        "Básica": "#FF6B6B",      # Rojo - oportunidad alta
        "Intermedia": "#FFE66D",  # Amarillo
        "Avanzada": "#4ECDC4",    # Verde azulado
    }

    st.markdown("### 📊 Dashboard de Inteligencia")

    # --- Fila 1: Postura + Adopción de seguridad ---
    col1, col2 = st.columns(2)

    with col1:
        # Gráfico 1: Distribución de Postura (Donut)
        postura_counts = df["postura_general"].value_counts().reset_index()
        postura_counts.columns = ["Postura", "Cantidad"]

        fig_postura = px.pie(
            postura_counts,
            values="Cantidad",
            names="Postura",
            hole=0.5,
            color="Postura",
            color_discrete_map=COLORES_POSTURA,
            title="🎯 Distribución de Postura de Seguridad"
        )
        fig_postura.update_traces(textposition='inside', textinfo='percent+label')
        fig_postura.update_layout(
            showlegend=False,
            margin=dict(t=50, b=20, l=20, r=20),
            height=300
        )
        st.plotly_chart(fig_postura, use_container_width=True)

    with col2:
        # Gráfico 2: Adopción de controles de seguridad (barras horizontales)
        total = len(df)
        adopcion = {
            "SPF configurado": (df["spf_estado"] != "Ausente").sum(),
            "DMARC activo": (df["dmarc_estado"] != "Ausente").sum(),
            "HTTPS forzado": (df["https_estado"] == "Forzado").sum(),
            "HSTS activo": df["hsts"].sum() if "hsts" in df.columns else 0,
            "CDN/WAF": (df["cdn_waf"] != "None").sum(),
        }
        adopcion_df = pd.DataFrame([
            {"Control": k, "Porcentaje": v/total*100, "Cantidad": v}
            for k, v in adopcion.items()
        ])

        fig_adopcion = px.bar(
            adopcion_df,
            y="Control",
            x="Porcentaje",
            orientation="h",
            text=adopcion_df.apply(lambda r: f"{r['Porcentaje']:.0f}% ({int(r['Cantidad'])})", axis=1),
            title="🛡️ Adopción de Controles de Seguridad",
            color="Porcentaje",
            color_continuous_scale=["#FF6B6B", "#FFE66D", "#4ECDC4"],
        )
        fig_adopcion.update_traces(textposition="outside")
        fig_adopcion.update_layout(
            showlegend=False,
            coloraxis_showscale=False,
            margin=dict(t=50, b=20, l=20, r=20),
            height=300,
            xaxis_title="% de dominios",
            yaxis_title=""
        )
        st.plotly_chart(fig_adopcion, use_container_width=True)

    # --- Fila 2: Proveedores de Email + CDN/WAF ---
    col3, col4 = st.columns(2)

    with col3:
        # Gráfico 3: Proveedores de Email
        email_counts = df["correo_proveedor"].value_counts().head(8).reset_index()
        email_counts.columns = ["Proveedor", "Cantidad"]

        fig_email = px.bar(
            email_counts,
            x="Proveedor",
            y="Cantidad",
            title="📧 Proveedores de Email (Top 8)",
            color="Cantidad",
            color_continuous_scale="Blues",
            text="Cantidad"
        )
        fig_email.update_traces(textposition="outside")
        fig_email.update_layout(
            showlegend=False,
            coloraxis_showscale=False,
            margin=dict(t=50, b=20, l=20, r=20),
            height=300,
            xaxis_title="",
            yaxis_title="Dominios"
        )
        st.plotly_chart(fig_email, use_container_width=True)

    with col4:
        # Gráfico 4: CDN/WAF detectados
        waf_data = df[df["cdn_waf"] != "None"]["cdn_waf"].value_counts().reset_index()
        waf_data.columns = ["CDN/WAF", "Cantidad"]

        if not waf_data.empty:
            fig_waf = px.pie(
                waf_data,
                values="Cantidad",
                names="CDN/WAF",
                title="🛡️ CDN/WAF Detectados",
                color_discrete_sequence=px.colors.qualitative.Set2
            )
            fig_waf.update_traces(textposition='inside', textinfo='percent+label')
            fig_waf.update_layout(
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.3),
                margin=dict(t=50, b=60, l=20, r=20),
                height=300
            )
            st.plotly_chart(fig_waf, use_container_width=True)
        else:
            st.info("No se detectaron CDN/WAF en los dominios analizados")

    # --- Métricas de oportunidad comercial ---
    st.markdown("### 💼 Oportunidades Comerciales")
    opp_col1, opp_col2, opp_col3, opp_col4 = st.columns(4)

    basica_pct = (df["postura_general"] == "Básica").sum() / total * 100
    sin_dmarc_pct = (df["dmarc_estado"] != "Reject").sum() / total * 100
    sin_waf_pct = (df["cdn_waf"] == "None").sum() / total * 100
    sin_gateway_pct = (df["correo_gateway"] == "None").sum() / total * 100

    opp_col1.metric("🔥 Postura Básica", f"{basica_pct:.0f}%", help="Mayor potencial de venta")
    opp_col2.metric("⚠️ Sin DMARC", f"{sin_dmarc_pct:.0f}%", help="Vulnerables a spoofing")
    opp_col3.metric("🌐 Sin WAF", f"{sin_waf_pct:.0f}%", help="Sin protección web")
    opp_col4.metric("📧 Sin Gateway", f"{sin_gateway_pct:.0f}%", help="Sin filtrado de email")


def vista_global(df: pd.DataFrame):
    st.markdown("## 💼 Oportunidades Comerciales Identificadas")

    total = len(df)
    basica = int((df["postura_general"] == "Básica").sum())
    sin_gateway = int((df["correo_gateway"] == "None").sum())
    sin_waf = int((df["cdn_waf"] == "None").sum())
    avanzada = int((df["postura_general"] == "Avanzada").sum())
    sin_dmarc = int((df["dmarc_estado"] != "Reject").sum())
    
    # Score promedio si existe la columna
    score_promedio = df["score"].mean() if "score" in df.columns else 0
    score_emoji = get_score_emoji(int(score_promedio)) if score_promedio else "⚪"

    # Fila 1: Métricas principales con score
    with st.container():
        col0, col1, col2, col3, col4 = st.columns([1.2, 1, 1, 1, 1])
        col0.metric(f"{score_emoji} Score Promedio", f"{score_promedio:.0f}/100", help="Promedio de seguridad del portafolio")
        col1.metric("🎯 Total analizados", total)
        col2.metric("🔥 Postura básica", basica, help="Prospectos con mayor potencial")
        col3.metric("📧 Sin gateway email", sin_gateway, help="Oportunidad para seguridad de correo")
        col4.metric("🌐 Sin WAF/CDN", sin_waf, help="Oportunidad para protección web")

    # Alertas críticas
    criticos = df[df["score"] < 30] if "score" in df.columns else pd.DataFrame()
    if not criticos.empty:
        with st.expander(f"🚨 {len(criticos)} dominios CRÍTICOS (score < 30)", expanded=False):
            for _, row in criticos.iterrows():
                st.markdown(f"- **{row['dominio']}** - Score: {row['score']}/100 | DMARC: {row['dmarc_estado']} | WAF: {row['cdn_waf']}")

    with st.container():
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🟢 Postura avanzada", avanzada)
        col2.metric("⚠️ Sin DMARC enforce", sin_dmarc, help="Vulnerables a spoofing")
        col3.metric("📊 % Básica", f"{(basica/total*100):.0f}%" if total else "0%")
        col4.metric("📊 % Sin protección web", f"{(sin_waf/total*100):.0f}%" if total else "0%")


def aplicar_busqueda(df: pd.DataFrame, texto: str) -> pd.DataFrame:
    texto = normalizar_busqueda(texto)
    if not texto:
        return df

    return df[
        df.apply(
            lambda row: texto in " ".join(str(v).lower() for v in row.values),
            axis=1,
        )
    ]


def aplicar_filtros(df: pd.DataFrame) -> pd.DataFrame:
    """Aplica filtros solo si el usuario los activa en el expander."""
    with st.expander("🔧 Filtros (opcional)", expanded=False):
        col1, col2, col3 = st.columns(3)
        with col1:
            filtro_basica = st.checkbox("Solo postura básica")
        with col2:
            filtro_dmarc = st.checkbox("Sin DMARC activo")
        with col3:
            filtro_asimetria = st.checkbox("Asimetría correo / web")

    if filtro_basica:
        df = df[df.postura_general == "Básica"]
    if filtro_dmarc:
        df = df[df.dmarc_estado != "Reject"]
    if filtro_asimetria:
        df = df[df.postura_identidad != df.postura_exposicion]

    return df


def vista_lista_explorable(df: pd.DataFrame):
    st.subheader("🔎 Exploración de Dominios")

    # Primero mostrar cuántos hay en total
    st.caption(f"Total: {len(df)} dominios")

    # Búsqueda y filtros
    col_busq, col_orden = st.columns([3, 1])
    with col_busq:
        busqueda = st.text_input("Búsqueda inteligente", placeholder="Buscar por dominio, proveedor...")
    with col_orden:
        orden = st.selectbox("Ordenar por", ["Score ↑", "Score ↓", "Dominio A-Z"], label_visibility="collapsed")
    
    df_filtrado = aplicar_busqueda(df, busqueda)
    df_filtrado = aplicar_filtros(df_filtrado)
    
    # Aplicar ordenamiento
    if "score" in df_filtrado.columns:
        if orden == "Score ↑":
            df_filtrado = df_filtrado.sort_values("score", ascending=True)
        elif orden == "Score ↓":
            df_filtrado = df_filtrado.sort_values("score", ascending=False)
        else:
            df_filtrado = df_filtrado.sort_values("dominio")

    # Indicar si hay filtros activos
    if len(df_filtrado) < len(df):
        st.info(f"Mostrando {len(df_filtrado)} de {len(df)} dominios (filtros activos)")

    # Columnas a mostrar (con score si existe)
    cols_mostrar = ["dominio", "score", "postura_general", "correo_proveedor", "cdn_waf"] if "score" in df_filtrado.columns else ["dominio", "postura_general", "correo_proveedor", "cdn_waf"]
    
    st.dataframe(
        df_filtrado[cols_mostrar],
        width="stretch",
        hide_index=True,
        height=400,
        column_config={
            "dominio": st.column_config.TextColumn("Dominio", width="medium"),
            "score": st.column_config.ProgressColumn(
                "Score",
                help="Score de seguridad 0-100",
                format="%d",
                min_value=0,
                max_value=100,
            ),
            "postura_general": st.column_config.TextColumn("Postura", width="small"),
            "correo_proveedor": st.column_config.TextColumn("Email", width="small"),
            "cdn_waf": st.column_config.TextColumn("CDN/WAF", width="small"),
        }
    )

    if df_filtrado.empty:
        st.session_state.pop("dominio_activo", None)
        return

    # Selección para detalle o comparación
    st.markdown("---")
    col_sel, col_comp = st.columns([2, 1])
    
    with col_sel:
        dominio = st.selectbox(
            "Selecciona un dominio para ver detalle",
            df_filtrado["dominio"].tolist(),
        )
        st.session_state["dominio_activo"] = dominio
    
    with col_comp:
        comparar = st.multiselect(
            "Comparar dominios",
            df_filtrado["dominio"].tolist(),
            max_selections=3,
            help="Selecciona hasta 3 dominios para comparar"
        )
        if len(comparar) >= 2:
            st.session_state["dominios_comparar"] = comparar


def generar_recomendaciones_fila(row) -> List[str]:
    """Genera recomendaciones basadas en los valores del dominio."""
    recs: List[str] = []
    
    # Convertir a dict si es Series para acceso uniforme
    if hasattr(row, 'to_dict'):
        r = row.to_dict()
    else:
        r = dict(row) if not isinstance(row, dict) else row

    if r.get("dmarc_estado") != "Reject":
        recs.append("Activar DMARC en modo Quarantine/Reject para proteger la identidad del dominio.")
    if r.get("spf_estado") != "OK":
        recs.append("Corregir y endurecer SPF para reducir suplantación de remitentes.")
    if r.get("correo_gateway") == "None" or not r.get("correo_gateway"):
        recs.append("Evaluar un gateway de seguridad de correo (ej. Proofpoint/Mimecast).")

    if r.get("https_estado") != "Forzado":
        recs.append("Forzar HTTPS en todo el sitio para evitar downgrade y tráfico inseguro.")
    if not r.get("hsts"):
        recs.append("Habilitar HSTS para reforzar HTTPS.")
    if not r.get("csp"):
        recs.append("Implementar CSP para mitigar inyección de scripts.")
    if r.get("cdn_waf") == "None" or not r.get("cdn_waf"):
        recs.append("Considerar CDN/WAF (ej. Cloudflare/Akamai) para protección web.")

    return recs


def vista_comparativa(df: pd.DataFrame):
    """Muestra comparativa lado a lado de dominios seleccionados."""
    dominios = st.session_state.get("dominios_comparar", [])
    if len(dominios) < 2:
        return
    
    st.markdown("### 🔄 Comparativa de Dominios")
    
    cols = st.columns(len(dominios))
    for i, dom in enumerate(dominios):
        row = df[df["dominio"] == dom]
        if row.empty:
            continue
        row = row.iloc[0]
        
        with cols[i]:
            score = int(row["score"]) if "score" in df.columns and pd.notna(row["score"]) else 0
            emoji = get_score_emoji(score)
            st.markdown(f"#### {emoji} {dom}")
            st.metric("Score", f"{score}/100")
            
            # Gauge visual simple
            st.progress(score / 100)
            
            st.caption("**Identidad**")
            st.write(f"📧 {row['correo_proveedor']}")
            st.write(f"SPF: {'✅' if row['spf_estado'] == 'OK' else '❌'}")
            st.write(f"DMARC: {'✅' if row['dmarc_estado'] == 'Reject' else '⚠️' if row['dmarc_estado'] == 'Quarantine' else '❌'}")
            
            st.caption("**Exposición**")
            st.write(f"HTTPS: {'✅' if row['https_estado'] == 'Forzado' else '❌'}")
            st.write(f"CDN/WAF: {row['cdn_waf'] if row['cdn_waf'] != 'None' else '❌'}")
    
    st.markdown("---")


def vista_dominio(df: pd.DataFrame):
    # Primero mostrar comparativa si hay dominios seleccionados
    vista_comparativa(df)
    
    dominio = st.session_state.get("dominio_activo")
    if not dominio:
        return

    row = df[df["dominio"] == dominio]
    if row.empty:
        return
    row = row.iloc[0]
    
    # Encabezado con score visual
    score = int(row["score"]) if "score" in df.columns and pd.notna(row["score"]) else calcular_score_seguridad(row.to_dict())
    emoji = get_score_emoji(score)
    
    st.markdown(f"### {emoji} Detalle: **{dominio}**")
    
    # Score gauge prominente
    col_score, col_info = st.columns([1, 3])
    with col_score:
        st.metric("Score de Seguridad", f"{score}/100")
        st.progress(score / 100)
        if score < 30:
            st.error("⚠️ Riesgo crítico")
        elif score < 50:
            st.warning("⚡ Necesita atención")
        else:
            st.success("✅ Postura aceptable")
    
    with col_info:
        st.markdown(f"""
        | Aspecto | Valor |
        |---------|-------|
        | **Postura General** | {row['postura_general']} |
        | **Antigüedad** | {row['dominio_antiguedad']} |
        """)

    # Detalles en dos columnas
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### ✉️ Identidad Digital (Correo)")
        st.write(f"**Proveedor:** {row['correo_proveedor']}")
        st.write(f"**SPF:** {'✅ ' + str(row['spf_estado']) if row['spf_estado'] == 'OK' else '❌ ' + str(row['spf_estado'])}")
        st.write(f"**DMARC:** {'✅ ' if row['dmarc_estado'] == 'Reject' else '⚠️ ' if row['dmarc_estado'] == 'Quarantine' else '❌ '}{row['dmarc_estado']}")
        st.write(f"**Gateway:** {row['correo_gateway'] if row['correo_gateway'] != 'None' else '❌ Sin gateway'}")
        st.write(f"**Envío:** {row['correo_envio'] if row['correo_envio'] != 'None' else '—'}")

    with col2:
        st.markdown("#### 🌐 Exposición Digital (Web)")
        st.write(f"**HTTPS:** {'✅ ' if row['https_estado'] == 'Forzado' else '⚠️ ' if row['https_estado'] == 'Parcial' else '❌ '}{row['https_estado']}")
        st.write(f"**CDN/WAF:** {row['cdn_waf'] if row['cdn_waf'] != 'None' else '❌ Sin protección'}")
        st.write(f"**HSTS:** {'✅ Activo' if row['hsts'] else '❌ Ausente'}")
        st.write(f"**CSP:** {'✅ Activo' if row['csp'] else '❌ Ausente'}")

    # Recomendaciones
    recs = generar_recomendaciones_fila(row)
    if recs:
        st.markdown("#### 📋 Recomendaciones de Mejora")
        for i, r in enumerate(recs, 1):
            st.write(f"{i}. {r}")


def main():
    st.set_page_config(layout="wide", page_title="ProspectScan - Diagnóstico de Seguridad")
    st.title("🧠 ProspectScan - Diagnóstico de Superficie Digital")

    # Tabs: Análisis masivo vs Consulta rápida vs Pipeline Cruce
    tab1, tab2, tab3, tab4 = st.tabs(["📁 Cargar archivo", "🔍 Dominio único", "📊 Reportes (cache)", "🎯 Pipeline Cruce"])

    with tab1:
        # Quick Start cuando no hay archivo
        archivo = st.file_uploader("Sube archivo CSV o Excel", type=["csv", "xlsx"])
        
        if not archivo:
            st.markdown("---")
            col_intro, col_stats = st.columns([2, 1])
            
            with col_intro:
                st.markdown("""
                ### 🚀 Quick Start
                
                **¿Qué analiza ProspectScan?**
                - ✉️ **Identidad Digital:** SPF, DMARC, proveedor de email, gateways de seguridad
                - 🌐 **Exposición Web:** HTTPS, HSTS, CSP, CDN/WAF
                - 📊 **Score 0-100:** Puntuación objetiva de postura de seguridad
                
                **Formato del archivo:**
                - CSV o Excel (.xlsx)
                - Una columna con dominios o emails corporativos
                - Se extraen automáticamente los dominios únicos
                
                **Ejemplo de contenido:**
                ```
                dominio
                empresa1.com
                contacto@empresa2.mx
                https://www.empresa3.com/pagina
                ```
                """)
            
            with col_stats:
                if CACHE_AVAILABLE:
                    stats = get_cache_stats()
                    if stats.get("connected"):
                        st.markdown("### 📦 Tu Base de Datos")
                        st.metric("Dominios en cache", stats.get("total", 0))
                        st.metric("Listos para reportes", stats.get("fresh", 0))
                        st.caption("Ve a la pestaña **Reportes** para explorar")
                    else:
                        st.info("💡 Conecta Neon DB para persistir análisis")
                else:
                    st.info("💡 Configura DATABASE_URL para guardar análisis")
            
            # NO hacer return aquí - los otros tabs deben renderizarse
        
        elif archivo:
            # Evitar re-análisis en cada rerun: verificar si el archivo cambió
            archivo_id = f"{archivo.name}_{archivo.size}"
            
            if st.session_state.get("archivo_id_last") == archivo_id and isinstance(
                st.session_state.get("df_resultados_last"), pd.DataFrame
            ):
                # Reutilizar resultado anterior
                df_resultados = st.session_state["df_resultados_last"]
            else:
                # Archivo nuevo: procesar
                try:
                    dominios = ingesta_archivo(archivo)
                except Exception as e:
                    st.error("No se pudo leer el archivo. Verifica formato y contenido.")
                    st.caption(f"Detalle: {e}")
                    return
                df_resultados = analizar_dominios(dominios)

                # Guardar en session_state
                st.session_state["archivo_id_last"] = archivo_id
                st.session_state["df_resultados_last"] = df_resultados

            if df_resultados.empty:
                st.warning("No se pudieron analizar dominios válidos desde el CSV")
                return

            vista_global(df_resultados)
            vista_lista_explorable(df_resultados)
            vista_dominio(df_resultados)
        else:
            st.info("Carga un archivo para iniciar el diagnóstico")
            # Limpiar estado si se quitó el archivo
            st.session_state.pop("archivo_id_last", None)
            st.session_state.pop("df_resultados_last", None)

    with tab2:
        st.markdown("### 🔍 Consulta un dominio específico")
        
        col_input, col_btn = st.columns([3, 1])
        with col_input:
            dominio_input = st.text_input(
                "Dominio corporativo",
                placeholder="empresa.com o contacto@empresa.com",
                key="single_domain",
                label_visibility="collapsed"
            )
        with col_btn:
            analizar_btn = st.button("🔎 Analizar", type="primary", use_container_width=True)

        if not dominio_input:
            st.caption("Ingresa un dominio corporativo y presiona **Analizar**")
        else:
            dominio_limpio = extraer_dominio(dominio_input)
            if not dominio_limpio:
                st.error("❌ Dominio no válido. Ingresa un dominio como: empresa.com")
            elif not es_corporativo(dominio_limpio):
                st.warning("⚠️ Ese es un dominio personal (Gmail, Hotmail, etc.). Ingresa un dominio corporativo.")
            else:
                # Verificar si ya tenemos resultados para este dominio
                tiene_cache = (
                    st.session_state.get("single_domain_last") == dominio_limpio
                    and isinstance(st.session_state.get("single_domain_df"), pd.DataFrame)
                    and not st.session_state["single_domain_df"].empty
                )
                
                df_single = pd.DataFrame()
                
                if tiene_cache:
                    # Reutilizar resultado anterior
                    df_single = st.session_state["single_domain_df"]
                elif analizar_btn:
                    # Usuario presionó el botón: buscar/analizar
                    
                    # 0) Cache local (si ya venía en el dataframe actual de sesión)
                    df_local = st.session_state.get("df_resultados_last")
                    if isinstance(df_local, pd.DataFrame) and not df_local.empty:
                        hit = df_local[df_local["dominio"] == dominio_limpio]
                        if not hit.empty:
                            st.success("✅ Resultado desde cache local (sin re-análisis)")
                            df_single = hit.reset_index(drop=True)

                    # 1) Cache Neon (si está configurado)
                    if df_single.empty and CACHE_AVAILABLE:
                        row_cached = get_single_domain(dominio_limpio)
                        if row_cached is not None:
                            st.success("✅ Resultado desde cache Neon (sin re-análisis)")
                            df_single = pd.DataFrame([row_cached])

                    # 2) Re-análisis solo si no hay cache
                    if df_single.empty:
                        with st.spinner(f"🔍 Analizando {dominio_limpio}..."):
                            df_single = analizar_dominios([dominio_limpio])

                    # Persistir en sesión para evitar reruns costosos
                    if isinstance(df_single, pd.DataFrame) and not df_single.empty:
                        st.session_state["single_domain_last"] = dominio_limpio
                        st.session_state["single_domain_df"] = df_single
                
                # Mostrar resultados si los hay (de cache o recién analizados)
                if not df_single.empty:
                    row = df_single.iloc[0]
                    
                    # Score visual prominente
                    score = int(row["score"]) if "score" in df_single.columns and pd.notna(row["score"]) else calcular_score_seguridad(row.to_dict())
                    emoji = get_score_emoji(score)
                    
                    st.markdown(f"### {emoji} **{dominio_limpio}**")
                    
                    # Encabezado con score gauge
                    col_score, col_postura = st.columns([1, 2])
                    with col_score:
                        st.metric("Score de Seguridad", f"{score}/100")
                        st.progress(score / 100)
                        if score < 30:
                            st.error("⚠️ Riesgo crítico")
                        elif score < 50:
                            st.warning("⚡ Necesita atención")
                        elif score < 70:
                            st.info("📊 Postura intermedia")
                        else:
                            st.success("✅ Buena postura")
                    
                    with col_postura:
                        st.metric("Postura General", row["postura_general"])
                        st.caption(f"Identidad: {row['postura_identidad']} | Exposición: {row['postura_exposicion']}")

                    st.markdown("---")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("#### ✉️ Identidad (Correo)")
                        st.write(f"**Proveedor:** {row['correo_proveedor']}")
                        st.write(f"**SPF:** {'✅ ' if row['spf_estado'] == 'OK' else '❌ '}{row['spf_estado']}")
                        st.write(f"**DMARC:** {'✅ ' if row['dmarc_estado'] == 'Reject' else '⚠️ ' if row['dmarc_estado'] == 'Quarantine' else '❌ '}{row['dmarc_estado']}")
                        st.write(f"**Gateway:** {row['correo_gateway'] if row['correo_gateway'] != 'None' else '❌ Sin gateway'}")

                    with col2:
                        st.markdown("#### 🌐 Exposición (Web)")
                        st.write(f"**HTTPS:** {'✅ ' if row['https_estado'] == 'Forzado' else '❌ '}{row['https_estado']}")
                        st.write(f"**CDN/WAF:** {row['cdn_waf'] if row['cdn_waf'] != 'None' else '❌ Sin protección'}")
                        st.write(f"**HSTS:** {'✅ Activo' if row['hsts'] else '❌ Ausente'}")
                        st.write(f"**CSP:** {'✅ Activo' if row['csp'] else '❌ Ausente'}")

                    # Recomendaciones
                    recs = generar_recomendaciones_fila(row)
                    if recs:
                        st.markdown("#### 📋 Recomendaciones")
                        for i, r in enumerate(recs, 1):
                            st.write(f"{i}. {r}")
                elif analizar_btn:
                    # Se presionó analizar pero no hay resultados
                    st.error("No se pudo analizar el dominio")
                else:
                    # No hay cache y no se presionó el botón
                    st.info("💡 Presiona **Analizar** para consultar este dominio")

    with tab3:
        if not CACHE_AVAILABLE:
            st.warning("Cache no disponible. Configura DATABASE_URL en secrets.")
        else:
            stats = get_cache_stats()
            if stats.get("connected"):
                st.markdown("### 📈 Estado del Cache")
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("📦 Total en cache", stats.get("total", 0))
                col2.metric("✅ Frescos (< 7 días)", stats.get("fresh", 0))
                col3.metric("⏰ Vencidos", stats.get("stale", 0))
                col4.metric("💾 Tasa de hit", f"{stats.get('fresh', 0) / max(stats.get('total', 1), 1) * 100:.0f}%")

                st.markdown("---")

                # Filtro y carga
                filtro_postura = st.selectbox(
                    "Filtrar por postura",
                    ["Todos", "Básica", "Intermedia", "Avanzada"],
                    key="tab3_filtro_postura"
                )
                
                filtros = {}
                if filtro_postura != "Todos":
                    filtros["postura_general"] = filtro_postura

                cargar_cache = st.button("🔄 Cargar datos del cache", type="primary", key="btn_cargar_cache")

                # Guardar en session_state para persistir después del rerun
                if cargar_cache:
                    with st.spinner("Cargando datos del cache..."):
                        df_cache = query_all_cached(filtros if filtros else None)
                        st.session_state["df_cache_tab3"] = df_cache
                        st.session_state["cache_loaded"] = True

                # Mostrar si hay datos cargados
                if st.session_state.get("cache_loaded") and "df_cache_tab3" in st.session_state:
                    df_cache = st.session_state["df_cache_tab3"]
                    
                    if df_cache.empty:
                        st.info("No hay dominios en cache con esos filtros")
                    else:
                        st.success(f"✅ {len(df_cache)} dominios cargados desde cache")

                        # 📊 GRÁFICOS DE VALOR
                        generar_graficos_cache(df_cache)

                        st.markdown("---")
                        st.markdown("### 📋 Datos Detallados")

                        # Tabla con datos
                        st.dataframe(
                            df_cache[[
                                "dominio", "postura_general", "correo_proveedor",
                                "dmarc_estado", "cdn_waf", "https_estado"
                            ]],
                            width="stretch",
                            height=400,
                            hide_index=True,
                            column_config={
                                "dominio": st.column_config.TextColumn("Dominio", width="medium"),
                                "postura_general": st.column_config.TextColumn("Postura", width="small"),
                                "correo_proveedor": st.column_config.TextColumn("Email", width="small"),
                                "dmarc_estado": st.column_config.TextColumn("DMARC", width="small"),
                                "cdn_waf": st.column_config.TextColumn("CDN/WAF", width="small"),
                                "https_estado": st.column_config.TextColumn("HTTPS", width="small"),
                            }
                        )

                        # Exportar
                        csv = df_cache.to_csv(index=False).encode("utf-8")
                        st.download_button(
                            "📥 Exportar reporte completo (CSV)",
                            csv,
                            f"prospectscan_reporte_{datetime.now().strftime('%Y%m%d')}.csv",
                            "text/csv"
                        )
            else:
                st.error("No se pudo conectar a la base de datos")
                if stats.get("error"):
                    st.caption(f"Error: {stats.get('error')}")
    
    # Tab 4: Pipeline de Cruce Semántico
    with tab4:
        st.markdown("### 🎯 Pipeline de Cruce Semántico (Capas 1-4)")
        st.markdown("**Integración:** Ingesta ZoomInfo → Contexto Empresarial → Cruce con Postura → Priorización")
        
        # Upload de archivo ZoomInfo
        st.markdown("#### 📤 Paso 1: Cargar archivo ZoomInfo")
        zoominfo_file = st.file_uploader("Sube reporte Excel de ZoomInfo", type=["xlsx", "xls"], key="zoominfo_upload")
        
        if zoominfo_file:
            try:
                # Lectura robusta: una sola vez sin headers
                df_raw = pd.read_excel(zoominfo_file, header=None)
                
                # Buscar fila que contiene headers (Website, Domain, etc.)
                header_row = 0
                keywords = ['website', 'domain', 'company name', 'company']
                
                for idx, row in df_raw.head(20).iterrows():  # Solo buscar en primeras 20 filas
                    row_str = ' '.join([str(v).lower() for v in row.values if pd.notna(v)])
                    if any(kw in row_str for kw in keywords):
                        header_row = idx
                        break
                
                # Usar la fila encontrada como headers y eliminar filas anteriores
                if header_row > 0:
                    df_zoom = df_raw.iloc[header_row:].reset_index(drop=True)
                    df_zoom.columns = df_zoom.iloc[0]  # Primera fila son los headers
                    df_zoom = df_zoom.iloc[1:].reset_index(drop=True)  # Eliminar fila de headers
                    st.success(f"✅ Headers en fila {header_row + 1}. Total: {len(df_zoom)} empresas")
                else:
                    df_zoom = df_raw.copy()
                    df_zoom.columns = df_zoom.iloc[0]
                    df_zoom = df_zoom.iloc[1:].reset_index(drop=True)
                    st.info(f"📄 Headers en fila 1. Total: {len(df_zoom)} empresas")
                
                # Limpiar nombres de columnas
                df_zoom.columns = [str(col).strip() if pd.notna(col) else f'col_{i}' 
                                   for i, col in enumerate(df_zoom.columns)]
                
                with st.expander("👀 Vista previa de datos", expanded=False):
                    st.write(f"**Columnas:** {list(df_zoom.columns)}")
                    st.dataframe(df_zoom.head(10))
                
                # Buscar columna de dominios (case-insensitive)
                dominios_col = None
                columnas_lower = {str(col).lower().strip(): col for col in df_zoom.columns}
                
                for buscar in ['website', 'domain', 'company website', 'url', 'site']:
                    if buscar in columnas_lower:
                        dominios_col = columnas_lower[buscar]
                        st.success(f"✅ Columna de dominios: **{dominios_col}**")
                        break
                
                if dominios_col:
                    dominios_zoom = df_zoom[dominios_col].dropna().unique().tolist()
                    dominios_zoom = [extraer_dominio(str(d)) for d in dominios_zoom if d]
                    dominios_zoom = [d for d in dominios_zoom if d and d not in DOMINIOS_PERSONALES]
                    
                    st.info(f"📧 Se extrajeron **{len(dominios_zoom)} dominios** únicos")
                    
                    if st.button("▶️ Ejecutar Análisis de Postura", type="primary"):
                        with st.spinner("Analizando superficie digital de los dominios..."):
                            resultados_df = None
                            
                            # Análisis masivo con caché
                            if CACHE_AVAILABLE:
                                df_cached, dominios_pendientes = get_cached_dominios(dominios_zoom)
                                
                                if not df_cached.empty:
                                    st.info(f"📦 {len(df_cached)} dominios en caché")
                                
                                if dominios_pendientes:
                                    st.info(f"🔍 Analizando {len(dominios_pendientes)} dominios nuevos...")
                                    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                                        nuevos = list(executor.map(analizar_dominio, dominios_pendientes))
                                    nuevos = [r for r in nuevos if r]
                                    
                                    if nuevos:
                                        df_nuevos = pd.DataFrame([r.__dict__ for r in nuevos])
                                        # Guardar en caché
                                        save_to_cache(df_nuevos)
                                        
                                        # Combinar con caché
                                        if not df_cached.empty:
                                            resultados_df = pd.concat([df_cached, df_nuevos], ignore_index=True)
                                        else:
                                            resultados_df = df_nuevos
                                    else:
                                        resultados_df = df_cached if not df_cached.empty else None
                                else:
                                    resultados_df = df_cached if not df_cached.empty else None
                            else:
                                # Sin caché - analizar todo
                                st.info(f"🔍 Analizando {len(dominios_zoom)} dominios...")
                                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                                    resultados = list(executor.map(analizar_dominio, dominios_zoom))
                                resultados = [r for r in resultados if r]
                                if resultados:
                                    resultados_df = pd.DataFrame([r.__dict__ for r in resultados])
                            
                            if resultados_df is not None and not resultados_df.empty:
                                st.session_state["pipeline_results"] = resultados_df
                                st.success(f"✅ Análisis completado: {len(resultados_df)} dominios")
                            else:
                                st.error("No se pudieron analizar los dominios")
                
                else:
                    st.warning("⚠️ No se encontró columna de dominios. Columnas disponibles:")
                    st.write(df_zoom.columns.tolist())
                    st.info("Renombra la columna a 'Website' o 'Domain' en tu Excel")
                    
            except Exception as e:
                st.error(f"Error al procesar archivo: {e}")
        
        # Mostrar resultados si existen
        if "pipeline_results" in st.session_state:
            df_res = st.session_state["pipeline_results"]
            st.markdown("---")
            st.markdown("#### 📊 Resultados del Análisis")
            
            # Detectar nombre de columna de score (varía entre caché y análisis nuevo)
            score_col = 'score' if 'score' in df_res.columns else 'score_final'
            hsts_col = 'hsts' if 'hsts' in df_res.columns else 'hsts_presente'
            provider_col = 'correo_proveedor' if 'correo_proveedor' in df_res.columns else 'email_provider'
            
            # Métricas globales
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Dominios analizados", len(df_res))
            with col2:
                if score_col in df_res.columns:
                    score_promedio = df_res[score_col].mean()
                    st.metric("Score Promedio", f"{score_promedio:.1f}/100")
                else:
                    st.metric("Score Promedio", "N/A")
            with col3:
                if 'dmarc_estado' in df_res.columns:
                    con_dmarc = len(df_res[df_res['dmarc_estado'] != 'Ausente'])
                    st.metric("Con DMARC", f"{con_dmarc} ({con_dmarc/len(df_res)*100:.0f}%)")
                else:
                    st.metric("Con DMARC", "N/A")
            with col4:
                if hsts_col in df_res.columns:
                    # Manejar tanto bool como string
                    hsts_values = df_res[hsts_col]
                    if hsts_values.dtype == bool:
                        con_hsts = hsts_values.sum()
                    else:
                        con_hsts = len(df_res[df_res[hsts_col].isin([True, 'True', 'Sí', 'Yes', 1, '1'])])
                    st.metric("Con HSTS", f"{con_hsts} ({con_hsts/len(df_res)*100:.0f}%)")
                else:
                    st.metric("Con HSTS", "N/A")
            
            # Vista global
            vista_global(df_res)
            
            # Tabla detallada - seleccionar columnas disponibles
            cols_mostrar = ['dominio']
            for col in [score_col, provider_col, 'dmarc_estado', hsts_col, 'cdn_waf']:
                if col in df_res.columns:
                    cols_mostrar.append(col)
            
            st.markdown("### 🗂️ Detalle por Dominio")
            st.dataframe(
                df_res[cols_mostrar],
                use_container_width=True,
                height=400
            )
            
            # Exportar
            csv = df_res.to_csv(index=False)
            st.download_button(
                "📥 Exportar resultados (CSV)",
                csv,
                f"pipeline_cruce_{datetime.now().strftime('%Y%m%d')}.csv",
                "text/csv"
            )


if __name__ == "__main__":
    main()
