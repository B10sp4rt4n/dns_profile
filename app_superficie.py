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
    return "None"


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

    return {
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


DF_RESULT_COLUMNS = [
    "dominio",
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


def vista_global(df: pd.DataFrame):
    st.markdown("## 💼 Oportunidades Comerciales Identificadas")

    total = len(df)
    basica = int((df.postura_general == "Básica").sum())
    sin_gateway = int((df.correo_gateway == "None").sum())
    sin_waf = int((df.cdn_waf == "None").sum())
    avanzada = int((df.postura_general == "Avanzada").sum())
    sin_dmarc = int((df.dmarc_estado != "Reject").sum())

    with st.container():
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🎯 Total analizados", total)
        col2.metric("🔥 Postura básica", basica, help="Prospectos con mayor potencial")
        col3.metric("📧 Sin gateway email", sin_gateway, help="Oportunidad para seguridad de correo")
        col4.metric("🌐 Sin WAF/CDN", sin_waf, help="Oportunidad para protección web")

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
    if st.checkbox("Solo postura básica"):
        df = df[df.postura_general == "Básica"]

    if st.checkbox("Sin DMARC activo"):
        df = df[df.dmarc_estado != "Reject"]

    if st.checkbox("Asimetría correo / web"):
        df = df[df.postura_identidad != df.postura_exposicion]

    return df


def vista_lista_explorable(df: pd.DataFrame):
    st.subheader("🔎 Exploración de Dominios")

    busqueda = st.text_input("Búsqueda inteligente")
    df_filtrado = aplicar_busqueda(df, busqueda)
    df_filtrado = aplicar_filtros(df_filtrado)

    st.dataframe(
        df_filtrado[["dominio", "postura_general", "correo_proveedor", "cdn_waf"]],
        use_container_width=True,
        hide_index=True,
        height=400,
    )

    if df_filtrado.empty:
        st.session_state.pop("dominio_activo", None)
        return

    dominio = st.selectbox(
        "Selecciona un dominio para ver detalle",
        df_filtrado["dominio"].tolist(),
    )

    st.session_state["dominio_activo"] = dominio


def generar_recomendaciones_fila(row: pd.Series) -> List[str]:
    recs: List[str] = []

    if row.get("dmarc_estado") != "Reject":
        recs.append("Activar DMARC en modo Quarantine/Reject para proteger la identidad del dominio.")
    if row.get("spf_estado") != "OK":
        recs.append("Corregir y endurecer SPF para reducir suplantación de remitentes.")
    if row.get("correo_gateway") == "None":
        recs.append("Evaluar un gateway de seguridad de correo (ej. Proofpoint/Mimecast).")

    if row.get("https_estado") != "Forzado":
        recs.append("Forzar HTTPS en todo el sitio para evitar downgrade y tráfico inseguro.")
    if not bool(row.get("hsts")):
        recs.append("Habilitar HSTS para reforzar HTTPS.")
    if not bool(row.get("csp")):
        recs.append("Implementar CSP para mitigar inyección de scripts.")
    if row.get("cdn_waf") == "None":
        recs.append("Considerar CDN/WAF (ej. Cloudflare/Akamai) para protección web.")

    return recs


def vista_dominio(df: pd.DataFrame):
    dominio = st.session_state.get("dominio_activo")
    if not dominio:
        return

    row = df[df.dominio == dominio].iloc[0]
    st.subheader(f"📌 Dominio: {dominio}")

    st.markdown("### ✉️ Identidad Digital (Correo)")
    st.write(row.correo_proveedor, row.spf_estado, row.dmarc_estado)

    st.markdown("### 🌐 Exposición Digital (Web)")
    st.write(row.https_estado, row.cdn_waf)

    st.markdown("### ✅ Recomendaciones")
    for r in generar_recomendaciones_fila(row):
        st.write(f"- {r}")


def main():
    st.set_page_config(layout="wide")
    st.title("🧠 Diagnóstico de Superficie Digital Corporativa")

    # Tabs: Análisis masivo vs Consulta rápida
    tab1, tab2, tab3 = st.tabs(["📁 Cargar archivo", "🔍 Dominio único", "📊 Reportes (cache)"])

    with tab1:
        archivo = st.file_uploader("Sube archivo CSV o Excel", type=["csv", "xlsx"])
        if archivo:
            try:
                dominios = ingesta_archivo(archivo)
            except Exception as e:
                st.error("No se pudo leer el archivo. Verifica formato y contenido.")
                st.caption(f"Detalle: {e}")
                return
            df_resultados = analizar_dominios(dominios)

            if df_resultados.empty:
                st.warning("No se pudieron analizar dominios válidos desde el CSV")
                return

            vista_global(df_resultados)
            vista_lista_explorable(df_resultados)
            vista_dominio(df_resultados)
        else:
            st.info("Carga un archivo para iniciar el diagnóstico")

    with tab2:
        st.markdown("### Consulta un dominio específico")
        dominio_input = st.text_input("Dominio (ej: empresa.com)", key="single_domain")

        if dominio_input:
            dominio_limpio = extraer_dominio(dominio_input)
            if not dominio_limpio:
                st.error("Dominio no válido")
            elif not es_corporativo(dominio_limpio):
                st.warning("Ese es un dominio personal (Gmail, Hotmail, etc.)")
            else:
                # Evitar re-análisis en cada rerun: si el dominio no cambió, reutiliza.
                if (
                    st.session_state.get("single_domain_last") == dominio_limpio
                    and isinstance(st.session_state.get("single_domain_df"), pd.DataFrame)
                    and not st.session_state["single_domain_df"].empty
                ):
                    df_single = st.session_state["single_domain_df"]
                else:
                    df_single = pd.DataFrame()

                    # 0) Cache local (si ya venía en el dataframe actual de sesión)
                    df_local = st.session_state.get("df_resultados_last")
                    if isinstance(df_local, pd.DataFrame) and not df_local.empty:
                        hit = df_local[df_local["dominio"] == dominio_limpio]
                        if not hit.empty:
                            st.success("✅ Resultado desde cache local (sin re-análisis)")
                            df_single = hit.reset_index(drop=True)

                    # 1) Cache Neon (si está configurado)
                    if df_single.empty:
                        row_cached = None
                        if CACHE_AVAILABLE:
                            row_cached = get_single_domain(dominio_limpio)

                        if row_cached is not None:
                            st.success("✅ Resultado desde cache Neon (sin re-análisis)")
                            df_single = pd.DataFrame([row_cached])

                    # 2) Re-análisis solo si no hay cache
                    if df_single.empty:
                        with st.spinner(f"Analizando {dominio_limpio}..."):
                            df_single = analizar_dominios([dominio_limpio])

                    # Persistir en sesión para evitar reruns costosos
                    if isinstance(df_single, pd.DataFrame) and not df_single.empty:
                        st.session_state["single_domain_last"] = dominio_limpio
                        st.session_state["single_domain_df"] = df_single

                if not df_single.empty:
                    row = df_single.iloc[0]
                    st.subheader(f"📌 {dominio_limpio}")

                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("#### ✉️ Identidad (Correo)")
                        st.metric("Postura", row.postura_identidad)
                        st.write(f"**Proveedor:** {row.correo_proveedor}")
                        st.write(f"**SPF:** {row.spf_estado}")
                        st.write(f"**DMARC:** {row.dmarc_estado}")
                        st.write(f"**Gateway:** {row.correo_gateway}")

                    with col2:
                        st.markdown("#### 🌐 Exposición (Web)")
                        st.metric("Postura", row.postura_exposicion)
                        st.write(f"**HTTPS:** {row.https_estado}")
                        st.write(f"**CDN/WAF:** {row.cdn_waf}")
                        st.write(f"**HSTS:** {'✅' if row.hsts else '❌'}")
                        st.write(f"**CSP:** {'✅' if row.csp else '❌'}")

                    st.markdown("#### ✅ Recomendaciones")
                    for r in generar_recomendaciones_fila(row):
                        st.write(f"- {r}")
                else:
                    st.error("No se pudo analizar el dominio")

    with tab3:
        if not CACHE_AVAILABLE:
            st.warning("Cache no disponible. Configura DATABASE_URL en secrets.")
        else:
            stats = get_cache_stats()
            if stats.get("connected"):
                col1, col2, col3 = st.columns(3)
                col1.metric("Total en cache", stats.get("total", 0))
                col2.metric("Frescos (< 7 días)", stats.get("fresh", 0))
                col3.metric("Vencidos", stats.get("stale", 0))

                st.markdown("---")
                st.markdown("### Filtros rápidos desde BD")

                filtro_postura = st.selectbox(
                    "Postura general",
                    ["Todos", "Básica", "Intermedia", "Avanzada"]
                )

                filtros = {}
                if filtro_postura != "Todos":
                    filtros["postura_general"] = filtro_postura

                if st.button("🔄 Cargar desde cache"):
                    df_cache = query_all_cached(filtros if filtros else None)
                    if df_cache.empty:
                        st.info("No hay dominios en cache con esos filtros")
                    else:
                        st.success(f"✅ {len(df_cache)} dominios cargados desde cache")
                        vista_global(df_cache)
                        st.dataframe(
                            df_cache[["dominio", "postura_general", "correo_proveedor", "cdn_waf"]],
                            use_container_width=True,
                            height=400,
                            hide_index=True,
                        )

                        csv = df_cache.to_csv(index=False).encode("utf-8")
                        st.download_button(
                            "📥 Exportar reporte",
                            csv,
                            f"prospectscan_reporte_{datetime.now().strftime('%Y%m%d')}.csv",
                            "text/csv"
                        )
            else:
                st.error("No se pudo conectar a la BD")
                if stats.get("error"):
                    st.caption(stats.get("error"))


if __name__ == "__main__":
    main()
