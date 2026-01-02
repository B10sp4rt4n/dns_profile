"""
ProspectScan - Análisis de Correo Corporativo
Producto SaaS B2B - Análisis de dominios corporativos
"""

import pandas as pd
import dns.resolver
import streamlit as st
import re
import whois
import concurrent.futures
from functools import lru_cache
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict
from enum import Enum

# ============================================================================
# CONFIGURACIÓN Y CONSTANTES
# ============================================================================

st.set_page_config(page_title="ProspectScan - Correo", page_icon="📧", layout="wide")

DNS_TIMEOUT = 5
MAX_WORKERS = 15
DOMINIOS_PERSONALES = frozenset([
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", 
    "protonmail.com", "icloud.com", "aol.com", "live.com"
])


class CategoriaVendor(Enum):
    PLATAFORMA_CORREO = "Plataforma de correo"
    SEGURIDAD_GATEWAY = "Seguridad / Gateway"
    ENVIO = "Envío (marketing / transaccional)"


class EstadoSPF(Enum):
    OK = "OK"
    DEBIL = "Débil"
    AUSENTE = "Ausente"


class EstadoDMARC(Enum):
    REJECT = "Reject"
    QUARANTINE = "Quarantine"
    NONE = "None"
    AUSENTE = "Ausente"


class PosturaGeneral(Enum):
    AVANZADA = "Avanzada"
    INTERMEDIA = "Intermedia"
    BASICA = "Básica"


class AntiguedadDominio(Enum):
    MADURO = "Maduro"
    INTERMEDIO = "Intermedio"
    NUEVO = "Nuevo"
    DESCONOCIDO = "Desconocido"


# ============================================================================
# CATÁLOGOS DE VENDORS
# ============================================================================

VENDORS_CORREO_MX = {
    r'outlook|protection\.outlook|microsoft': ("Microsoft 365", CategoriaVendor.PLATAFORMA_CORREO),
    r'google|googlemail|smtp\.google': ("Google Workspace", CategoriaVendor.PLATAFORMA_CORREO),
    r'zoho': ("Zoho Mail", CategoriaVendor.PLATAFORMA_CORREO),
    r'secureserver|domaincontrol': ("GoDaddy", CategoriaVendor.PLATAFORMA_CORREO),
    r'yahoodns|yahoo': ("Yahoo", CategoriaVendor.PLATAFORMA_CORREO),
}

VENDORS_SEGURIDAD_MX = {
    r'proofpoint|pphosted': ("Proofpoint", CategoriaVendor.SEGURIDAD_GATEWAY),
    r'mimecast': ("Mimecast", CategoriaVendor.SEGURIDAD_GATEWAY),
    r'barracuda|barracudanetworks': ("Barracuda", CategoriaVendor.SEGURIDAD_GATEWAY),
    r'iphmx|ironport': ("Cisco IronPort", CategoriaVendor.SEGURIDAD_GATEWAY),
    r'messagelabs|symantec': ("Symantec", CategoriaVendor.SEGURIDAD_GATEWAY),
    r'fireeye': ("FireEye", CategoriaVendor.SEGURIDAD_GATEWAY),
}

VENDORS_SEGURIDAD_SPF = {
    r'include:_spf\.proofpoint\.com': ("Proofpoint", CategoriaVendor.SEGURIDAD_GATEWAY),
    r'include:.*mimecast': ("Mimecast", CategoriaVendor.SEGURIDAD_GATEWAY),
    r'include:.*barracuda': ("Barracuda", CategoriaVendor.SEGURIDAD_GATEWAY),
}

VENDORS_ENVIO_SPF = {
    r'include:sendgrid\.net': ("SendGrid", CategoriaVendor.ENVIO),
    r'include:.*mailgun\.org': ("Mailgun", CategoriaVendor.ENVIO),
    r'include:amazonses\.com': ("Amazon SES", CategoriaVendor.ENVIO),
    r'include:.*mailchimp\.com': ("Mailchimp", CategoriaVendor.ENVIO),
    r'include:.*sendinblue': ("Sendinblue", CategoriaVendor.ENVIO),
    r'include:.*hubspot\.com': ("HubSpot", CategoriaVendor.ENVIO),
    r'include:.*salesforce\.com': ("Salesforce", CategoriaVendor.ENVIO),
    r'include:.*constantcontact\.com': ("Constant Contact", CategoriaVendor.ENVIO),
    r'include:.*postmarkapp\.com': ("Postmark", CategoriaVendor.ENVIO),
    r'include:.*sparkpost': ("SparkPost", CategoriaVendor.ENVIO),
    r'include:.*mandrill': ("Mandrill", CategoriaVendor.ENVIO),
}


# ============================================================================
# ESTRUCTURAS DE DATOS
# ============================================================================

@dataclass
class VendorDetectado:
    nombre: str
    categoria: CategoriaVendor
    fuente: str  # "MX" o "SPF"


@dataclass
class ResultadoAnalisis:
    dominio: str
    spf_raw: str
    dmarc_raw: str
    estado_spf: EstadoSPF
    estado_dmarc: EstadoDMARC
    vendor_correo: Optional[str]
    vendors_seguridad: List[str]
    vendors_envio: List[str]
    antiguedad: AntiguedadDominio
    fecha_creacion: Optional[str]
    postura: PosturaGeneral


# ============================================================================
# FUNCIONES DE CONSULTA DNS
# ============================================================================

@lru_cache(maxsize=1024)
def obtener_registros_mx(dominio: str) -> List[str]:
    """Obtiene registros MX del dominio."""
    try:
        respuesta = dns.resolver.resolve(dominio, 'MX', lifetime=DNS_TIMEOUT)
        return [r.exchange.to_text().rstrip('.').lower() for r in respuesta]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, 
            dns.resolver.Timeout, Exception):
        return []


@lru_cache(maxsize=1024)
def obtener_spf(dominio: str) -> str:
    """Obtiene registro SPF del dominio."""
    try:
        respuestas = dns.resolver.resolve(dominio, 'TXT', lifetime=DNS_TIMEOUT)
        for r in respuestas:
            txt_record = b''.join(r.strings).decode()
            if "v=spf1" in txt_record.lower():
                return txt_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, 
            dns.resolver.Timeout, Exception):
        pass
    return ""


@lru_cache(maxsize=1024)
def obtener_dmarc(dominio: str) -> str:
    """Obtiene registro DMARC del dominio."""
    try:
        respuestas = dns.resolver.resolve(f"_dmarc.{dominio}", 'TXT', lifetime=DNS_TIMEOUT)
        for r in respuestas:
            txt_record = b''.join(r.strings).decode()
            if "v=DMARC1" in txt_record.upper():
                return txt_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, 
            dns.resolver.Timeout, Exception):
        pass
    return ""


@lru_cache(maxsize=512)
def obtener_whois(dominio: str) -> Tuple[Optional[datetime], str]:
    """Obtiene fecha de creación del dominio via WHOIS."""
    try:
        info = whois.whois(dominio, timeout=10)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            return creation, creation.strftime("%Y-%m-%d")
    except Exception:
        pass
    return None, "N/D"


# ============================================================================
# FUNCIONES DE CLASIFICACIÓN
# ============================================================================

def evaluar_estado_spf(spf: str) -> EstadoSPF:
    """Evalúa el estado del SPF: OK, Débil o Ausente."""
    if not spf:
        return EstadoSPF.AUSENTE
    
    spf_lower = spf.lower()
    
    # SPF débil: +all, ?all o sin directiva all
    if "+all" in spf_lower:
        return EstadoSPF.DEBIL
    if "?all" in spf_lower:
        return EstadoSPF.DEBIL
    if "~all" not in spf_lower and "-all" not in spf_lower:
        return EstadoSPF.DEBIL
    
    return EstadoSPF.OK


def evaluar_estado_dmarc(dmarc: str) -> EstadoDMARC:
    """Evalúa el estado del DMARC: Reject, Quarantine, None o Ausente."""
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


def calcular_antiguedad(fecha_creacion: Optional[datetime]) -> AntiguedadDominio:
    """Calcula la antigüedad del dominio."""
    if not fecha_creacion:
        return AntiguedadDominio.DESCONOCIDO
    
    try:
        dias = (datetime.now() - fecha_creacion).days
        if dias >= 1095:  # 3+ años
            return AntiguedadDominio.MADURO
        elif dias >= 365:  # 1-3 años
            return AntiguedadDominio.INTERMEDIO
        else:
            return AntiguedadDominio.NUEVO
    except Exception:
        return AntiguedadDominio.DESCONOCIDO


def detectar_vendor_correo(registros_mx: List[str]) -> Optional[str]:
    """Detecta el vendor de correo principal por MX."""
    for registro in registros_mx:
        for patron, (nombre, _) in VENDORS_CORREO_MX.items():
            if re.search(patron, registro, re.IGNORECASE):
                return nombre
    
    # Si hay MX pero no coincide con ningún vendor conocido
    if registros_mx:
        return "Infraestructura propia"
    return None


def detectar_vendors_seguridad(registros_mx: List[str], spf: str) -> List[str]:
    """Detecta vendors de seguridad/gateway por MX y SPF."""
    vendors = set()
    
    # Buscar en MX
    for registro in registros_mx:
        for patron, (nombre, _) in VENDORS_SEGURIDAD_MX.items():
            if re.search(patron, registro, re.IGNORECASE):
                vendors.add(nombre)
    
    # Buscar en SPF
    if spf:
        for patron, (nombre, _) in VENDORS_SEGURIDAD_SPF.items():
            if re.search(patron, spf, re.IGNORECASE):
                vendors.add(nombre)
    
    return list(vendors)


def detectar_vendors_envio(spf: str) -> List[str]:
    """Detecta vendors de envío (marketing/transaccional) por SPF."""
    vendors = set()
    
    if spf:
        for patron, (nombre, _) in VENDORS_ENVIO_SPF.items():
            if re.search(patron, spf, re.IGNORECASE):
                vendors.add(nombre)
    
    return list(vendors)


def calcular_postura_general(
    estado_spf: EstadoSPF,
    estado_dmarc: EstadoDMARC,
    vendors_seguridad: List[str],
    antiguedad: AntiguedadDominio
) -> PosturaGeneral:
    """Calcula la postura general del dominio."""
    puntos = 0
    
    # SPF
    if estado_spf == EstadoSPF.OK:
        puntos += 2
    elif estado_spf == EstadoSPF.DEBIL:
        puntos += 1
    
    # DMARC
    if estado_dmarc == EstadoDMARC.REJECT:
        puntos += 3
    elif estado_dmarc == EstadoDMARC.QUARANTINE:
        puntos += 2
    elif estado_dmarc == EstadoDMARC.NONE:
        puntos += 1
    
    # Vendor de seguridad
    if vendors_seguridad:
        puntos += 2
    
    # Antigüedad (indicador blando)
    if antiguedad == AntiguedadDominio.MADURO:
        puntos += 1
    
    # Clasificación
    if puntos >= 6:
        return PosturaGeneral.AVANZADA
    elif puntos >= 3:
        return PosturaGeneral.INTERMEDIA
    return PosturaGeneral.BASICA


# ============================================================================
# FUNCIÓN PRINCIPAL DE ANÁLISIS
# ============================================================================

def analizar_dominio(dominio: str) -> ResultadoAnalisis:
    """Analiza un dominio y retorna el resultado completo."""
    # Consultas DNS
    registros_mx = obtener_registros_mx(dominio)
    spf = obtener_spf(dominio)
    dmarc = obtener_dmarc(dominio)
    fecha_creacion, fecha_str = obtener_whois(dominio)
    
    # Evaluaciones
    estado_spf = evaluar_estado_spf(spf)
    estado_dmarc = evaluar_estado_dmarc(dmarc)
    antiguedad = calcular_antiguedad(fecha_creacion)
    
    # Detección de vendors
    vendor_correo = detectar_vendor_correo(registros_mx)
    vendors_seguridad = detectar_vendors_seguridad(registros_mx, spf)
    vendors_envio = detectar_vendors_envio(spf)
    
    # Postura general
    postura = calcular_postura_general(
        estado_spf, estado_dmarc, vendors_seguridad, antiguedad
    )
    
    return ResultadoAnalisis(
        dominio=dominio,
        spf_raw=spf or "No encontrado",
        dmarc_raw=dmarc or "No encontrado",
        estado_spf=estado_spf,
        estado_dmarc=estado_dmarc,
        vendor_correo=vendor_correo or "No detectado",
        vendors_seguridad=vendors_seguridad,
        vendors_envio=vendors_envio,
        antiguedad=antiguedad,
        fecha_creacion=fecha_str,
        postura=postura
    )


def resultado_a_dict_tecnico(resultado: ResultadoAnalisis) -> Dict:
    """Convierte resultado a diccionario para DataFrame técnico."""
    return {
        "Dominio": resultado.dominio,
        "Vendor de Correo": resultado.vendor_correo,
        "Vendors de Seguridad": ", ".join(resultado.vendors_seguridad) or "Ninguno",
        "Vendors de Envío": ", ".join(resultado.vendors_envio) or "Ninguno",
        "SPF (Raw)": resultado.spf_raw,
        "Estado SPF": resultado.estado_spf.value,
        "DMARC (Raw)": resultado.dmarc_raw,
        "Estado DMARC": resultado.estado_dmarc.value,
        "Fecha Creación": resultado.fecha_creacion,
        "Antigüedad": resultado.antiguedad.value,
        "Postura General": resultado.postura.value
    }


def resultado_a_dict_ejecutivo(resultado: ResultadoAnalisis) -> Dict:
    """Convierte resultado a diccionario para resumen ejecutivo."""
    return {
        "Dominio": resultado.dominio,
        "Vendor de Correo": resultado.vendor_correo,
        "Seguridad": ", ".join(resultado.vendors_seguridad) or "Sin gateway",
        "Envío": ", ".join(resultado.vendors_envio) or "Sin servicios",
        "SPF": resultado.estado_spf.value,
        "DMARC": resultado.estado_dmarc.value,
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
    st.title("� ProspectScan - Análisis de Correo Corporativo")
    st.markdown("**v1** — Análisis de dominios corporativos")
    
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
        
        st.dataframe(
            df_ejecutivo,
            use_container_width=True,
            hide_index=True
        )
        
        csv_ejecutivo = df_ejecutivo.to_csv(index=False).encode("utf-8")
        st.download_button(
            "📥 Descargar Resumen Ejecutivo",
            csv_ejecutivo,
            "resumen_ejecutivo.csv",
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
            "diagnostico_tecnico.csv",
            "text/csv"
        )
        
    except Exception as e:
        st.error(f"❌ Error procesando archivo: {str(e)}")


if __name__ == "__main__":
    main()
