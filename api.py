"""
API REST para ProspectScan - Security Heatmap
Expone funcionalidades de app_superficie.py como endpoints JSON

ARQUITECTURA DE 5 CAPAS:
1. Ingesta → ZoomInfo Excel (inmutable)
2. Contexto → Derivación empresarial
3. Postura → app_superficie.py
4. Motor → cruce_semantico.py
5. Focus → Validación humana (Capa 5)
"""

from fastapi import FastAPI, HTTPException, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from typing import List, Optional, Dict, Any
import pandas as pd
from datetime import datetime
import tempfile
import os

# Importar funciones del backend existente (Capa 3)
from app_superficie import (
    analizar_dominio,
    analizar_dominios,
    validar_email,
    extraer_dominio,
    resultado_a_tecnico,
    Postura,
    EstadoSPF,
    EstadoDMARC,
    EstadoHTTPS,
    EstadoHeader,
    CACHE_AVAILABLE
)

# Importar análisis enriquecido
from enriched_analysis import generate_enriched_analysis

# Importar Capa 1 y 2: Ingesta y Contexto
from ingesta.zoominfo_adapter import procesar_ingesta_zoominfo, derivar_contexto
from models.data_model_v2 import (
    NivelPostura, PosturaSeguridad, ResultadoCruce, PrioridadAccion,
    DISCLAIMER_PROSPECTSCAN
)

# Importar Capa 4: Motor de Cruce
from motor.cruce_semantico import (
    generar_resultado_cruce,
    procesar_batch_cruce,
    filtrar_por_prioridad,
    resultado_a_dict
)

if CACHE_AVAILABLE:
    from db_cache import query_all_cached, get_cache_stats, _get_connection

# ============================================================================
# CONFIGURACIÓN FASTAPI
# ============================================================================

app = FastAPI(
    title="ProspectScan API",
    description="API para análisis de seguridad de dominios empresariales",
    version="1.0.0"
)

# CORS para permitir requests desde el frontend React
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, especificar dominios exactos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# MODELOS PYDANTIC
# ============================================================================

class DomainAnalysisRequest(BaseModel):
    domain: str
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        if not v or len(v) < 3:
            raise ValueError("Dominio inválido")
        return v.lower().strip()


class BulkAnalysisRequest(BaseModel):
    domains: List[str]
    
    @field_validator('domains')
    @classmethod
    def validate_domains(cls, v):
        if not v or len(v) == 0:
            raise ValueError("Lista de dominios vacía")
        if len(v) > 100:
            raise ValueError("Máximo 100 dominios por request")
        return [d.lower().strip() for d in v]


class EmailListRequest(BaseModel):
    emails: List[str]
    
    @field_validator('emails')
    @classmethod
    def validate_emails(cls, v):
        if not v or len(v) == 0:
            raise ValueError("Lista de emails vacía")
        if len(v) > 100:
            raise ValueError("Máximo 100 emails por request")
        return v


class DomainResponse(BaseModel):
    domain: str
    score: int
    identity_level: str
    exposure_level: str
    general_level: str
    provider: str
    spf_status: str
    dmarc_status: str
    https_status: str
    cdn_waf: Optional[str]
    security_vendors: List[str]
    recommendations: List[str]
    analyzed_at: str


# ============================================================================
# FUNCIONES HELPER
# ============================================================================

def calcular_score(postura_identidad: str, postura_exposicion: str, 
                   estado_spf: str, estado_dmarc: str) -> int:
    """
    Calcula un score 0-100 basado en las posturas y estados.
    Lógica simplificada - en producción usar ML.
    """
    score = 50  # Base
    
    # Postura Identidad (40 puntos)
    if postura_identidad == "Avanzada":
        score += 20
    elif postura_identidad == "Intermedia":
        score += 10
    else:
        score -= 10
    
    # Postura Exposición (40 puntos)
    if postura_exposicion == "Avanzada":
        score += 20
    elif postura_exposicion == "Intermedia":
        score += 10
    else:
        score -= 10
    
    # SPF (10 puntos)
    if estado_spf == "OK":
        score += 5
    elif estado_spf == "Débil":
        score += 2
    else:
        score -= 5
    
    # DMARC (10 puntos)
    if estado_dmarc == "Reject":
        score += 5
    elif estado_dmarc == "Quarantine":
        score += 3
    elif estado_dmarc == "None":
        score += 1
    else:
        score -= 5
    
    return max(0, min(100, score))


def convertir_resultado_a_api(resultado) -> Dict[str, Any]:
    """Convierte ResultadoSuperficie a formato API del Heatmap"""
    
    # Calcular score
    score = calcular_score(
        resultado.identidad.postura.value,
        resultado.exposicion.postura.value,
        resultado.identidad.estado_spf.value,
        resultado.identidad.estado_dmarc.value
    )
    
    # Mapear niveles
    identity_level = resultado.identidad.postura.value
    exposure_level = resultado.exposicion.postura.value
    general_level = resultado.postura_general.value
    
    # Provider
    provider = resultado.identidad.vendor_correo or "Otro"
    
    return {
        "domain": resultado.dominio,
        "score": score,
        "identity_level": identity_level,
        "exposure_level": exposure_level,
        "general_level": general_level,
        "provider": provider,
        "spf_status": resultado.identidad.estado_spf.value,
        "dmarc_status": resultado.identidad.estado_dmarc.value,
        "https_status": resultado.exposicion.https.value,
        "cdn_waf": resultado.exposicion.cdn_waf,
        "security_vendors": resultado.identidad.vendors_seguridad,
        "recommendations": resultado.recomendaciones,
        "analyzed_at": datetime.utcnow().isoformat()
    }


# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/")
def root():
    """Health check"""
    return {
        "status": "ok",
        "service": "ProspectScan API",
        "version": "1.0.0",
        "cache_available": CACHE_AVAILABLE
    }


@app.get("/api/health")
def health():
    """Health check detallado"""
    health_info = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "cache_available": CACHE_AVAILABLE
    }
    
    if CACHE_AVAILABLE:
        try:
            stats = get_cache_stats()
            health_info["cache_stats"] = stats
        except:
            health_info["cache_stats"] = "unavailable"
    
    return health_info


@app.get("/api/domains", response_model=List[DomainResponse])
def get_all_domains():
    """
    Obtiene todos los dominios analizados desde cache.
    Si no hay cache, retorna lista vacía.
    """
    if not CACHE_AVAILABLE:
        return []
    
    try:
        df = query_all_cached()
        
        if df is None or df.empty:
            return []
        
        # Convertir DataFrame a lista de respuestas
        dominios = []
        for _, row in df.iterrows():
            # Parsear los datos del cache
            dominio_data = {
                "domain": row.get("dominio", ""),
                "score": calcular_score(
                    row.get("postura_identidad", "Básica"),
                    row.get("postura_exposicion", "Básica"),
                    row.get("spf_estado", "Ausente"),
                    row.get("dmarc_estado", "Ausente")
                ),
                "identity_level": row.get("postura_identidad", "Básica"),
                "exposure_level": row.get("postura_exposicion", "Básica"),
                "general_level": row.get("postura_general", "Básica"),
                "provider": row.get("correo_proveedor", "Otro") or "Otro",
                "spf_status": row.get("spf_estado", "Ausente"),
                "dmarc_status": row.get("dmarc_estado", "Ausente"),
                "https_status": row.get("https_estado", "No disponible"),
                "cdn_waf": row.get("cdn_waf"),
                "security_vendors": row.get("correo_gateway", "").split(", ") if row.get("correo_gateway") else [],
                "recommendations": [],  # No guardadas en cache
                "analyzed_at": row.get("updated_at", datetime.utcnow().isoformat())
            }
            dominios.append(dominio_data)
        
        return dominios
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener dominios: {str(e)}")


@app.post("/api/analyze/domain", response_model=DomainResponse)
def analyze_single_domain(request: DomainAnalysisRequest):
    """
    Analiza un dominio individual y retorna resultados detallados.
    """
    try:
        resultado = analizar_dominio(request.domain)
        return convertir_resultado_a_api(resultado)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al analizar dominio: {str(e)}")


@app.post("/api/analyze/bulk", response_model=List[DomainResponse])
def analyze_bulk_domains(request: BulkAnalysisRequest):
    """
    Analiza múltiples dominios en paralelo.
    Máximo 100 dominios por request.
    """
    try:
        df = analizar_dominios(request.domains)
        
        # Convertir DataFrame a lista de respuestas
        resultados = []
        for _, row in df.iterrows():
            # Reconstruir resultado desde DataFrame
            resultado_data = {
                "domain": row["Dominio"],
                "score": calcular_score(
                    row["Postura Identidad"],
                    row["Postura Exposición"],
                    row["Estado SPF"],
                    row["Estado DMARC"]
                ),
                "identity_level": row["Postura Identidad"],
                "exposure_level": row["Postura Exposición"],
                "general_level": row["Superficie Digital"],
                "provider": row["Vendor Correo"],
                "spf_status": row["Estado SPF"],
                "dmarc_status": row["Estado DMARC"],
                "https_status": row["HTTPS"],
                "cdn_waf": row["CDN/WAF"] if row["CDN/WAF"] != "No detectado" else None,
                "security_vendors": row["Vendors Seguridad"].split(", ") if row["Vendors Seguridad"] != "Ninguno" else [],
                "recommendations": [],
                "analyzed_at": datetime.utcnow().isoformat()
            }
            resultados.append(resultado_data)
        
        return resultados
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al analizar dominios: {str(e)}")


@app.post("/api/analyze/emails", response_model=List[DomainResponse])
def analyze_from_emails(request: EmailListRequest):
    """
    Extrae dominios de emails y los analiza.
    Filtra dominios personales automáticamente.
    """
    try:
        # Extraer dominios únicos de los emails
        dominios = set()
        for email in request.emails:
            if validar_email(email):
                dominio = extraer_dominio(email)
                if dominio:
                    dominios.add(dominio)
        
        if not dominios:
            raise HTTPException(status_code=400, detail="No se encontraron dominios válidos en los emails")
        
        # Analizar dominios
        df = analizar_dominios(list(dominios))
        
        # Convertir a respuesta
        resultados = []
        for _, row in df.iterrows():
            resultado_data = {
                "domain": row["Dominio"],
                "score": calcular_score(
                    row["Postura Identidad"],
                    row["Postura Exposición"],
                    row["Estado SPF"],
                    row["Estado DMARC"]
                ),
                "identity_level": row["Postura Identidad"],
                "exposure_level": row["Postura Exposición"],
                "general_level": row["Superficie Digital"],
                "provider": row["Vendor Correo"],
                "spf_status": row["Estado SPF"],
                "dmarc_status": row["Estado DMARC"],
                "https_status": row["HTTPS"],
                "cdn_waf": row["CDN/WAF"] if row["CDN/WAF"] != "No detectado" else None,
                "security_vendors": row["Vendors Seguridad"].split(", ") if row["Vendors Seguridad"] != "Ninguno" else [],
                "recommendations": [],
                "analyzed_at": datetime.utcnow().isoformat()
            }
            resultados.append(resultado_data)
        
        return resultados
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al analizar emails: {str(e)}")


@app.get("/api/stats")
def get_statistics():
    """
    Obtiene estadísticas agregadas de todos los dominios analizados.
    """
    if not CACHE_AVAILABLE:
        return {
            "total_domains": 0,
            "cache_available": False
        }
    
    try:
        stats = get_cache_stats()
        return {
            "cache_available": True,
            **stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")


@app.post("/api/analyze/enriched")
def analyze_domain_enriched(request: DomainAnalysisRequest):
    """
    Analiza un dominio y retorna análisis enriquecido con insights comerciales.
    Incluye:
    - Detección de industria
    - Tech stack completo
    - Budget signals
    - Talking points para ventas
    - Estimación de deal size
    - Urgencia de acción
    """
    try:
        # Análisis técnico base
        resultado = analizar_dominio(request.domain)
        
        # Calcular score
        score = calcular_score(
            resultado.identidad.postura.value,
            resultado.exposicion.postura.value,
            resultado.identidad.estado_spf.value,
            resultado.identidad.estado_dmarc.value
        )
        
        # Generar análisis enriquecido
        enriched = generate_enriched_analysis(resultado, score)
        
        # Convertir a dict para JSON response
        return {
            "domain": enriched.domain,
            "industry": enriched.industry,
            "score": enriched.score,
            "posture": enriched.posture,
            "insights": [
                {
                    "category": i.category,
                    "title": i.title,
                    "status": i.status,
                    "technical_detail": i.technical_detail,
                    "business_impact": i.business_impact,
                    "cost_estimate": i.cost_estimate,
                    "recommendation": i.recommendation,
                    "urgency": i.urgency
                }
                for i in enriched.insights
            ],
            "commercial_intel": {
                "budget_signals": enriched.commercial_intel.budget_signals,
                "tech_stack": enriched.commercial_intel.tech_stack,
                "decision_makers": enriched.commercial_intel.decision_makers,
                "pain_points": enriched.commercial_intel.pain_points,
                "estimated_budget": enriched.commercial_intel.estimated_budget,
                "competitive_advantage": enriched.commercial_intel.competitive_advantage
            },
            "executive_summary": enriched.executive_summary,
            "technical_summary": enriched.technical_summary,
            "sales_talking_points": enriched.sales_talking_points,
            "estimated_deal_size": enriched.estimated_deal_size,
            "urgency_level": enriched.urgency_level,
            "analyzed_at": enriched.analyzed_at
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al generar análisis enriquecido: {str(e)}")


@app.delete("/api/cache/clear")
def clear_cache():
    """
    Limpia completamente el caché de dominios.
    Útil para forzar re-análisis con detección actualizada.
    """
    if not CACHE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Cache no disponible")
    
    try:
        conn = _get_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="No se pudo conectar a la base de datos")
        
        cur = conn.cursor()
        cur.execute("TRUNCATE TABLE dominios_cache;")
        conn.commit()
        
        # Obtener conteo antes de cerrar
        cur.execute("SELECT COUNT(*) FROM dominios_cache;")
        count = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "message": "Caché limpiado completamente",
            "domains_remaining": count,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al limpiar caché: {str(e)}")


# ============================================================================
# ENDPOINTS CAPA 1-4: PIPELINE COMPLETO PROSPECTSCAN
# ============================================================================

# Storage en memoria para snapshots (en producción usar DB)
_snapshots_storage: Dict[str, Any] = {}
_contextos_storage: Dict[str, Any] = {}
_resultados_cruce_storage: Dict[str, ResultadoCruce] = {}


@app.post("/api/ingesta/upload")
async def upload_zoominfo_excel(file: UploadFile = File(...)):
    """
    Capa 1 - INGESTA: Sube reporte ZoomInfo Excel.
    
    IMPORTANTE: ProspectScan NO modifica estos datos.
    ZoomInfo es la fuente de verdad.
    
    Retorna:
    - snapshot_id: ID del snapshot creado
    - empresas_count: Número de empresas procesadas
    - dominios: Lista de dominios extraídos
    """
    if not file.filename.endswith(('.xlsx', '.xls')):
        raise HTTPException(status_code=400, detail="Solo se aceptan archivos Excel (.xlsx, .xls)")
    
    try:
        # Guardar archivo temporal
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        
        try:
            # Procesar ingesta (Capa 1 + 2)
            snapshot, empresas, contextos = procesar_ingesta_zoominfo(tmp_path)
            
            # Almacenar en memoria
            _snapshots_storage[snapshot.id] = snapshot
            for ctx in contextos:
                _contextos_storage[ctx.dominio] = ctx
            
            # Extraer dominios para respuesta
            dominios = [e.dominio for e in empresas if e.dominio]
            
            return {
                "status": "success",
                "snapshot_id": snapshot.id,
                "archivo_original": snapshot.archivo_origen,
                "checksum": snapshot.checksum,
                "empresas_count": len(empresas),
                "dominios": dominios,
                "timestamp": snapshot.fecha_creacion.isoformat(),
                "mensaje": "Snapshot creado. Use POST /api/cruce/batch para ejecutar análisis completo."
            }
        finally:
            # Limpiar archivo temporal
            os.unlink(tmp_path)
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error procesando archivo: {str(e)}")


@app.post("/api/cruce/batch")
def ejecutar_cruce_batch(
    snapshot_id: str = Query(..., description="ID del snapshot a procesar"),
    prioridad_minima: str = Query("MEDIA", description="Filtrar por prioridad mínima: CRITICA, ALTA, MEDIA, BAJA")
):
    """
    Capa 3+4 - POSTURA + MOTOR: Ejecuta análisis de seguridad y cruce semántico.
    
    Para cada dominio del snapshot:
    1. Obtiene PosturaSeguridad (Capa 3 - app_superficie.py)
    2. Ejecuta cruce con Contexto (Capa 4 - REGLAS_CRUCE)
    3. Genera ResultadoCruce con prioridad
    
    Retorna lista ordenada por score_oportunidad.
    """
    if snapshot_id not in _snapshots_storage:
        raise HTTPException(status_code=404, detail=f"Snapshot {snapshot_id} no encontrado")
    
    try:
        # Obtener contextos del snapshot
        dominios_snapshot = [
            dominio for dominio, ctx in _contextos_storage.items()
            if ctx.snapshot_id == snapshot_id
        ]
        
        if not dominios_snapshot:
            raise HTTPException(status_code=400, detail="No hay dominios en este snapshot")
        
        resultados = []
        errores = []
        
        for dominio in dominios_snapshot:
            try:
                # Capa 3: Análisis de seguridad
                resultado_superficie = analizar_dominio(dominio)
                
                # Convertir a PosturaSeguridad
                postura = _resultado_a_postura(resultado_superficie)
                
                # Capa 4: Cruce semántico
                contexto = _contextos_storage[dominio]
                resultado_cruce = generar_resultado_cruce(contexto, postura)
                
                # Almacenar
                _resultados_cruce_storage[dominio] = resultado_cruce
                resultados.append(resultado_cruce)
                
            except Exception as e:
                errores.append({"dominio": dominio, "error": str(e)})
        
        # Filtrar por prioridad
        prioridad_enum = PrioridadAccion(prioridad_minima.upper())
        resultados_filtrados = filtrar_por_prioridad(resultados, prioridad_enum)
        
        # Ordenar por score
        resultados_filtrados.sort(key=lambda r: r.score_oportunidad, reverse=True)
        
        return {
            "disclaimer": DISCLAIMER_PROSPECTSCAN.strip(),
            "snapshot_id": snapshot_id,
            "total_procesados": len(resultados),
            "total_filtrados": len(resultados_filtrados),
            "filtro_prioridad": prioridad_minima,
            "errores": errores,
            "resultados": [resultado_a_dict(r) for r in resultados_filtrados]
        }
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en cruce: {str(e)}")


@app.get("/api/cruce/{dominio}")
def get_resultado_cruce(dominio: str):
    """
    Obtiene ResultadoCruce para un dominio específico.
    Debe haberse ejecutado el batch primero.
    """
    if dominio not in _resultados_cruce_storage:
        raise HTTPException(
            status_code=404, 
            detail=f"No hay resultado de cruce para {dominio}. Ejecute /api/cruce/batch primero."
        )
    
    return resultado_a_dict(_resultados_cruce_storage[dominio])


@app.post("/api/cruce/dominio-individual")
def analizar_dominio_completo(
    dominio: str = Query(..., description="Dominio a analizar"),
    industria: str = Query("general", description="Industria de la empresa"),
    estado: str = Query("estable", description="Estado organizacional: ma_activo, en_transicion, en_crecimiento, estable, en_contraccion"),
    señales: str = Query("", description="Señales de inversión separadas por coma: funding,hiring")
):
    """
    Análisis completo de un dominio sin necesidad de Excel.
    Útil para análisis ad-hoc o demos.
    
    Ejecuta las 4 capas:
    1. Simula ingesta con datos proporcionados
    2. Deriva contexto empresarial
    3. Analiza postura de seguridad
    4. Ejecuta cruce semántico
    """
    from models.data_model_v2 import (
        EmpresaFuente, EstadoOrganizacional, PresionExterna, ContextoEmpresarial
    )
    from datetime import datetime
    import uuid
    
    try:
        # Capa 1+2: Simular ingesta y derivar contexto
        empresa = EmpresaFuente(
            dominio=dominio,
            nombre_empresa=dominio.split('.')[0].upper(),
            industria=industria,
            pais="MX",
            empleados_rango="desconocido",
            ingresos_rango="desconocido",
            tecnologias_detectadas=[],
            fecha_extraccion=datetime.utcnow()
        )
        
        # Mapear estado
        estado_map = {
            "ma_activo": EstadoOrganizacional.MA_ACTIVO,
            "en_transicion": EstadoOrganizacional.EN_TRANSICION,
            "en_crecimiento": EstadoOrganizacional.EN_CRECIMIENTO,
            "estable": EstadoOrganizacional.ESTABLE,
            "en_contraccion": EstadoOrganizacional.EN_CONTRACCION,
        }
        estado_org = estado_map.get(estado.lower(), EstadoOrganizacional.DESCONOCIDO)
        
        # Derivar presión externa por industria
        presion_alta = ["finance", "banking", "healthcare", "fintech", "insurance"]
        presion_media = ["retail", "technology", "telecom", "energy"]
        
        if industria.lower() in presion_alta:
            presion = PresionExterna.ALTA
        elif industria.lower() in presion_media:
            presion = PresionExterna.MEDIA
        else:
            presion = PresionExterna.BAJA
        
        # Detectar regulaciones
        regulaciones = []
        if industria.lower() in ["finance", "banking", "fintech", "insurance"]:
            regulaciones.extend(["SOX", "PCI-DSS"])
        if industria.lower() == "healthcare":
            regulaciones.append("HIPAA")
        # GDPR si tiene presencia EU (asumimos por defecto)
        regulaciones.append("GDPR")
        
        contexto = ContextoEmpresarial(
            dominio=dominio,
            snapshot_id=str(uuid.uuid4()),
            empresa_fuente=empresa,
            estado_organizacional=estado_org,
            ritmo_cambio="moderado",
            presion_externa=presion,
            señales_inversion=señales.split(",") if señales else [],
            industria_detectada=industria,
            regulaciones_aplicables=regulaciones,
            fecha_derivacion=datetime.utcnow()
        )
        
        # Capa 3: Postura de seguridad
        resultado_superficie = analizar_dominio(dominio)
        postura = _resultado_a_postura(resultado_superficie)
        
        # Capa 4: Cruce semántico
        resultado_cruce = generar_resultado_cruce(contexto, postura)
        
        # Almacenar
        _contextos_storage[dominio] = contexto
        _resultados_cruce_storage[dominio] = resultado_cruce
        
        return resultado_a_dict(resultado_cruce)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en análisis: {str(e)}")


def _resultado_a_postura(resultado) -> PosturaSeguridad:
    """
    Convierte ResultadoSuperficie (Capa 3) a PosturaSeguridad para el Motor.
    """
    from models.data_model_v2 import NivelPostura, PosturaSeguridad
    
    # Mapear posturas
    postura_map = {
        "Avanzada": NivelPostura.AVANZADA,
        "Intermedia": NivelPostura.INTERMEDIA,
        "Básica": NivelPostura.BASICA,
    }
    
    postura_identidad = postura_map.get(
        resultado.identidad.postura.value, NivelPostura.BASICA
    )
    postura_exposicion = postura_map.get(
        resultado.exposicion.postura.value, NivelPostura.BASICA
    )
    postura_general = postura_map.get(
        resultado.postura_general.value, NivelPostura.BASICA
    )
    
    # Calcular score técnico
    score = 50
    if resultado.identidad.estado_spf.value == "OK":
        score += 15
    elif resultado.identidad.estado_spf.value == "Débil":
        score += 5
    
    if resultado.identidad.estado_dmarc.value in ["Reject", "Quarantine"]:
        score += 15
    elif resultado.identidad.estado_dmarc.value == "None":
        score += 5
    
    if resultado.exposicion.https.value in ["Estricto", "OK"]:
        score += 10
    
    if resultado.exposicion.cdn_waf:
        score += 10
    
    return PosturaSeguridad(
        dominio=resultado.dominio,
        postura_identidad=postura_identidad,
        postura_exposicion=postura_exposicion,
        postura_general=postura_general,
        tiene_spf=resultado.identidad.estado_spf.value != "Ausente",
        tiene_dmarc=resultado.identidad.estado_dmarc.value != "Ausente",
        tiene_https=resultado.exposicion.https.value not in ["No disponible", "Redirect Inseguro"],
        tiene_waf=resultado.exposicion.cdn_waf is not None,
        vendors_detectados=resultado.identidad.vendors_seguridad or [],
        score_agregado=min(100, max(0, score)),
        fecha_analisis=datetime.utcnow()
    )


# ============================================================================
# ARRANQUE
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
