"""
Motor ProspectScan - Cruce Semántico (Capa 4)
Cruza Contexto Empresarial × Postura Seguridad → Prioridad de Acción

PREGUNTA QUE RESPONDE:
¿El contexto actual hace prudente anticipar una iniciativa de seguridad?

NO RESPONDE:
¿Qué vulnerabilidad existe? ¿Qué control falta?
"""

from datetime import datetime
from typing import List, Dict, Optional
import uuid

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from models.data_model_v2 import (
    ContextoEmpresarial, PosturaSeguridad, ResultadoCruce,
    EstadoOrganizacional, NivelPostura, PrioridadAccion, PresionExterna,
    REGLAS_CRUCE, DISCLAIMER_PROSPECTSCAN
)


# ============================================================================
# REGLAS DE CRUCE EXTENDIDAS
# ============================================================================

# Factores que aumentan prioridad
FACTORES_POSITIVOS = {
    "funding": "Funding reciente indica presupuesto disponible",
    "hiring": "Crecimiento de equipo = nuevas necesidades de seguridad",
    "ma_activo": "M&A requiere due diligence de seguridad urgente",
    "regulacion_alta": "Industria regulada prioriza compliance",
    "transicion": "Cambio organizacional = momento de decisión",
    "postura_debil": "Gaps evidentes facilitan justificación de inversión",
}

# Factores que reducen prioridad
FACTORES_NEGATIVOS = {
    "contraccion": "Empresa en reducción = presupuesto limitado",
    "postura_avanzada": "Ya tienen soluciones robustas",
    "industria_baja_regulacion": "Menor presión regulatoria",
    "estable_sin_cambio": "Sin drivers de cambio interno",
}

# Budget por industria (USD/año estimado)
BUDGET_POR_INDUSTRIA = {
    "finance": (100000, 250000),
    "banking": (100000, 250000),
    "healthcare": (75000, 200000),
    "retail": (50000, 150000),
    "technology": (50000, 150000),
    "manufacturing": (30000, 100000),
    "education": (20000, 75000),
    "default": (25000, 100000),
}


def ejecutar_cruce(contexto: ContextoEmpresarial, postura: PosturaSeguridad) -> PrioridadAccion:
    """
    Ejecuta cruce según REGLAS_CRUCE definidas en data_model_v2.
    NO inventa reglas, solo ejecuta las explícitas.
    """
    key = (contexto.estado_organizacional, postura.postura_general)
    return REGLAS_CRUCE.get(key, PrioridadAccion.MEDIA)


def calcular_score_oportunidad(contexto: ContextoEmpresarial, postura: PosturaSeguridad) -> int:
    """
    Calcula score numérico (0-100) para ordenamiento.
    Mayor score = mayor oportunidad.
    """
    score = 50  # Base
    
    # Estado organizacional
    score_estado = {
        EstadoOrganizacional.MA_ACTIVO: 30,
        EstadoOrganizacional.EN_TRANSICION: 25,
        EstadoOrganizacional.EN_CRECIMIENTO: 15,
        EstadoOrganizacional.ESTABLE: 0,
        EstadoOrganizacional.EN_CONTRACCION: -20,
        EstadoOrganizacional.DESCONOCIDO: 0,
    }
    score += score_estado.get(contexto.estado_organizacional, 0)
    
    # Postura de seguridad (menor postura = mayor oportunidad)
    score_postura = {
        NivelPostura.BASICA: 20,
        NivelPostura.INTERMEDIA: 5,
        NivelPostura.AVANZADA: -15,
    }
    score += score_postura.get(postura.postura_general, 0)
    
    # Presión externa
    score_presion = {
        PresionExterna.CRITICA: 15,
        PresionExterna.ALTA: 10,
        PresionExterna.MEDIA: 0,
        PresionExterna.BAJA: -10,
    }
    score += score_presion.get(contexto.presion_externa, 0)
    
    # Señales de inversión
    if "funding" in contexto.señales_inversion:
        score += 10
    if "hiring" in contexto.señales_inversion:
        score += 5
    
    # Regulaciones
    score += len(contexto.regulaciones_aplicables) * 3
    
    return max(0, min(100, score))


def identificar_factores(contexto: ContextoEmpresarial, postura: PosturaSeguridad) -> tuple[List[str], List[str]]:
    """
    Identifica factores positivos y negativos del cruce.
    Para explicar al humano por qué se priorizó así.
    """
    positivos = []
    negativos = []
    
    # Estado organizacional
    if contexto.estado_organizacional == EstadoOrganizacional.MA_ACTIVO:
        positivos.append(FACTORES_POSITIVOS["ma_activo"])
    elif contexto.estado_organizacional == EstadoOrganizacional.EN_TRANSICION:
        positivos.append(FACTORES_POSITIVOS["transicion"])
    elif contexto.estado_organizacional == EstadoOrganizacional.EN_CONTRACCION:
        negativos.append(FACTORES_NEGATIVOS["contraccion"])
    elif contexto.estado_organizacional == EstadoOrganizacional.ESTABLE:
        negativos.append(FACTORES_NEGATIVOS["estable_sin_cambio"])
    
    # Postura de seguridad
    if postura.postura_general == NivelPostura.BASICA:
        positivos.append(FACTORES_POSITIVOS["postura_debil"])
    elif postura.postura_general == NivelPostura.AVANZADA:
        negativos.append(FACTORES_NEGATIVOS["postura_avanzada"])
    
    # Señales de inversión
    if "funding" in contexto.señales_inversion:
        positivos.append(FACTORES_POSITIVOS["funding"])
    if "hiring" in contexto.señales_inversion:
        positivos.append(FACTORES_POSITIVOS["hiring"])
    
    # Presión regulatoria
    if contexto.presion_externa in [PresionExterna.ALTA, PresionExterna.CRITICA]:
        positivos.append(FACTORES_POSITIVOS["regulacion_alta"])
    elif contexto.presion_externa == PresionExterna.BAJA:
        negativos.append(FACTORES_NEGATIVOS["industria_baja_regulacion"])
    
    return positivos, negativos


def determinar_momento(contexto: ContextoEmpresarial, postura: PosturaSeguridad) -> tuple[bool, str]:
    """
    Determina si es momento oportuno para acercarse.
    """
    # Siempre es buen momento si hay funding o M&A
    if "funding" in contexto.señales_inversion:
        return True, "Funding reciente = presupuesto disponible para nuevas iniciativas"
    
    if contexto.estado_organizacional == EstadoOrganizacional.MA_ACTIVO:
        return True, "M&A en curso requiere evaluación de seguridad urgente"
    
    # Buen momento si hay crecimiento + gaps
    if contexto.estado_organizacional == EstadoOrganizacional.EN_CRECIMIENTO and postura.postura_general == NivelPostura.BASICA:
        return True, "Crecimiento rápido con gaps de seguridad = urgencia de inversión"
    
    # Mal momento si hay contracción
    if contexto.estado_organizacional == EstadoOrganizacional.EN_CONTRACCION:
        return False, "Empresa en contracción, probable recorte de presupuestos"
    
    # Mal momento si ya tienen todo resuelto
    if postura.postura_general == NivelPostura.AVANZADA and contexto.estado_organizacional == EstadoOrganizacional.ESTABLE:
        return False, "Empresa estable con seguridad avanzada, bajo incentivo de cambio"
    
    # Momento neutro
    return True, "Contexto favorable para conversación exploratoria"


def estimar_budget(contexto: ContextoEmpresarial) -> tuple[int, int]:
    """
    Estima rango de budget según industria.
    """
    industria_lower = contexto.industria_detectada.lower()
    
    for key, rango in BUDGET_POR_INDUSTRIA.items():
        if key in industria_lower:
            return rango
    
    return BUDGET_POR_INDUSTRIA["default"]


def generar_talking_points(contexto: ContextoEmpresarial, postura: PosturaSeguridad) -> List[str]:
    """
    Genera talking points para el equipo de ventas.
    """
    points = []
    
    # Por estado organizacional
    if contexto.estado_organizacional == EstadoOrganizacional.MA_ACTIVO:
        points.append("🔥 'Vemos que están en proceso de M&A. La due diligence de ciberseguridad es crítica para evitar heredar vulnerabilidades.'")
    elif contexto.estado_organizacional == EstadoOrganizacional.EN_CRECIMIENTO:
        points.append("📈 'Su crecimiento del equipo indica que están escalando. ¿Han escalado también la infraestructura de seguridad?'")
    elif contexto.estado_organizacional == EstadoOrganizacional.EN_TRANSICION:
        points.append("🔄 'Los momentos de transición son ideales para evaluar y fortalecer la postura de seguridad.'")
    
    # Por postura de seguridad
    if postura.postura_general == NivelPostura.BASICA:
        points.append("⚠️ 'Notamos oportunidades de mejora en protección de email y web. ¿Es algo que están evaluando?'")
        if not postura.tiene_dmarc:
            points.append("📧 'Sin DMARC configurado, su dominio es vulnerable a suplantación. El 90% de ataques empiezan por email.'")
    
    # Por regulación
    if "GDPR" in contexto.regulaciones_aplicables:
        points.append("🇪🇺 'Con operaciones en Europa, GDPR requiere medidas técnicas demostradas. ¿Tienen documentado su cumplimiento?'")
    if "PCI-DSS" in contexto.regulaciones_aplicables:
        points.append("💳 'PCI-DSS exige controles específicos de seguridad. Podemos ayudarles a identificar gaps.'")
    
    # Por presión externa
    if contexto.presion_externa == PresionExterna.CRITICA:
        points.append("🚨 'Su industria está bajo escrutinio regulatorio intenso. Una brecha ahora tendría consecuencias severas.'")
    
    return points


def generar_resultado_cruce(contexto: ContextoEmpresarial, postura: PosturaSeguridad) -> ResultadoCruce:
    """
    Genera ResultadoCruce completo.
    Output principal del Motor ProspectScan (Capa 4).
    """
    # Ejecutar cruce
    prioridad = ejecutar_cruce(contexto, postura)
    score = calcular_score_oportunidad(contexto, postura)
    factores_pos, factores_neg = identificar_factores(contexto, postura)
    momento_ok, razon_momento = determinar_momento(contexto, postura)
    budget_min, budget_max = estimar_budget(contexto)
    talking_points = generar_talking_points(contexto, postura)
    
    return ResultadoCruce(
        dominio=contexto.dominio,
        contexto=contexto,
        postura=postura,
        prioridad=prioridad,
        score_oportunidad=score,
        factores_positivos=factores_pos,
        factores_negativos=factores_neg,
        momento_oportuno=momento_ok,
        razon_momento=razon_momento,
        budget_estimado_min=budget_min,
        budget_estimado_max=budget_max,
        talking_points=talking_points,
        timestamp_cruce=datetime.utcnow(),
        version_reglas="1.0"
    )


# ============================================================================
# PROCESAMIENTO BATCH
# ============================================================================

def procesar_batch_cruce(
    contextos: List[ContextoEmpresarial], 
    posturas: Dict[str, PosturaSeguridad]
) -> List[ResultadoCruce]:
    """
    Procesa batch de cruces.
    Requiere que postura exista para cada dominio en contextos.
    """
    resultados = []
    
    for ctx in contextos:
        if ctx.dominio in posturas:
            resultado = generar_resultado_cruce(ctx, posturas[ctx.dominio])
            resultados.append(resultado)
        else:
            print(f"⚠️ Sin postura para {ctx.dominio}, omitiendo...")
    
    # Ordenar por score descendente
    resultados.sort(key=lambda r: r.score_oportunidad, reverse=True)
    
    return resultados


def filtrar_por_prioridad(resultados: List[ResultadoCruce], prioridad_minima: PrioridadAccion) -> List[ResultadoCruce]:
    """
    Filtra resultados por prioridad mínima.
    """
    orden = [PrioridadAccion.CRITICA, PrioridadAccion.ALTA, PrioridadAccion.MEDIA, PrioridadAccion.BAJA, PrioridadAccion.DESCARTADA]
    idx_minimo = orden.index(prioridad_minima)
    
    return [r for r in resultados if orden.index(r.prioridad) <= idx_minimo]


# ============================================================================
# SERIALIZACIÓN PARA API
# ============================================================================

def resultado_a_dict(resultado: ResultadoCruce) -> Dict:
    """
    Convierte ResultadoCruce a dict para API response.
    Incluye disclaimer obligatorio.
    """
    return {
        "disclaimer": DISCLAIMER_PROSPECTSCAN.strip(),
        "dominio": resultado.dominio,
        "prioridad": resultado.prioridad.value,
        "score_oportunidad": resultado.score_oportunidad,
        "momento_oportuno": resultado.momento_oportuno,
        "razon_momento": resultado.razon_momento,
        "factores_positivos": resultado.factores_positivos,
        "factores_negativos": resultado.factores_negativos,
        "budget_estimado": {
            "min": resultado.budget_estimado_min,
            "max": resultado.budget_estimado_max,
            "moneda": "USD"
        },
        "talking_points": resultado.talking_points,
        "contexto": {
            "estado_organizacional": resultado.contexto.estado_organizacional.value,
            "ritmo_cambio": resultado.contexto.ritmo_cambio,
            "presion_externa": resultado.contexto.presion_externa.value,
            "industria": resultado.contexto.industria_detectada,
            "regulaciones": resultado.contexto.regulaciones_aplicables,
            "señales_inversion": resultado.contexto.señales_inversion,
        },
        "postura": {
            "general": resultado.postura.postura_general.value,
            "identidad": resultado.postura.postura_identidad.value,
            "exposicion": resultado.postura.postura_exposicion.value,
            "score_tecnico": resultado.postura.score_agregado,
        },
        "metadata": {
            "timestamp_cruce": resultado.timestamp_cruce.isoformat(),
            "version_reglas": resultado.version_reglas,
        }
    }
