"""
Adaptador de Ingesta - ZoomInfo Excel → Snapshots
Capa 1: Ingesta Masiva según PROMPT_MAESTRO.md

PRINCIPIO: ZoomInfo es la fuente de verdad
ProspectScan NO edita, NO corrige, solo interpreta.
"""

import pandas as pd
import hashlib
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent))

from models.data_model_v2 import (
    Snapshot, EmpresaFuente, FuenteDatos,
    ContextoEmpresarial, EstadoOrganizacional, PresionExterna
)


# ============================================================================
# MAPEO DE COLUMNAS ZOOMINFO → EmpresaFuente
# ============================================================================

COLUMNAS_ZOOMINFO = {
    # Identificadores
    'company_id': 'zoominfo_id',
    'website': 'dominio',
    'company_name': 'nombre_empresa',
    
    # Datos empresariales
    'industry': 'industria',
    'sub_industry': 'sub_industria',
    'employee_range': 'empleados_rango',
    'revenue_range': 'ingresos_rango',
    'country': 'pais',
    'state': 'estado_region',
    
    # Señales
    'employee_growth_12m': 'crecimiento_empleados_12m',
    'recent_funding': 'funding_reciente',
    'technologies': 'tech_stack_conocido',
}


def parsear_excel_zoominfo(ruta_excel: str) -> pd.DataFrame:
    """
    Lee Excel de ZoomInfo sin modificar datos.
    Validación mínima, preserva datos crudos.
    """
    try:
        df = pd.read_excel(ruta_excel)
        print(f"✅ Excel cargado: {len(df)} registros")
        return df
    except Exception as e:
        print(f"❌ Error leyendo Excel: {e}")
        raise


def calcular_checksum(df: pd.DataFrame) -> str:
    """Genera checksum del DataFrame para validar integridad"""
    contenido = df.to_json(orient='records')
    return hashlib.sha256(contenido.encode()).hexdigest()


def crear_snapshot(df: pd.DataFrame, fuente: FuenteDatos = FuenteDatos.ZOOMINFO) -> Snapshot:
    """
    Crea Snapshot inmutable del Excel de ZoomInfo.
    NO modifica datos, solo empaqueta.
    """
    snapshot_id = f"snapshot_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    
    return Snapshot(
        snapshot_id=snapshot_id,
        fuente=fuente,
        timestamp_ingesta=datetime.utcnow(),
        version=1,  # Incrementa en cada refresco
        datos_crudos=df.to_dict(orient='records'),
        checksum=calcular_checksum(df),
        registros_totales=len(df),
        registros_nuevos=len(df),  # En primera ingesta, todos son nuevos
        registros_actualizados=0
    )


def extraer_empresas(snapshot: Snapshot) -> List[EmpresaFuente]:
    """
    Extrae EmpresaFuente desde Snapshot.
    Mapea columnas pero NO modifica valores.
    """
    empresas = []
    
    for row in snapshot.datos_crudos:
        # Mapeo directo, sin transformaciones
        empresa = EmpresaFuente(
            zoominfo_id=str(row.get('company_id', '')),
            dominio=str(row.get('website', '')).replace('http://', '').replace('https://', '').split('/')[0],
            nombre_empresa=str(row.get('company_name', '')),
            industria=str(row.get('industry', 'Desconocido')),
            sub_industria=row.get('sub_industry'),
            empleados_rango=str(row.get('employee_range', 'Desconocido')),
            ingresos_rango=row.get('revenue_range'),
            pais=str(row.get('country', 'Unknown')),
            estado_region=row.get('state'),
            
            # Señales numéricas
            crecimiento_empleados_12m=float(row.get('employee_growth_12m', 0)) if row.get('employee_growth_12m') else None,
            funding_reciente=bool(row.get('recent_funding', False)),
            tech_stack_conocido=str(row.get('technologies', '')).split(',') if row.get('technologies') else [],
            
            # Metadatos
            snapshot_id=snapshot.snapshot_id,
            timestamp_fuente=snapshot.timestamp_ingesta
        )
        empresas.append(empresa)
    
    print(f"✅ Extraídas {len(empresas)} empresas de snapshot {snapshot.snapshot_id}")
    return empresas


# ============================================================================
# DERIVACIÓN CAPA 2: EmpresaFuente → ContextoEmpresarial
# ============================================================================

def derivar_estado_organizacional(empresa: EmpresaFuente) -> EstadoOrganizacional:
    """
    Deriva estado organizacional desde señales de ZoomInfo.
    Reglas explícitas, NO adivinación.
    """
    # M&A o funding = transición
    if empresa.funding_reciente:
        return EstadoOrganizacional.EN_TRANSICION
    
    # Crecimiento alto de empleados
    if empresa.crecimiento_empleados_12m:
        if empresa.crecimiento_empleados_12m > 20:
            return EstadoOrganizacional.EN_CRECIMIENTO
        elif empresa.crecimiento_empleados_12m < -10:
            return EstadoOrganizacional.EN_CONTRACCION
    
    # Por defecto: estable
    return EstadoOrganizacional.ESTABLE


def derivar_presion_externa(empresa: EmpresaFuente) -> PresionExterna:
    """
    Deriva presión externa según industria y regulación.
    Reglas explícitas basadas en contexto regulatorio.
    """
    industrias_alta_presion = [
        'Finance', 'Banking', 'Healthcare', 'Insurance',
        'Government', 'Legal', 'Retail', 'E-commerce'
    ]
    
    if any(ind.lower() in empresa.industria.lower() for ind in industrias_alta_presion):
        return PresionExterna.ALTA
    
    return PresionExterna.MEDIA


def detectar_regulaciones(empresa: EmpresaFuente) -> List[str]:
    """Detecta regulaciones aplicables por industria y país"""
    regulaciones = []
    
    industria_lower = empresa.industria.lower()
    
    # GDPR (Europa)
    if empresa.pais in ['Germany', 'France', 'Spain', 'Italy', 'UK', 'Netherlands']:
        regulaciones.append('GDPR')
    
    # PCI-DSS (Retail/E-commerce)
    if any(x in industria_lower for x in ['retail', 'ecommerce', 'payment']):
        regulaciones.append('PCI-DSS')
    
    # HIPAA (Healthcare)
    if any(x in industria_lower for x in ['healthcare', 'hospital', 'medical']):
        regulaciones.append('HIPAA')
    
    # SOX (Finance)
    if any(x in industria_lower for x in ['finance', 'banking', 'insurance']):
        regulaciones.append('SOX')
    
    return regulaciones


def derivar_contexto(empresa: EmpresaFuente) -> ContextoEmpresarial:
    """
    Deriva ContextoEmpresarial completo desde EmpresaFuente.
    Interpretación contextual, NO datos técnicos.
    """
    estado = derivar_estado_organizacional(empresa)
    presion = derivar_presion_externa(empresa)
    
    # Ritmo de cambio
    ritmo = "lento"
    if empresa.crecimiento_empleados_12m:
        if abs(empresa.crecimiento_empleados_12m) > 30:
            ritmo = "acelerado"
        elif abs(empresa.crecimiento_empleados_12m) > 10:
            ritmo = "moderado"
    
    # Señales de inversión
    señales = []
    if empresa.funding_reciente:
        señales.append("funding")
    if empresa.crecimiento_empleados_12m and empresa.crecimiento_empleados_12m > 15:
        señales.append("hiring")
    
    # Madurez digital (básica por tamaño)
    madurez = "en_desarrollo"
    if "1000+" in empresa.empleados_rango or "5000+" in empresa.empleados_rango:
        madurez = "madura"
    elif empresa.empleados_rango in ["1-10", "11-50"]:
        madurez = "emergente"
    
    return ContextoEmpresarial(
        dominio=empresa.dominio,
        estado_organizacional=estado,
        ritmo_cambio=ritmo,
        presion_externa=presion,
        señales_inversion=señales,
        madurez_digital=madurez,
        industria_detectada=empresa.industria,
        regulaciones_aplicables=detectar_regulaciones(empresa),
        snapshot_origen=empresa.snapshot_id,
        timestamp_derivacion=datetime.utcnow(),
        confianza_derivacion=0.8  # Alta confianza con datos de ZoomInfo
    )


# ============================================================================
# PIPELINE COMPLETO
# ============================================================================

def procesar_ingesta_zoominfo(ruta_excel: str) -> tuple[Snapshot, List[EmpresaFuente], List[ContextoEmpresarial]]:
    """
    Pipeline completo de ingesta:
    Excel → Snapshot → EmpresaFuente → ContextoEmpresarial
    
    Respeta el orden de capas inquebrantable.
    """
    print(f"\n{'='*60}")
    print("INGESTA ZOOMINFO - ProspectScan")
    print(f"{'='*60}\n")
    
    # Capa 1: Ingesta Masiva
    print("📥 CAPA 1: Cargando Excel de ZoomInfo...")
    df = parsear_excel_zoominfo(ruta_excel)
    snapshot = crear_snapshot(df)
    print(f"   Snapshot creado: {snapshot.snapshot_id}")
    print(f"   Checksum: {snapshot.checksum[:16]}...")
    
    # Extracción
    print("\n📦 Extrayendo empresas desde snapshot...")
    empresas_fuente = extraer_empresas(snapshot)
    
    # Capa 2: Derivación de Contexto
    print("\n🔄 CAPA 2: Derivando contexto empresarial...")
    contextos = [derivar_contexto(emp) for emp in empresas_fuente]
    print(f"   {len(contextos)} contextos derivados")
    
    # Resumen
    print(f"\n{'='*60}")
    print("✅ INGESTA COMPLETADA")
    print(f"{'='*60}")
    print(f"Empresas: {len(empresas_fuente)}")
    print(f"Contextos: {len(contextos)}")
    print(f"\nDistribución de estados:")
    for estado in EstadoOrganizacional:
        count = sum(1 for c in contextos if c.estado_organizacional == estado)
        if count > 0:
            print(f"  {estado.value}: {count}")
    
    return snapshot, empresas_fuente, contextos


# ============================================================================
# EJEMPLO DE USO
# ============================================================================

if __name__ == "__main__":
    # Ejemplo: procesar Excel de ZoomInfo
    ruta = "data/zoominfo_export.xlsx"  # Ruta al Excel
    
    if Path(ruta).exists():
        snapshot, empresas, contextos = procesar_ingesta_zoominfo(ruta)
        
        # Mostrar ejemplo
        if contextos:
            print(f"\n📊 Ejemplo de contexto derivado:")
            ctx = contextos[0]
            print(f"   Dominio: {ctx.dominio}")
            print(f"   Estado: {ctx.estado_organizacional.value}")
            print(f"   Presión: {ctx.presion_externa.value}")
            print(f"   Regulaciones: {', '.join(ctx.regulaciones_aplicables)}")
    else:
        print(f"❌ Archivo no encontrado: {ruta}")
        print("\n💡 Para usar este adaptador:")
        print("   1. Exporta un reporte de ZoomInfo a Excel")
        print("   2. Guárdalo en data/zoominfo_export.xlsx")
        print("   3. Ejecuta este script")
