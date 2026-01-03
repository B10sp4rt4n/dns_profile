"""
ProspectScan - Cache de dominios en Neon PostgreSQL
Solo analiza dominios nuevos o con cache vencido (TTL configurable).
"""

import os
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
import streamlit as st

# TTL por defecto: 7 días
CACHE_TTL_DAYS = int(os.environ.get("PROSPECTSCAN_CACHE_TTL_DAYS", "7"))

# Columnas del contrato df_resultados
DF_COLUMNS = [
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

# SQL para crear la tabla (ejecutar una vez en Neon)
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS dominios_cache (
    dominio             TEXT PRIMARY KEY,
    postura_identidad   TEXT,
    postura_exposicion  TEXT,
    postura_general     TEXT,
    correo_proveedor    TEXT,
    correo_gateway      TEXT,
    correo_envio        TEXT,
    spf_estado          TEXT,
    dmarc_estado        TEXT,
    https_estado        TEXT,
    cdn_waf             TEXT,
    hsts                BOOLEAN,
    csp                 BOOLEAN,
    dominio_antiguedad  TEXT,
    updated_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dominios_updated ON dominios_cache(updated_at);
CREATE INDEX IF NOT EXISTS idx_dominios_postura ON dominios_cache(postura_general);
"""


def _get_connection():
    """Obtiene conexión a Neon desde secrets o env."""
    try:
        import psycopg2
    except ImportError:
        return None

    # Intentar desde Streamlit secrets primero
    db_url = None
    try:
        # Streamlit secrets se accede como diccionario o atributo
        if "DATABASE_URL" in st.secrets:
            db_url = st.secrets["DATABASE_URL"]
        elif "NEON_DATABASE_URL" in st.secrets:
            db_url = st.secrets["NEON_DATABASE_URL"]
    except Exception:
        pass

    # Fallback a variable de entorno
    if not db_url:
        db_url = os.environ.get("DATABASE_URL") or os.environ.get("NEON_DATABASE_URL")

    if not db_url:
        return None

    try:
        return psycopg2.connect(db_url, connect_timeout=10)
    except Exception as e:
        st.warning(f"No se pudo conectar a Neon: {e}")
        return None


def init_db():
    """Crea la tabla si no existe."""
    conn = _get_connection()
    if not conn:
        return False

    try:
        with conn.cursor() as cur:
            cur.execute(CREATE_TABLE_SQL)
        conn.commit()
        return True
    except Exception as e:
        st.warning(f"Error inicializando BD: {e}")
        return False
    finally:
        conn.close()


def get_cached_dominios(dominios: List[str]) -> Tuple[pd.DataFrame, List[str]]:
    """
    Busca dominios en cache.
    Retorna: (df_cacheados, dominios_pendientes)
    - df_cacheados: DataFrame con los dominios que están en cache y no han vencido
    - dominios_pendientes: lista de dominios que hay que analizar
    """
    conn = _get_connection()
    if not conn or not dominios:
        return pd.DataFrame(columns=DF_COLUMNS), list(dominios)

    try:
        cutoff = datetime.now() - timedelta(days=CACHE_TTL_DAYS)
        placeholders = ",".join(["%s"] * len(dominios))

        query = f"""
            SELECT dominio, postura_identidad, postura_exposicion, postura_general,
                   correo_proveedor, correo_gateway, correo_envio, spf_estado,
                   dmarc_estado, https_estado, cdn_waf, hsts, csp, dominio_antiguedad
            FROM dominios_cache
            WHERE dominio IN ({placeholders})
              AND updated_at > %s
        """

        with conn.cursor() as cur:
            cur.execute(query, tuple(dominios) + (cutoff,))
            rows = cur.fetchall()

        if not rows:
            return pd.DataFrame(columns=DF_COLUMNS), list(dominios)

        df_cached = pd.DataFrame(rows, columns=DF_COLUMNS)
        cached_set = set(df_cached["dominio"].tolist())
        pendientes = [d for d in dominios if d not in cached_set]

        return df_cached, pendientes

    except Exception as e:
        st.warning(f"Error leyendo cache: {e}")
        return pd.DataFrame(columns=DF_COLUMNS), list(dominios)
    finally:
        conn.close()


def save_to_cache(df: pd.DataFrame):
    """Guarda/actualiza dominios en cache."""
    conn = _get_connection()
    if not conn or df is None or df.empty:
        return

    try:
        with conn.cursor() as cur:
            for _, row in df.iterrows():
                cur.execute("""
                    INSERT INTO dominios_cache (
                        dominio, postura_identidad, postura_exposicion, postura_general,
                        correo_proveedor, correo_gateway, correo_envio, spf_estado,
                        dmarc_estado, https_estado, cdn_waf, hsts, csp, dominio_antiguedad,
                        updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (dominio) DO UPDATE SET
                        postura_identidad = EXCLUDED.postura_identidad,
                        postura_exposicion = EXCLUDED.postura_exposicion,
                        postura_general = EXCLUDED.postura_general,
                        correo_proveedor = EXCLUDED.correo_proveedor,
                        correo_gateway = EXCLUDED.correo_gateway,
                        correo_envio = EXCLUDED.correo_envio,
                        spf_estado = EXCLUDED.spf_estado,
                        dmarc_estado = EXCLUDED.dmarc_estado,
                        https_estado = EXCLUDED.https_estado,
                        cdn_waf = EXCLUDED.cdn_waf,
                        hsts = EXCLUDED.hsts,
                        csp = EXCLUDED.csp,
                        dominio_antiguedad = EXCLUDED.dominio_antiguedad,
                        updated_at = NOW()
                """, (
                    row["dominio"],
                    row["postura_identidad"],
                    row["postura_exposicion"],
                    row["postura_general"],
                    row["correo_proveedor"],
                    row["correo_gateway"],
                    row["correo_envio"],
                    row["spf_estado"],
                    row["dmarc_estado"],
                    row["https_estado"],
                    row["cdn_waf"],
                    bool(row["hsts"]),
                    bool(row["csp"]),
                    row["dominio_antiguedad"],
                ))
        conn.commit()
    except Exception as e:
        st.warning(f"Error guardando en cache: {e}")
    finally:
        conn.close()


def query_all_cached(filtros: Optional[dict] = None) -> pd.DataFrame:
    """
    Consulta todos los dominios en cache con filtros opcionales.
    Ideal para reportes rápidos sin re-análisis.

    filtros = {
        "postura_general": "Básica",
        "correo_proveedor": "Microsoft 365",
        ...
    }
    """
    conn = _get_connection()
    if not conn:
        return pd.DataFrame(columns=DF_COLUMNS)

    try:
        query = """
            SELECT dominio, postura_identidad, postura_exposicion, postura_general,
                   correo_proveedor, correo_gateway, correo_envio, spf_estado,
                   dmarc_estado, https_estado, cdn_waf, hsts, csp, dominio_antiguedad
            FROM dominios_cache
        """
        params = []

        if filtros:
            conditions = []
            for col, val in filtros.items():
                if col in DF_COLUMNS and val:
                    conditions.append(f"{col} = %s")
                    params.append(val)
            if conditions:
                query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY dominio"

        with conn.cursor() as cur:
            cur.execute(query, tuple(params))
            rows = cur.fetchall()

        return pd.DataFrame(rows, columns=DF_COLUMNS) if rows else pd.DataFrame(columns=DF_COLUMNS)

    except Exception as e:
        st.warning(f"Error consultando cache: {e}")
        return pd.DataFrame(columns=DF_COLUMNS)
    finally:
        conn.close()


def get_cache_stats() -> dict:
    """Estadísticas del cache para mostrar en UI."""
    conn = _get_connection()
    if not conn:
        return {"connected": False}

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*), MAX(updated_at) FROM dominios_cache")
            total, last_update = cur.fetchone()

            cutoff = datetime.now() - timedelta(days=CACHE_TTL_DAYS)
            cur.execute("SELECT COUNT(*) FROM dominios_cache WHERE updated_at > %s", (cutoff,))
            fresh = cur.fetchone()[0]

        return {
            "connected": True,
            "total": total or 0,
            "fresh": fresh or 0,
            "stale": (total or 0) - (fresh or 0),
            "last_update": last_update,
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}
    finally:
        conn.close()


def get_single_domain(dominio: str) -> Optional[pd.Series]:
    """
    Busca UN dominio en cache.
    Retorna la fila como pd.Series si existe y no está vencido, None si no.
    """
    conn = _get_connection()
    if not conn or not dominio:
        return None

    try:
        cutoff = datetime.now() - timedelta(days=CACHE_TTL_DAYS)

        query = """
            SELECT dominio, postura_identidad, postura_exposicion, postura_general,
                   correo_proveedor, correo_gateway, correo_envio, spf_estado,
                   dmarc_estado, https_estado, cdn_waf, hsts, csp, dominio_antiguedad
            FROM dominios_cache
            WHERE dominio = %s
              AND updated_at > %s
        """

        with conn.cursor() as cur:
            cur.execute(query, (dominio.lower().strip(), cutoff))
            row = cur.fetchone()

        if row:
            return pd.Series(dict(zip(DF_COLUMNS, row)))
        return None

    except Exception:
        return None
    finally:
        conn.close()
