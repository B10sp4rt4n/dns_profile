/**
 * Lógica central del dominio - Sistema de scoring y niveles
 * Arquitectura AUP: Dominio como entidad principal
 */

// Enums de niveles de seguridad
export const SecurityLevel = {
  BASICA: 'Básica',
  INTERMEDIA: 'Intermedia',
  AVANZADA: 'Avanzada'
};

export const Provider = {
  MICROSOFT: 'Microsoft 365',
  GOOGLE: 'Google Workspace',
  OTRO: 'Otro'
};

/**
 * Obtiene el color semántico basado en el nivel de seguridad
 * @param {string} level - Nivel de seguridad
 * @returns {object} Colores para background y texto
 */
export const getSecurityColor = (level) => {
  const colorMap = {
    [SecurityLevel.AVANZADA]: {
      bg: '#10b981',    // verde
      text: '#ffffff',
      intensity: 'high'
    },
    [SecurityLevel.INTERMEDIA]: {
      bg: '#f59e0b',    // amarillo/naranja
      text: '#ffffff',
      intensity: 'medium'
    },
    [SecurityLevel.BASICA]: {
      bg: '#ef4444',    // rojo
      text: '#ffffff',
      intensity: 'low'
    }
  };
  
  return colorMap[level] || { bg: '#94a3b8', text: '#ffffff', intensity: 'unknown' };
};

/**
 * Obtiene el color basado en el score numérico (0-100)
 * @param {number} score - Puntuación del dominio
 * @returns {object} Colores para background y texto
 */
export const getScoreColor = (score) => {
  if (score >= 70) {
    return { bg: '#10b981', text: '#ffffff', label: 'Alta' };  // verde
  } else if (score >= 40) {
    return { bg: '#f59e0b', text: '#ffffff', label: 'Media' }; // amarillo
  } else {
    return { bg: '#ef4444', text: '#ffffff', label: 'Baja' };  // rojo
  }
};

/**
 * Clasifica el score en categoría (Alta/Media/Baja)
 * @param {number} score - Puntuación del dominio
 * @returns {string} Categoría de seguridad
 */
export const getScoreCategory = (score) => {
  if (score >= 70) return 'Alta';
  if (score >= 40) return 'Media';
  return 'Baja';
};

/**
 * Calcula estadísticas agregadas de una lista de dominios
 * @param {Array} domains - Lista de dominios
 * @returns {object} Estadísticas globales
 */
export const calculateGlobalStats = (domains) => {
  if (!domains || domains.length === 0) {
    return {
      total: 0,
      avgScore: 0,
      scoreDistribution: { Alta: 0, Media: 0, Baja: 0 },
      providerDistribution: {},
      identityDistribution: {},
      exposureDistribution: {},
      generalDistribution: {}
    };
  }

  const total = domains.length;
  const avgScore = domains.reduce((sum, d) => sum + d.score, 0) / total;

  // Distribución por score category
  const scoreDistribution = domains.reduce((acc, d) => {
    const category = getScoreCategory(d.score);
    acc[category] = (acc[category] || 0) + 1;
    return acc;
  }, { Alta: 0, Media: 0, Baja: 0 });

  // Distribución por provider
  const providerDistribution = domains.reduce((acc, d) => {
    acc[d.provider] = (acc[d.provider] || 0) + 1;
    return acc;
  }, {});

  // Distribución por niveles
  const identityDistribution = domains.reduce((acc, d) => {
    acc[d.identity_level] = (acc[d.identity_level] || 0) + 1;
    return acc;
  }, {});

  const exposureDistribution = domains.reduce((acc, d) => {
    acc[d.exposure_level] = (acc[d.exposure_level] || 0) + 1;
    return acc;
  }, {});

  const generalDistribution = domains.reduce((acc, d) => {
    acc[d.general_level] = (acc[d.general_level] || 0) + 1;
    return acc;
  }, {});

  return {
    total,
    avgScore: Math.round(avgScore * 10) / 10,
    scoreDistribution,
    providerDistribution,
    identityDistribution,
    exposureDistribution,
    generalDistribution
  };
};

/**
 * Filtra dominios basándose en criterios
 * @param {Array} domains - Lista de dominios
 * @param {object} filters - Objeto con filtros { searchTerm, provider, sortBy }
 * @returns {Array} Dominios filtrados
 */
export const filterDomains = (domains, filters) => {
  if (!domains) return [];

  let filtered = [...domains];

  // Filtro por búsqueda (substring en dominio)
  if (filters.searchTerm) {
    const term = filters.searchTerm.toLowerCase();
    filtered = filtered.filter(d => 
      d.domain.toLowerCase().includes(term)
    );
  }

  // Filtro por provider
  if (filters.provider && filters.provider !== 'all') {
    filtered = filtered.filter(d => d.provider === filters.provider);
  }

  // Ordenamiento
  if (filters.sortBy) {
    filtered.sort((a, b) => {
      switch (filters.sortBy) {
        case 'score-desc':
          return b.score - a.score;
        case 'score-asc':
          return a.score - b.score;
        case 'domain-asc':
          return a.domain.localeCompare(b.domain);
        case 'domain-desc':
          return b.domain.localeCompare(a.domain);
        default:
          return 0;
      }
    });
  }

  return filtered;
};

/**
 * Punto de integración IA: Scoring inteligente
 * Actualmente calcula score basado en reglas, pero puede reemplazarse
 * con un modelo ML que considere múltiples dimensiones y contexto
 */
export const calculateIntelligentScore = (domain) => {
  // TODO: Integrar modelo ML para scoring dinámico
  // Considera: identity_level, exposure_level, general_level, provider, sector, etc.
  return domain.score; // Por ahora retorna el score existente
};

/**
 * Punto de integración IA: Insights automáticos
 * Analiza un dominio y genera insights accionables
 */
export const generateDomainInsights = (domain) => {
  // TODO: Integrar LLM para generar insights personalizados
  const insights = [];
  
  if (domain.score < 40) {
    insights.push('⚠️ Vulnerabilidad crítica detectada');
  }
  
  if (domain.identity_level === SecurityLevel.BASICA) {
    insights.push('🔐 Autenticación básica - recomendar MFA');
  }
  
  if (domain.exposure_level === SecurityLevel.BASICA) {
    insights.push('🌐 Alta exposición pública detectada');
  }

  return insights;
};

/**
 * Punto de integración IA: Alertas predictivas
 * Detecta patrones y predice posibles problemas
 */
export const generatePredictiveAlerts = (domains) => {
  // TODO: Integrar modelo de detección de anomalías
  const alerts = [];
  
  const lowScoreDomains = domains.filter(d => d.score < 30).length;
  if (lowScoreDomains > 0) {
    alerts.push({
      severity: 'high',
      message: `${lowScoreDomains} dominios con riesgo crítico`,
      actionable: true
    });
  }

  return alerts;
};
