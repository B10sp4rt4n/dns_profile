/**
 * Datos de ejemplo para testing del Heatmap
 * Representa una muestra realista de dominios empresariales con diferentes perfiles de seguridad
 */

import { SecurityLevel, Provider } from '../utils/domainLogic';

export const mockDomains = [
  {
    domain: 'acme-corp.com',
    score: 85,
    identity_level: SecurityLevel.AVANZADA,
    exposure_level: SecurityLevel.AVANZADA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.MICROSOFT,
    sector: 'Tecnología',
    tamaño_empresa: 'Grande (500+)'
  },
  {
    domain: 'techstartup.io',
    score: 72,
    identity_level: SecurityLevel.AVANZADA,
    exposure_level: SecurityLevel.INTERMEDIA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.GOOGLE,
    sector: 'Tecnología',
    tamaño_empresa: 'Mediana (50-500)'
  },
  {
    domain: 'finance-solutions.com',
    score: 90,
    identity_level: SecurityLevel.AVANZADA,
    exposure_level: SecurityLevel.AVANZADA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.MICROSOFT,
    sector: 'Finanzas',
    tamaño_empresa: 'Grande (500+)'
  },
  {
    domain: 'smallbiz-consulting.com',
    score: 45,
    identity_level: SecurityLevel.INTERMEDIA,
    exposure_level: SecurityLevel.BASICA,
    general_level: SecurityLevel.INTERMEDIA,
    provider: Provider.GOOGLE,
    sector: 'Consultoría',
    tamaño_empresa: 'Pequeña (10-50)'
  },
  {
    domain: 'healthcare-provider.org',
    score: 78,
    identity_level: SecurityLevel.AVANZADA,
    exposure_level: SecurityLevel.INTERMEDIA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.MICROSOFT,
    sector: 'Salud',
    tamaño_empresa: 'Grande (500+)'
  },
  {
    domain: 'retail-online.shop',
    score: 35,
    identity_level: SecurityLevel.BASICA,
    exposure_level: SecurityLevel.BASICA,
    general_level: SecurityLevel.BASICA,
    provider: Provider.OTRO,
    sector: 'Retail',
    tamaño_empresa: 'Pequeña (10-50)'
  },
  {
    domain: 'manufacturing-co.com',
    score: 58,
    identity_level: SecurityLevel.INTERMEDIA,
    exposure_level: SecurityLevel.INTERMEDIA,
    general_level: SecurityLevel.INTERMEDIA,
    provider: Provider.MICROSOFT,
    sector: 'Manufactura',
    tamaño_empresa: 'Mediana (50-500)'
  },
  {
    domain: 'digital-agency.design',
    score: 62,
    identity_level: SecurityLevel.INTERMEDIA,
    exposure_level: SecurityLevel.INTERMEDIA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.GOOGLE,
    sector: 'Marketing',
    tamaño_empresa: 'Pequeña (10-50)'
  },
  {
    domain: 'enterprise-solutions.net',
    score: 88,
    identity_level: SecurityLevel.AVANZADA,
    exposure_level: SecurityLevel.AVANZADA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.MICROSOFT,
    sector: 'Tecnología',
    tamaño_empresa: 'Grande (500+)'
  },
  {
    domain: 'local-restaurant.com',
    score: 28,
    identity_level: SecurityLevel.BASICA,
    exposure_level: SecurityLevel.BASICA,
    general_level: SecurityLevel.BASICA,
    provider: Provider.OTRO,
    sector: 'Hospitalidad',
    tamaño_empresa: 'Micro (1-10)'
  },
  {
    domain: 'education-platform.edu',
    score: 75,
    identity_level: SecurityLevel.AVANZADA,
    exposure_level: SecurityLevel.INTERMEDIA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.GOOGLE,
    sector: 'Educación',
    tamaño_empresa: 'Mediana (50-500)'
  },
  {
    domain: 'legal-services.law',
    score: 82,
    identity_level: SecurityLevel.AVANZADA,
    exposure_level: SecurityLevel.AVANZADA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.MICROSOFT,
    sector: 'Legal',
    tamaño_empresa: 'Mediana (50-500)'
  },
  {
    domain: 'construction-builders.com',
    score: 42,
    identity_level: SecurityLevel.INTERMEDIA,
    exposure_level: SecurityLevel.BASICA,
    general_level: SecurityLevel.INTERMEDIA,
    provider: Provider.OTRO,
    sector: 'Construcción',
    tamaño_empresa: 'Mediana (50-500)'
  },
  {
    domain: 'media-production.tv',
    score: 68,
    identity_level: SecurityLevel.INTERMEDIA,
    exposure_level: SecurityLevel.AVANZADA,
    general_level: SecurityLevel.INTERMEDIA,
    provider: Provider.GOOGLE,
    sector: 'Media',
    tamaño_empresa: 'Pequeña (10-50)'
  },
  {
    domain: 'pharma-research.com',
    score: 92,
    identity_level: SecurityLevel.AVANZADA,
    exposure_level: SecurityLevel.AVANZADA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.MICROSOFT,
    sector: 'Farmacéutica',
    tamaño_empresa: 'Grande (500+)'
  },
  {
    domain: 'ecommerce-store.shop',
    score: 38,
    identity_level: SecurityLevel.BASICA,
    exposure_level: SecurityLevel.BASICA,
    general_level: SecurityLevel.INTERMEDIA,
    provider: Provider.OTRO,
    sector: 'Retail',
    tamaño_empresa: 'Pequeña (10-50)'
  },
  {
    domain: 'logistics-transport.com',
    score: 54,
    identity_level: SecurityLevel.INTERMEDIA,
    exposure_level: SecurityLevel.INTERMEDIA,
    general_level: SecurityLevel.INTERMEDIA,
    provider: Provider.MICROSOFT,
    sector: 'Logística',
    tamaño_empresa: 'Grande (500+)'
  },
  {
    domain: 'insurance-broker.com',
    score: 80,
    identity_level: SecurityLevel.AVANZADA,
    exposure_level: SecurityLevel.AVANZADA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.MICROSOFT,
    sector: 'Seguros',
    tamaño_empresa: 'Mediana (50-500)'
  },
  {
    domain: 'creative-studio.art',
    score: 48,
    identity_level: SecurityLevel.INTERMEDIA,
    exposure_level: SecurityLevel.BASICA,
    general_level: SecurityLevel.INTERMEDIA,
    provider: Provider.GOOGLE,
    sector: 'Arte y Diseño',
    tamaño_empresa: 'Micro (1-10)'
  },
  {
    domain: 'cybersecurity-firm.com',
    score: 95,
    identity_level: SecurityLevel.AVANZADA,
    exposure_level: SecurityLevel.AVANZADA,
    general_level: SecurityLevel.AVANZADA,
    provider: Provider.MICROSOFT,
    sector: 'Ciberseguridad',
    tamaño_empresa: 'Mediana (50-500)'
  }
];

/**
 * Genera dominios adicionales para testing de rendimiento
 */
export const generateMockDomains = (count = 100) => {
  const providers = [Provider.MICROSOFT, Provider.GOOGLE, Provider.OTRO];
  const levels = [SecurityLevel.BASICA, SecurityLevel.INTERMEDIA, SecurityLevel.AVANZADA];
  const sectores = ['Tecnología', 'Finanzas', 'Salud', 'Retail', 'Manufactura', 'Consultoría'];
  const tamanos = ['Micro (1-10)', 'Pequeña (10-50)', 'Mediana (50-500)', 'Grande (500+)'];
  
  const domains = [];
  
  for (let i = 0; i < count; i++) {
    const provider = providers[Math.floor(Math.random() * providers.length)];
    const identityLevel = levels[Math.floor(Math.random() * levels.length)];
    const exposureLevel = levels[Math.floor(Math.random() * levels.length)];
    const generalLevel = levels[Math.floor(Math.random() * levels.length)];
    
    // Calcular score basado en niveles
    const levelToScore = {
      [SecurityLevel.AVANZADA]: 80 + Math.floor(Math.random() * 20),
      [SecurityLevel.INTERMEDIA]: 40 + Math.floor(Math.random() * 40),
      [SecurityLevel.BASICA]: Math.floor(Math.random() * 40)
    };
    
    const avgScore = Math.floor(
      (levelToScore[identityLevel] + levelToScore[exposureLevel] + levelToScore[generalLevel]) / 3
    );
    
    domains.push({
      domain: `company-${i + 1}.com`,
      score: avgScore,
      identity_level: identityLevel,
      exposure_level: exposureLevel,
      general_level: generalLevel,
      provider,
      sector: sectores[Math.floor(Math.random() * sectores.length)],
      tamaño_empresa: tamanos[Math.floor(Math.random() * tamanos.length)]
    });
  }
  
  return domains;
};
