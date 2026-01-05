import React from 'react';
import { getScoreColor, getSecurityColor, generateDomainInsights } from '../utils/domainLogic';

/**
 * Detalle contextual de un dominio seleccionado
 * Se muestra inline, no como popup invasivo
 * Mantiene el contexto global mientras explora el detalle
 */
const DomainDetail = ({ domain, onClose, className = '' }) => {
  if (!domain) {
    return null;
  }

  const scoreColor = getScoreColor(domain.score);
  const identityColor = getSecurityColor(domain.identity_level);
  const exposureColor = getSecurityColor(domain.exposure_level);
  const generalColor = getSecurityColor(domain.general_level);
  
  // Punto de integración IA: Insights automáticos
  const insights = generateDomainInsights(domain);

  return (
    <div className={`domain-detail ${className}`}>
      <div className="detail-header">
        <div className="detail-title">
          <h3>{domain.domain}</h3>
          <div 
            className="detail-score"
            style={{
              backgroundColor: scoreColor.bg,
              color: scoreColor.text
            }}
          >
            Score: {domain.score}
          </div>
        </div>
        <button 
          className="close-detail"
          onClick={onClose}
          title="Cerrar detalle"
        >
          ✕
        </button>
      </div>

      <div className="detail-body">
        {/* Métricas principales */}
        <div className="detail-section metrics-section">
          <h4>Métricas de Seguridad</h4>
          <div className="metrics-grid">
            <div className="metric-card">
              <div className="metric-label">Identity Level</div>
              <div 
                className="metric-value"
                style={{
                  backgroundColor: identityColor.bg,
                  color: identityColor.text
                }}
              >
                {domain.identity_level}
              </div>
              <div className="metric-description">
                Nivel de autenticación e identidad
              </div>
            </div>

            <div className="metric-card">
              <div className="metric-label">Exposure Level</div>
              <div 
                className="metric-value"
                style={{
                  backgroundColor: exposureColor.bg,
                  color: exposureColor.text
                }}
              >
                {domain.exposure_level}
              </div>
              <div className="metric-description">
                Nivel de exposición pública
              </div>
            </div>

            <div className="metric-card">
              <div className="metric-label">General Level</div>
              <div 
                className="metric-value"
                style={{
                  backgroundColor: generalColor.bg,
                  color: generalColor.text
                }}
              >
                {domain.general_level}
              </div>
              <div className="metric-description">
                Nivel general de seguridad
              </div>
            </div>
          </div>
        </div>

        {/* Información adicional */}
        <div className="detail-section info-section">
          <h4>Información Técnica</h4>
          <div className="info-list">
            <div className="info-item">
              <span className="info-label">Provider:</span>
              <span className="info-value">{domain.provider}</span>
            </div>
            {domain.sector && (
              <div className="info-item">
                <span className="info-label">Sector:</span>
                <span className="info-value">{domain.sector}</span>
              </div>
            )}
            {domain.tamaño_empresa && (
              <div className="info-item">
                <span className="info-label">Tamaño:</span>
                <span className="info-value">{domain.tamaño_empresa}</span>
              </div>
            )}
          </div>
        </div>

        {/* Insights automáticos - Punto de integración IA */}
        {insights.length > 0 && (
          <div className="detail-section insights-section">
            <h4>Insights Automáticos</h4>
            <div className="insights-list">
              {insights.map((insight, idx) => (
                <div key={idx} className="insight-item">
                  {insight}
                </div>
              ))}
            </div>
            <div className="ai-badge">
              🤖 Análisis asistido por IA
            </div>
          </div>
        )}

        {/* Acciones recomendadas */}
        <div className="detail-section actions-section">
          <h4>Acciones Sugeridas</h4>
          <div className="actions-list">
            {domain.score < 70 && (
              <button className="action-btn priority">
                Generar ticket de prospección
              </button>
            )}
            <button className="action-btn secondary">
              Ver contactos LinkedIn
            </button>
            <button className="action-btn secondary">
              Exportar análisis
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DomainDetail;
