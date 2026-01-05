import React from 'react';
import { getScoreColor } from '../utils/domainLogic';

/**
 * Vista Global - Estadísticas agregadas independientes del dominio individual
 * Muestra resumen ejecutivo del estado de seguridad de todos los dominios
 */
const GlobalSummary = ({ stats, className = '' }) => {
  if (!stats || stats.total === 0) {
    return (
      <div className={`global-summary empty ${className}`}>
        <p>No hay dominios para analizar</p>
      </div>
    );
  }

  const scoreColor = getScoreColor(stats.avgScore);

  return (
    <div className={`global-summary ${className}`}>
      <div className="summary-header">
        <h2>Resumen Global</h2>
        <span className="total-domains">{stats.total} dominios analizados</span>
      </div>

      <div className="summary-grid">
        {/* Score promedio */}
        <div className="summary-card score-card">
          <div className="card-label">Score Promedio</div>
          <div 
            className="card-value score-value"
            style={{ 
              backgroundColor: scoreColor.bg,
              color: scoreColor.text 
            }}
          >
            {stats.avgScore}
          </div>
          <div className="card-sublabel">{scoreColor.label}</div>
        </div>

        {/* Distribución por seguridad */}
        <div className="summary-card distribution-card">
          <div className="card-label">Distribución de Seguridad</div>
          <div className="distribution-bars">
            <div className="dist-item">
              <span className="dist-label">Alta</span>
              <div className="dist-bar-container">
                <div 
                  className="dist-bar high"
                  style={{ 
                    width: `${(stats.scoreDistribution.Alta / stats.total) * 100}%`,
                    backgroundColor: '#10b981'
                  }}
                />
              </div>
              <span className="dist-count">{stats.scoreDistribution.Alta}</span>
            </div>
            <div className="dist-item">
              <span className="dist-label">Media</span>
              <div className="dist-bar-container">
                <div 
                  className="dist-bar medium"
                  style={{ 
                    width: `${(stats.scoreDistribution.Media / stats.total) * 100}%`,
                    backgroundColor: '#f59e0b'
                  }}
                />
              </div>
              <span className="dist-count">{stats.scoreDistribution.Media}</span>
            </div>
            <div className="dist-item">
              <span className="dist-label">Baja</span>
              <div className="dist-bar-container">
                <div 
                  className="dist-bar low"
                  style={{ 
                    width: `${(stats.scoreDistribution.Baja / stats.total) * 100}%`,
                    backgroundColor: '#ef4444'
                  }}
                />
              </div>
              <span className="dist-count">{stats.scoreDistribution.Baja}</span>
            </div>
          </div>
        </div>

        {/* Distribución por provider */}
        <div className="summary-card provider-card">
          <div className="card-label">Distribución por Provider</div>
          <div className="provider-list">
            {Object.entries(stats.providerDistribution).map(([provider, count]) => (
              <div key={provider} className="provider-item">
                <span className="provider-name">{provider}</span>
                <span className="provider-count">{count}</span>
                <span className="provider-percentage">
                  {Math.round((count / stats.total) * 100)}%
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Niveles de seguridad */}
        <div className="summary-card levels-card">
          <div className="card-label">Niveles de Seguridad</div>
          <div className="levels-grid">
            <div className="level-section">
              <div className="level-title">Identity</div>
              {Object.entries(stats.identityDistribution).map(([level, count]) => (
                <div key={level} className="level-row">
                  <span>{level}</span>
                  <span className="level-count">{count}</span>
                </div>
              ))}
            </div>
            <div className="level-section">
              <div className="level-title">Exposure</div>
              {Object.entries(stats.exposureDistribution).map(([level, count]) => (
                <div key={level} className="level-row">
                  <span>{level}</span>
                  <span className="level-count">{count}</span>
                </div>
              ))}
            </div>
            <div className="level-section">
              <div className="level-title">General</div>
              {Object.entries(stats.generalDistribution).map(([level, count]) => (
                <div key={level} className="level-row">
                  <span>{level}</span>
                  <span className="level-count">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GlobalSummary;
