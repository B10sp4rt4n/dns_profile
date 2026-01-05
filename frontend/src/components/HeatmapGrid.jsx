import React from 'react';
import { getScoreColor, getSecurityColor } from '../utils/domainLogic';

/**
 * Grid principal del Heatmap
 * Representa dominios como filas con sus métricas de seguridad
 * Colores semánticos coherentes basados en niveles
 */
const HeatmapGrid = ({ domains, onDomainSelect, selectedDomain, className = '' }) => {
  if (!domains || domains.length === 0) {
    return (
      <div className={`heatmap-grid empty ${className}`}>
        <p>No hay dominios que mostrar con los filtros actuales</p>
      </div>
    );
  }

  return (
    <div className={`heatmap-grid ${className}`}>
      <table className="heatmap-table">
        <thead>
          <tr>
            <th className="col-domain">Dominio</th>
            <th className="col-score">Score</th>
            <th className="col-identity">Identity</th>
            <th className="col-exposure">Exposure</th>
            <th className="col-general">General</th>
            <th className="col-provider">Provider</th>
          </tr>
        </thead>
        <tbody>
          {domains.map((domain) => {
            const scoreColor = getScoreColor(domain.score);
            const identityColor = getSecurityColor(domain.identity_level);
            const exposureColor = getSecurityColor(domain.exposure_level);
            const generalColor = getSecurityColor(domain.general_level);
            const isSelected = selectedDomain?.domain === domain.domain;

            return (
              <tr 
                key={domain.domain}
                className={`domain-row ${isSelected ? 'selected' : ''}`}
                onClick={() => onDomainSelect(domain)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    onDomainSelect(domain);
                  }
                }}
              >
                <td className="col-domain">
                  <span className="domain-name">{domain.domain}</span>
                </td>
                <td className="col-score">
                  <div 
                    className="score-badge"
                    style={{
                      backgroundColor: scoreColor.bg,
                      color: scoreColor.text
                    }}
                  >
                    {domain.score}
                  </div>
                </td>
                <td className="col-identity">
                  <div 
                    className="level-badge"
                    style={{
                      backgroundColor: identityColor.bg,
                      color: identityColor.text
                    }}
                  >
                    {domain.identity_level}
                  </div>
                </td>
                <td className="col-exposure">
                  <div 
                    className="level-badge"
                    style={{
                      backgroundColor: exposureColor.bg,
                      color: exposureColor.text
                    }}
                  >
                    {domain.exposure_level}
                  </div>
                </td>
                <td className="col-general">
                  <div 
                    className="level-badge"
                    style={{
                      backgroundColor: generalColor.bg,
                      color: generalColor.text
                    }}
                  >
                    {domain.general_level}
                  </div>
                </td>
                <td className="col-provider">
                  <span className="provider-text">{domain.provider}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default HeatmapGrid;
