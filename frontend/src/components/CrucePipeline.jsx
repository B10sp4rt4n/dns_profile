import React, { useState } from 'react';
import './CrucePipeline.css';

/**
 * Componente para ejecutar el cruce semántico (Capas 3+4)
 * Muestra resultados priorizados con talking points
 */
const CrucePipeline = ({ snapshotId }) => {
  const [isProcessing, setIsProcessing] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [prioridadFilter, setPrioridadFilter] = useState('baja');

  const ejecutarCruce = async () => {
    if (!snapshotId) {
      setError('No hay snapshot cargado. Por favor sube un archivo ZoomInfo primero.');
      return;
    }

    setIsProcessing(true);
    setError(null);

    try {
      const response = await fetch(
        `http://localhost:8000/api/cruce/batch?snapshot_id=${snapshotId}&prioridad_minima=${prioridadFilter}`
      );

      if (!response.ok) {
        throw new Error(`Error ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsProcessing(false);
    }
  };

  const getPrioridadColor = (prioridad) => {
    const colors = {
      'critica': '#e74c3c',
      'alta': '#e67e22',
      'media': '#f39c12',
      'baja': '#2ecc71',
      'descartada': '#95a5a6'
    };
    return colors[prioridad] || '#95a5a6';
  };

  const getPrioridadEmoji = (prioridad) => {
    const emojis = {
      'critica': '🔴',
      'alta': '🟠',
      'media': '🟡',
      'baja': '🟢',
      'descartada': '⚪'
    };
    return emojis[prioridad] || '⚪';
  };

  return (
    <div className="cruce-pipeline">
      <div className="pipeline-header">
        <h2>🔄 Pipeline de Cruce Semántico</h2>
        <p>Ejecuta REGLAS_CRUCE: Contexto × Postura → Prioridad</p>
        
        {snapshotId && (
          <div className="snapshot-indicator">
            ✅ Snapshot activo: <code>{snapshotId}</code>
          </div>
        )}
      </div>

      {!snapshotId ? (
        <div className="pipeline-empty">
          <div className="empty-icon">📭</div>
          <h3>Sin datos para procesar</h3>
          <p>Ve al tab <strong>Ingesta ZoomInfo</strong> y sube un archivo Excel primero.</p>
          <p className="empty-hint">El snapshot se cargará automáticamente aquí.</p>
        </div>
      ) : (
        <>
          <div className="pipeline-controls">
            <div className="control-group">
              <label>Prioridad mínima:</label>
              <select 
                value={prioridadFilter} 
                onChange={(e) => setPrioridadFilter(e.target.value)}
                disabled={isProcessing}
              >
                <option value="critica">🔴 Crítica</option>
                <option value="alta">🟠 Alta</option>
                <option value="media">🟡 Media</option>
                <option value="baja">🟢 Baja</option>
              </select>
            </div>

            <button 
              onClick={ejecutarCruce} 
              disabled={isProcessing}
              className="btn-execute"
            >
              {isProcessing ? (
                <>
                  <span className="btn-spinner"></span>
                  Procesando...
                </>
              ) : (
                <>
                  ▶️ Ejecutar Cruce
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="pipeline-error">
              <span className="error-icon">⚠️</span>
              <span>{error}</span>
            </div>
          )}

      {results && (
        <div className="pipeline-results">
          <div className="results-summary">
            <div className="summary-card">
              <div className="card-value">{results.total_procesados}</div>
              <div className="card-label">Total Procesados</div>
            </div>
            <div className="summary-card">
              <div className="card-value">{results.total_filtrados}</div>
              <div className="card-label">Con Prioridad ≥ {prioridadFilter.toUpperCase()}</div>
            </div>
            {results.errores && results.errores.length > 0 && (
              <div className="summary-card error">
                <div className="card-value">{results.errores.length}</div>
                <div className="card-label">Errores</div>
              </div>
            )}
          </div>

          <div className="results-list">
            <h3>📊 Resultados Ordenados por Oportunidad</h3>
            
            {results.resultados.length === 0 ? (
              <div className="no-results">
                <p>No hay resultados con prioridad ≥ {prioridadFilter.toUpperCase()}</p>
                <small>Intenta con un filtro de prioridad más bajo</small>
              </div>
            ) : (
              results.resultados.map((resultado, idx) => (
                <div key={idx} className="resultado-card">
                  <div className="resultado-header">
                    <div className="header-left">
                      <span className="resultado-rank">#{idx + 1}</span>
                      <span className="resultado-emoji">
                        {getPrioridadEmoji(resultado.prioridad)}
                      </span>
                      <h4 className="resultado-dominio">{resultado.dominio}</h4>
                    </div>
                    <div className="header-right">
                      <div 
                        className="prioridad-badge"
                        style={{ backgroundColor: getPrioridadColor(resultado.prioridad) }}
                      >
                        {resultado.prioridad.toUpperCase()}
                      </div>
                      <div className="score-badge">
                        Score: {resultado.score_oportunidad}/100
                      </div>
                    </div>
                  </div>

                  <div className="resultado-body">
                    <div className="info-row">
                      <div className="info-item">
                        <span className="info-label">💰 Budget:</span>
                        <span className="info-value">
                          ${resultado.budget_estimado.min.toLocaleString()} - 
                          ${resultado.budget_estimado.max.toLocaleString()} USD
                        </span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">🔒 Postura:</span>
                        <span className="info-value">{resultado.postura.general}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">🏢 Industria:</span>
                        <span className="info-value">{resultado.contexto.industria}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">⏰ Momento:</span>
                        <span className={`info-value ${resultado.momento_oportuno ? 'oportuno' : 'no-oportuno'}`}>
                          {resultado.momento_oportuno ? '✅ Oportuno' : '❌ No oportuno'}
                        </span>
                      </div>
                    </div>

                    {resultado.razon_momento && (
                      <div className="momento-razon">
                        💡 {resultado.razon_momento}
                      </div>
                    )}

                    {resultado.factores_positivos.length > 0 && (
                      <div className="factores positivos">
                        <h5>✅ Factores Positivos:</h5>
                        <ul>
                          {resultado.factores_positivos.map((factor, i) => (
                            <li key={i}>{factor}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {resultado.factores_negativos.length > 0 && (
                      <div className="factores negativos">
                        <h5>⚠️ Factores Negativos:</h5>
                        <ul>
                          {resultado.factores_negativos.map((factor, i) => (
                            <li key={i}>{factor}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {resultado.talking_points.length > 0 && (
                      <div className="talking-points">
                        <h5>💬 Talking Points para Ventas:</h5>
                        <ol>
                          {resultado.talking_points.map((point, i) => (
                            <li key={i}>{point}</li>
                          ))}
                        </ol>
                      </div>
                    )}

                    {resultado.contexto.regulaciones && resultado.contexto.regulaciones.length > 0 && (
                      <div className="regulaciones">
                        <strong>📋 Regulaciones:</strong>
                        {resultado.contexto.regulaciones.map((reg, i) => (
                          <span key={i} className="reg-badge">{reg}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
      </>
      )}
    </div>
  );
};

export default CrucePipeline;
