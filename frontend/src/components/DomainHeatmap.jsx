import React, { useState, useMemo, useEffect } from 'react';
import GlobalSummary from './GlobalSummary';
import FilterBar from './FilterBar';
import HeatmapGrid from './HeatmapGrid';
import DomainDetail from './DomainDetail';
import { 
  calculateGlobalStats, 
  filterDomains,
  generatePredictiveAlerts 
} from '../utils/domainLogic';
import { fetchAllDomains } from '../services/api';
import './DomainHeatmap.css';

/**
 * DomainHeatmap - Componente principal del Heatmap de seguridad de dominios
 * 
 * Arquitectura AUP (Aggregate, Unit, Part):
 * - Aggregate: Vista global con estadísticas agregadas
 * - Unit: Dominio individual como entidad principal
 * - Part: Subdimensiones (identity, exposure, general)
 * 
 * Permite:
 * 1. Vista global independiente (summary stats)
 * 2. Exploración por dominio individual
 * 3. Búsqueda inteligente sobre toda la lista
 * 4. Navegación sin perder contexto global
 */
const DomainHeatmap = ({ initialDomains = [] }) => {
  // Estado local
  const [domains, setDomains] = useState(initialDomains);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedProvider, setSelectedProvider] = useState('all');
  const [sortBy, setSortBy] = useState('score-desc');
  const [selectedDomain, setSelectedDomain] = useState(null);

  // Cargar dominios desde API al montar
  useEffect(() => {
    const loadDomains = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await fetchAllDomains();
        setDomains(data.length > 0 ? data : initialDomains);
      } catch (err) {
        console.error('Error loading domains from API, using mock data:', err);
        setError('No se pudo conectar con el backend. Usando datos de prueba.');
        setDomains(initialDomains);
      } finally {
        setLoading(false);
      }
    };

    loadDomains();
  }, [initialDomains]);

  // Memoización para optimización de rendimiento
  // useMemo previene recálculos innecesarios en cada render

  // Estadísticas globales (independientes de filtros)
  const globalStats = useMemo(() => {
    return calculateGlobalStats(domains);
  }, [domains]);

  // Lista de providers únicos para el filtro
  const availableProviders = useMemo(() => {
    return [...new Set(domains.map(d => d.provider))];
  }, [domains]);

  // Dominios filtrados según criterios del usuario
  const filteredDomains = useMemo(() => {
    return filterDomains(domains, {
      searchTerm,
      provider: selectedProvider,
      sortBy
    });
  }, [domains, searchTerm, selectedProvider, sortBy]);

  // Punto de integración IA: Alertas predictivas
  const predictiveAlerts = useMemo(() => {
    return generatePredictiveAlerts(filteredDomains);
  }, [filteredDomains]);

  // Handlers
  const handleDomainSelect = (domain) => {
    setSelectedDomain(domain);
  };

  const handleDetailClose = () => {
    setSelectedDomain(null);
  };

  return (
    <div className="domain-heatmap">
      {/* Header con alertas predictivas */}
      <div className="heatmap-header">
        <h1>ProspectScan - Security Heatmap</h1>
        
        {/* Loading state */}
        {loading && (
          <div className="loading-indicator">
            <span>⏳ Cargando dominios desde backend...</span>
          </div>
        )}
        
        {/* Error state */}
        {error && (
          <div className="alert alert-warning">
            ⚠️ {error}
          </div>
        )}
        
        {predictiveAlerts.length > 0 && (
          <div className="alerts-container">
            {predictiveAlerts.map((alert, idx) => (
              <div 
                key={idx} 
                className={`alert alert-${alert.severity}`}
              >
                {alert.message}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Vista Global - Estadísticas agregadas */}
      <GlobalSummary 
        stats={globalStats} 
        className="heatmap-summary"
      />

      {/* Barra de filtros y búsqueda */}
      <FilterBar
        searchTerm={searchTerm}
        onSearchChange={setSearchTerm}
        provider={selectedProvider}
        onProviderChange={setSelectedProvider}
        sortBy={sortBy}
        onSortChange={setSortBy}
        providers={availableProviders}
        resultCount={filteredDomains.length}
        totalCount={domains.length}
        className="heatmap-filters"
      />

      {/* Layout principal: Grid + Detalle */}
      <div className="heatmap-main">
        <div className={`heatmap-grid-container ${selectedDomain ? 'with-detail' : ''}`}>
          <HeatmapGrid
            domains={filteredDomains}
            onDomainSelect={handleDomainSelect}
            selectedDomain={selectedDomain}
            className="heatmap-grid"
          />
        </div>

        {/* Detalle contextual (inline, no modal) */}
        {selectedDomain && (
          <div className="heatmap-detail-container">
            <DomainDetail
              domain={selectedDomain}
              onClose={handleDetailClose}
              className="heatmap-detail"
            />
          </div>
        )}
      </div>

      {/* Footer con metadata */}
      <div className="heatmap-footer">
        <span className="footer-info">
          Última actualización: {new Date().toLocaleString('es-ES')}
        </span>
        <span className="footer-version">
          ProspectScan v1.0 | Powered by AI
        </span>
      </div>
    </div>
  );
};

export default DomainHeatmap;
