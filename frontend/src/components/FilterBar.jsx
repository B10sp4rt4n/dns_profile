import React from 'react';

/**
 * Barra de filtros y búsqueda
 * Permite exploración inteligente del dataset de dominios
 */
const FilterBar = ({ 
  searchTerm, 
  onSearchChange, 
  provider, 
  onProviderChange, 
  sortBy, 
  onSortChange,
  providers = [],
  resultCount = 0,
  totalCount = 0,
  className = '' 
}) => {
  return (
    <div className={`filter-bar ${className}`}>
      <div className="filter-section search-section">
        <label htmlFor="domain-search">Buscar Dominio</label>
        <input
          id="domain-search"
          type="text"
          placeholder="Ej: empresa.com"
          value={searchTerm}
          onChange={(e) => onSearchChange(e.target.value)}
          className="search-input"
        />
        {searchTerm && (
          <button 
            className="clear-search"
            onClick={() => onSearchChange('')}
            title="Limpiar búsqueda"
          >
            ✕
          </button>
        )}
      </div>

      <div className="filter-section provider-section">
        <label htmlFor="provider-filter">Provider</label>
        <select
          id="provider-filter"
          value={provider}
          onChange={(e) => onProviderChange(e.target.value)}
          className="provider-select"
        >
          <option value="all">Todos</option>
          {providers.map(p => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
      </div>

      <div className="filter-section sort-section">
        <label htmlFor="sort-by">Ordenar por</label>
        <select
          id="sort-by"
          value={sortBy}
          onChange={(e) => onSortChange(e.target.value)}
          className="sort-select"
        >
          <option value="score-desc">Score (mayor a menor)</option>
          <option value="score-asc">Score (menor a mayor)</option>
          <option value="domain-asc">Dominio (A-Z)</option>
          <option value="domain-desc">Dominio (Z-A)</option>
        </select>
      </div>

      <div className="filter-results">
        <span className="result-count">
          {resultCount === totalCount 
            ? `${totalCount} dominios`
            : `${resultCount} de ${totalCount} dominios`
          }
        </span>
      </div>
    </div>
  );
};

export default FilterBar;
