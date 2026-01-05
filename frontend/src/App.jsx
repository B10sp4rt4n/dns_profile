import React from 'react';
import DomainHeatmap from './components/DomainHeatmap';
import { mockDomains } from './utils/mockData';

/**
 * App principal - Entry point del Heatmap
 * En producción, los datos vendrían de una API backend
 */
function App() {
  return (
    <div className="App">
      <DomainHeatmap initialDomains={mockDomains} />
    </div>
  );
}

export default App;
