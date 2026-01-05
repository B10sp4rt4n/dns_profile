import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import DomainHeatmap from './components/DomainHeatmap';
import ZoomInfoUpload from './components/ZoomInfoUpload';
import CrucePipeline from './components/CrucePipeline';
import { mockDomains } from './utils/mockData';
import { API_URL, API_BASE_URL } from './config';
import './App.css';

/**
 * App principal - ProspectScan Unificado
 * Combina Heatmap + Ingesta ZoomInfo + Pipeline de Cruce
 */
function App() {
  const [currentSnapshot, setCurrentSnapshot] = useState(null);
  const [backendStatus, setBackendStatus] = useState({ connected: false, loading: true });

  const handleUploadSuccess = (uploadResult) => {
    setCurrentSnapshot(uploadResult.snapshot_id);
  };

  // Verificar conexión al backend al cargar
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const response = await fetch(API_URL('/api/health'));
        if (response.ok) {
          const data = await response.json();
          console.log('✅ Backend conectado:', data);
          setBackendStatus({ connected: true, loading: false, data });
        } else {
          console.error('❌ Backend respondió con error:', response.status);
          setBackendStatus({ connected: false, loading: false, error: response.status });
        }
      } catch (error) {
        console.error('❌ Error conectando al backend:', error.message);
        setBackendStatus({ connected: false, loading: false, error: error.message });
      }
    };
    
    checkBackend();
  }, []);

  return (
    <Router>
      <div className="App">
        <nav className="app-nav">
          <div className="nav-brand">
            <h1>🎯 ProspectScan</h1>
            <p className="nav-subtitle">Contextual Decision Intelligence</p>
          </div>
          <div className="nav-links">
            <Link to="/ingesta" className="nav-link">
              📤 Ingesta ZoomInfo
            </Link>
            <Link to="/cruce" className="nav-link">
              🔄 Pipeline Cruce
            </Link>
            <Link to="/heatmap" className="nav-link">
              🗺️ Heatmap
            </Link>
          </div>
          <div className="nav-status">
            {backendStatus.loading ? (
              <span className="status-badge loading">🔄 Conectando...</span>
            ) : backendStatus.connected ? (
              <span className="status-badge connected" title={`Cache: ${backendStatus.data?.cache_stats?.total || 0} dominios`}>
                ✅ Backend OK
              </span>
            ) : (
              <span className="status-badge disconnected" title={`Error: ${backendStatus.error}`}>
                ❌ Backend offline
              </span>
            )}
          </div>
        </nav>

        {!backendStatus.loading && !backendStatus.connected && (
          <div className="connection-alert">
            <strong>⚠️ No se puede conectar al backend</strong>
            <p>Backend URL: <code>{API_BASE_URL || 'localhost (via proxy)'}</code></p>
            <p>Error: {backendStatus.error}</p>
            <button onClick={() => window.location.reload()}>🔄 Reintentar</button>
          </div>
        )}

        <main className="app-main">
          <Routes>
            <Route path="/" element={<Navigate to="/ingesta" replace />} />
            
            <Route 
              path="/ingesta" 
              element={<ZoomInfoUpload onUploadSuccess={handleUploadSuccess} />} 
            />
            
            <Route 
              path="/cruce" 
              element={<CrucePipeline snapshotId={currentSnapshot} />} 
            />
            
            <Route 
              path="/heatmap" 
              element={<DomainHeatmap initialDomains={mockDomains} />} 
            />
          </Routes>
        </main>

        <footer className="app-footer">
          <p>ProspectScan v1.0 - Enero 2026 | 
            <a href="/docs" target="_blank"> Documentación</a> | 
            <a href="https://github.com/B10sp4rt4n/ProspectScan" target="_blank"> GitHub</a>
          </p>
        </footer>
      </div>
    </Router>
  );
}

export default App;
