import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import './ZoomInfoUpload.css';

/**
 * Componente para subir archivos Excel de ZoomInfo
 * Capa 1+2: Ingesta → Contexto Empresarial
 */
const ZoomInfoUpload = ({ onUploadSuccess }) => {
  const [isUploading, setIsUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [error, setError] = useState(null);

  const onDrop = useCallback(async (acceptedFiles) => {
    const file = acceptedFiles[0];
    if (!file) {
      console.log('No file selected');
      return;
    }

    // Validar que sea Excel
    if (!file.name.match(/\.(xlsx|xls)$/)) {
      const errorMsg = 'Solo se aceptan archivos Excel (.xlsx, .xls)';
      console.error('Invalid file type:', file.name);
      setError(errorMsg);
      return;
    }

    console.log('Starting upload:', file.name, file.size, 'bytes');
    setIsUploading(true);
    setError(null);
    setUploadResult(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      console.log('Sending POST to /api/ingesta/upload');
      const response = await fetch('http://localhost:8000/api/ingesta/upload', {
        method: 'POST',
        body: formData,
      });

      console.log('Response status:', response.status);

      if (!response.ok) {
        const errorText = await response.text();
        console.error('Upload failed:', response.status, errorText);
        throw new Error(`Error ${response.status}: ${errorText || response.statusText}`);
      }

      const data = await response.json();
      console.log('Upload successful:', data);
      setUploadResult(data);
      
      // Notificar al componente padre
      if (onUploadSuccess) {
        onUploadSuccess(data);
      }
    } catch (err) {
      console.error('Upload error:', err);
      setError(err.message || 'Error al subir archivo');
    } finally {
      setIsUploading(false);
    }
  }, [onUploadSuccess]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
      'application/vnd.ms-excel': ['.xls']
    },
    maxFiles: 1
  });

  return (
    <div className="zoominfo-upload">
      <div className="upload-header">
        <h2>📤 Ingesta ZoomInfo</h2>
        <p>Sube un reporte Excel de ZoomInfo para iniciar el análisis</p>
        <div className="debug-info">
          <small>🔧 Debug: API = http://localhost:8000 | Estado: {isUploading ? 'Subiendo...' : 'Listo'}</small>
        </div>
      </div>

      <div 
        {...getRootProps()} 
        className={`dropzone ${isDragActive ? 'active' : ''} ${isUploading ? 'uploading' : ''}`}
      >
        <input {...getInputProps()} />
        
        {isUploading ? (
          <div className="upload-loading">
            <div className="spinner"></div>
            <p>Procesando archivo...</p>
            <small>Esto puede tomar unos segundos</small>
          </div>
        ) : (
          <>
            <div className="upload-icon">📊</div>
            <p className="upload-text">
              {isDragActive 
                ? 'Suelta el archivo aquí...' 
                : 'Arrastra un archivo Excel o haz clic para seleccionar'}
            </p>
            <small className="upload-hint">Formatos: .xlsx, .xls | Máximo: 1000 empresas</small>
          </>
        )}
      </div>

      {error && (
        <div className="upload-error">
          <span className="error-icon">⚠️</span>
          <div className="error-content">
            <p><strong>Error al subir archivo:</strong></p>
            <p>{error}</p>
            <button 
              className="btn-retry" 
              onClick={() => {
                setError(null);
                setUploadResult(null);
              }}
            >
              🔄 Reintentar
            </button>
          </div>
        </div>
      )}

      {uploadResult && (
        <div className="upload-success">
          <div className="success-header">
            <span className="success-icon">✅</span>
            <h3>Snapshot Creado</h3>
          </div>
          
          <div className="success-details">
            <div className="detail-row">
              <span className="label">Snapshot ID:</span>
              <code>{uploadResult.snapshot_id}</code>
            </div>
            <div className="detail-row">
              <span className="label">Empresas procesadas:</span>
              <strong>{uploadResult.empresas_count}</strong>
            </div>
            <div className="detail-row">
              <span className="label">Timestamp:</span>
              <span>{new Date(uploadResult.timestamp).toLocaleString('es-MX')}</span>
            </div>
          </div>

          <div className="dominios-list">
            <h4>🌐 Dominios extraídos ({uploadResult.dominios.length})</h4>
            <div className="dominios-grid">
              {uploadResult.dominios.map((dominio, idx) => (
                <div key={idx} className="dominio-chip">{dominio}</div>
              ))}
            </div>
          </div>

          <div className="next-step">
            <p>✨ Ahora puedes ejecutar el cruce semántico</p>
          </div>
        </div>
      )}

      {uploadResult && (
        <div className="upload-info">
          <h4>📋 Columnas soportadas del Excel ZoomInfo:</h4>
          <ul className="columns-list">
            <li><code>Company Name</code> / <code>company_name</code></li>
            <li><code>Website</code> / <code>website</code></li>
            <li><code>Industry</code> / <code>industry</code></li>
            <li><code>Employees</code> / <code>employee_range</code></li>
            <li><code>Revenue</code> / <code>revenue_range</code></li>
            <li><code>Employee Growth (YoY)</code></li>
            <li><code>Technologies</code></li>
          </ul>
        </div>
      )}
    </div>
  );
};

export default ZoomInfoUpload;
