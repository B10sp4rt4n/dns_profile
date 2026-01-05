// Configuración de API para soportar tanto localhost como Codespaces
const getApiBaseUrl = () => {
  // Si estamos en Codespaces (URL contiene .app.github.dev)
  if (window.location.hostname.includes('.app.github.dev')) {
    // Reemplazar puerto 3000 por 8000 en la URL
    const backendUrl = window.location.origin.replace('-3000.', '-8000.');
    console.log('🌐 Codespaces detectado - Backend URL:', backendUrl);
    return backendUrl;
  }
  // En desarrollo local, usar el proxy de Vite
  console.log('💻 Localhost detectado - Usando proxy de Vite');
  return '';
};

export const API_BASE_URL = getApiBaseUrl();
export const API_URL = (path) => {
  const fullUrl = `${API_BASE_URL}${path}`;
  console.log('🔗 API Request:', fullUrl);
  return fullUrl;
};
