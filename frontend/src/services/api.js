/**
 * API Service para conectar frontend con backend FastAPI
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

/**
 * Obtiene todos los dominios analizados desde el cache
 */
export async function fetchAllDomains() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/domains`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching domains:', error);
    throw error;
  }
}

/**
 * Analiza un dominio individual
 */
export async function analyzeSingleDomain(domain) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze/domain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ domain }),
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error analyzing domain:', error);
    throw error;
  }
}

/**
 * Analiza múltiples dominios en paralelo
 */
export async function analyzeBulkDomains(domains) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze/bulk`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ domains }),
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error analyzing bulk domains:', error);
    throw error;
  }
}

/**
 * Analiza dominios desde una lista de emails
 */
export async function analyzeFromEmails(emails) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze/emails`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ emails }),
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error analyzing emails:', error);
    throw error;
  }
}

/**
 * Obtiene estadísticas agregadas
 */
export async function fetchStatistics() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/stats`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching statistics:', error);
    throw error;
  }
}

/**
 * Health check de la API
 */
export async function checkHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/health`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error checking health:', error);
    throw error;
  }
}
