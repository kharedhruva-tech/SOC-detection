const getHostname = () => {
  if (typeof window === 'undefined') return '127.0.0.1';
  return window.location.hostname === 'localhost' ? '127.0.0.1' : window.location.hostname;
};

const host = getHostname();

const API_BASE_URL = typeof window !== 'undefined' 
  ? (window.location.protocol === 'https:' ? `https://${window.location.host}/api/v1` : `http://${host}:8002/api/v1`)
  : 'http://127.0.0.1:8002/api/v1';

const WS_BASE_URL = typeof window !== 'undefined'
  ? (window.location.protocol === 'https:' ? `wss://${window.location.host}/ws/alerts` : `ws://${host}:8002/ws/alerts`)
  : 'ws://127.0.0.1:8002/ws/alerts';

export { API_BASE_URL, WS_BASE_URL };


const getHeaders = () => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('soc_token');
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }
  return headers;
};

export const api = {
  async get(endpoint: string) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (response.status === 401) {
      handleUnauthorized();
    }
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'API request failed' }));
      throw new Error(err.detail || 'API request failed');
    }
    return response.json();
  },

  async post(endpoint: string, data?: any) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: getHeaders(),
      body: data ? JSON.stringify(data) : undefined,
    });
    if (response.status === 401) {
      handleUnauthorized();
    }
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'API request failed' }));
      throw new Error(err.detail || 'API request failed');
    }
    return response.json();
  },

  async postFormData(endpoint: string, formData: FormData) {
    const headers: Record<string, string> = {};
    if (typeof window !== 'undefined') {
      const token = localStorage.getItem('soc_token');
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }
    
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers,
      body: formData,
    });
    if (response.status === 401) {
      handleUnauthorized();
    }
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'API request failed' }));
      throw new Error(err.detail || 'API request failed');
    }
    return response.json();
  },

  async put(endpoint: string, data?: any) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'PUT',
      headers: getHeaders(),
      body: data ? JSON.stringify(data) : undefined,
    });
    if (response.status === 401) {
      handleUnauthorized();
    }
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'API request failed' }));
      throw new Error(err.detail || 'API request failed');
    }
    return response.json();
  },

  async delete(endpoint: string) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'DELETE',
      headers: getHeaders(),
    });
    if (response.status === 401) {
      handleUnauthorized();
    }
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'API request failed' }));
      throw new Error(err.detail || 'API request failed');
    }
    return response.json();
  },
};

const handleUnauthorized = () => {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_user');
    localStorage.removeItem('soc_role');
    if (window.location.pathname !== '/') {
      window.location.href = '/';
    }
  }
};
