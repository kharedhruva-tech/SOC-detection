// NEXT_PUBLIC_BACKEND_URL is set in Vercel env vars pointing to the Render backend.
// Local development uses the FastAPI app on port 8000.
const getBackendOrigin = (): string => {
  if (typeof window !== 'undefined') {
    const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    if (isLocalhost) {
      if (process.env.NEXT_PUBLIC_BACKEND_URL && process.env.NEXT_PUBLIC_BACKEND_URL.includes('localhost')) {
        return process.env.NEXT_PUBLIC_BACKEND_URL.replace(/\/$/, '');
      }
      return 'http://localhost:8000';
    }
  }

  if (process.env.NEXT_PUBLIC_BACKEND_URL) {
    let url = process.env.NEXT_PUBLIC_BACKEND_URL.replace(/\/$/, '');
    if (!url.startsWith('http')) {
      url = 'https://' + url;
    }
    return url;
  }
  // Hosted Production fallback (Render Cloud Backend)
  return 'https://soc-detection-system.onrender.com';
};

const backendOrigin = getBackendOrigin();

const API_BASE_URL = `${backendOrigin}/api/v1`;

const WS_BASE_URL = backendOrigin.replace(/^https?/, (match) => match === 'https' ? 'wss' : 'ws') + '/ws/alerts';

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

const safeFetch = async (url: string, options: RequestInit): Promise<Response> => {
  try {
    return await fetch(url, options);
  } catch (err: any) {
    if (err instanceof TypeError && (err.message.includes('fetch') || err.message.includes('NetworkError') || err.message.includes('Failed'))) {
      throw new Error(`Unable to reach backend at ${API_BASE_URL}. Ensure the FastAPI server is running on port 8000.`);
    }
    throw err;
  }
};

export const api = {
  async get(endpoint: string) {
    const response = await safeFetch(`${API_BASE_URL}${endpoint}`, {
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
    const response = await safeFetch(`${API_BASE_URL}${endpoint}`, {
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
    
    const response = await safeFetch(`${API_BASE_URL}${endpoint}`, {
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
    const response = await safeFetch(`${API_BASE_URL}${endpoint}`, {
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

  async patch(endpoint: string, data?: any) {
    const response = await safeFetch(`${API_BASE_URL}${endpoint}`, {
      method: 'PATCH',
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
    const response = await safeFetch(`${API_BASE_URL}${endpoint}`, {
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
