const API_BASE = (import.meta.env.VITE_API_URL || '').replace(/\/+$/, '');
const DEFAULT_TIMEOUT_MS = 60000;
const FAST_TIMEOUT_MS = 15000;

export class ApiError extends Error {
  constructor(message, status = 0, detail = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

async function request(endpoint, options = {}) {
  const { timeout = DEFAULT_TIMEOUT_MS, signal: externalSignal, headers = {}, ...fetchOptions } = options;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  if (externalSignal) {
    externalSignal.addEventListener('abort', () => controller.abort(), { once: true });
  }

  const url = `${API_BASE}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

  try {
    const res = await fetch(url, {
      ...fetchOptions,
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        ...(fetchOptions.body ? { 'Content-Type': 'application/json' } : {}),
        ...headers,
      },
    });

    let data = null;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      data = await res.json().catch(() => null);
    } else {
      data = await res.text().catch(() => null);
    }

    if (!res.ok) {
      let errorMessage = `Request failed with status ${res.status}`;
      let detail = null;

      if (data && typeof data === 'object') {
        detail = data.detail;
        if (typeof detail === 'string') {
          errorMessage = detail;
        } else if (Array.isArray(detail)) {
          errorMessage = detail.map((err) => err.msg || JSON.stringify(err)).join(', ');
        }
      } else if (typeof data === 'string' && data.trim()) {
        errorMessage = data.trim();
      } else if (res.statusText) {
        errorMessage = res.statusText;
      }

      throw new ApiError(errorMessage, res.status, detail);
    }

    return data;
  } catch (err) {
    if (err.name === 'AbortError' || err.name === 'CanceledError') {
      if (externalSignal?.aborted) {
        throw new ApiError('Request cancelled by user', 499, 'aborted');
      }
      throw new ApiError(`Request to ${endpoint} timed out after ${timeout / 1000}s`, 408);
    }
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(err.message || 'Network communication failure', 0);
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function analyzeThreat(query, maxTechniques = 4, history = [], options = {}) {
  const cleanQuery = (query || '').trim();
  if (!cleanQuery) {
    throw new ApiError('Query string cannot be empty', 400);
  }

  return request('/api/intelligence/analyze', {
    method: 'POST',
    body: JSON.stringify({
      query: cleanQuery,
      max_techniques: Math.max(1, Math.min(maxTechniques, 20)),
      history: Array.isArray(history) ? history : [],
    }),
    ...options,
  });
}

const ENTITY_ROUTE_MAP = {
  technique: '/api/techniques',
  tactic: '/api/tactics',
  mitigation: '/api/mitigations',
  group: '/api/groups',
  software: '/api/software',
};

export async function getEntityDetail(entityId, entityType, options = {}) {
  const cleanId = (entityId || '').trim();
  if (!cleanId) {
    throw new ApiError('Entity ID is required', 400);
  }

  const cleanType = (entityType || 'technique').toLowerCase().trim();
  const baseRoute = ENTITY_ROUTE_MAP[cleanType] || ENTITY_ROUTE_MAP.technique;
  const endpoint = `${baseRoute}/${encodeURIComponent(cleanId)}`;

  return request(endpoint, {
    timeout: FAST_TIMEOUT_MS,
    ...options,
  });
}

export async function searchEntities(query, limit = 15, options = {}) {
  const cleanQuery = (query || '').trim();
  if (!cleanQuery) {
    return { query: '', techniques: [], groups: [], software: [] };
  }

  return request(`/api/search?q=${encodeURIComponent(cleanQuery)}&limit=${limit}`, {
    timeout: FAST_TIMEOUT_MS,
    ...options,
  });
}

export async function getStatistics(options = {}) {
  return request('/api/stats', {
    timeout: FAST_TIMEOUT_MS,
    ...options,
  });
}

export async function getHealth(options = {}) {
  return request('/health', {
    timeout: FAST_TIMEOUT_MS,
    ...options,
  });
}
