const API_BASE = import.meta.env.VITE_API_URL || '';

export async function analyzeThreat(query, maxTechniques = 4, history = []) {
  const res = await fetch(`${API_BASE}/api/intelligence/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, max_techniques: maxTechniques, history }),
  });
  if (!res.ok) {
    throw new Error(`Analysis failed: ${res.statusText}`);
  }
  return res.json();
}


export async function searchRRF(query, entityType = null, limit = 8) {
  const params = new URLSearchParams({ q: query, limit: String(limit) });
  if (entityType) params.append('entity_type', entityType);
  const res = await fetch(`${API_BASE}/api/search/rrf?${params.toString()}`);
  if (!res.ok) {
    throw new Error(`Search failed: ${res.statusText}`);
  }
  return res.json();
}

export async function getEntityDetail(entityId, entityType) {
  let endpoint = '';
  const type = (entityType || '').toLowerCase();

  if (type === 'technique') endpoint = `/api/techniques/${entityId}`;
  else if (type === 'group') endpoint = `/api/groups/${entityId}`;
  else if (type === 'software') endpoint = `/api/software/${entityId}`;
  else if (type === 'mitigation') endpoint = `/api/mitigations/${entityId}`;
  else if (type === 'tactic') endpoint = `/api/tactics/${entityId}`;
  else endpoint = `/api/techniques/${entityId}`;

  const res = await fetch(`${API_BASE}${endpoint}`);
  if (!res.ok) {
    throw new Error(`Failed to load ${entityType} ${entityId}`);
  }
  return res.json();
}

export async function getStats() {
  const res = await fetch(`${API_BASE}/api/stats`);
  if (!res.ok) return null;
  return res.json();
}

export async function generateNarrative(report) {
  const res = await fetch(`${API_BASE}/api/intelligence/narrative`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(report),
  });
  if (!res.ok) {
    throw new Error(`Failed to generate briefing: ${res.statusText}`);
  }
  return res.json();
}

export async function chatThreatIntel(report, message, history = []) {
  const res = await fetch(`${API_BASE}/api/intelligence/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ report, message, history }),
  });
  if (!res.ok) {
    throw new Error(`Chat request failed: ${res.statusText}`);
  }
  return res.json();
}

