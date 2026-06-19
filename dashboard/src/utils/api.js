export const BASE = import.meta.env.VITE_API_URL ??
  `${window.location.protocol}//${window.location.hostname}:8000`

async function request(path, options = {}) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 5000)
  let res
  try {
    res = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      ...options,
    })
  } catch (error) {
    if (error.name === 'AbortError') throw new Error(`API timeout: ${BASE}`)
    throw new Error(`API unreachable at ${BASE}`)
  } finally {
    clearTimeout(timeout)
  }
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`${res.status} ${text}`)
  }
  return res.json()
}

export async function fetchHealth() {
  // Try dedicated health endpoint, fall back to root
  try {
    return await request('/api/health')
  } catch {
    const root = await request('/')
    return {
      status:    root.status === 'running' ? 'ok' : 'error',
      model:     'onemoney_cnn',
      database:  'sqlite',
      threshold: root.threshold ?? 0.50,
      timestamp: root.time,
    }
  }
}

export async function fetchStats(hours = 24) {
  return request(`/api/stats?hours=${hours}`)
}

export async function fetchAlerts(limit = 20, hours = 24) {
  const data = await request(`/api/alerts?limit=${limit}&hours=${hours}`)
  // Normalise: API may return list or { total, alerts: [] }
  if (Array.isArray(data)) return { total: data.length, alerts: data }
  return data
}

export async function fetchBlocked() {
  const data = await request('/api/blocked')
  // Normalise: may return { blocked: [] } or a list
  if (Array.isArray(data)) return { blocked: data }
  return data
}

export async function blockIP(ip, reason = 'manual') {
  return request('/api/block', {
    method: 'POST',
    body: JSON.stringify({ ip, reason }),
  })
}

export async function unblockIP(ip) {
  // Try POST first (user spec), then DELETE (our FastAPI implementation)
  try {
    return await request(`/api/unblock/${encodeURIComponent(ip)}`, { method: 'POST' })
  } catch {
    return request(`/api/unblock/${encodeURIComponent(ip)}`, { method: 'DELETE' })
  }
}

export async function predict(features) {
  return request('/api/predict', {
    method: 'POST',
    body: JSON.stringify({ features }),
  })
}

export async function clearDatabase() {
  return request('/api/clear-db', {
    method: 'POST',
  })
}

export async function fetchCorrelated(limit = 50, hours = 24, onlyCorrelated = false) {
  const data = await request(`/api/correlated?limit=${limit}&hours=${hours}&only_correlated=${onlyCorrelated}`)
  if (Array.isArray(data)) return { total: data.length, alerts: data }
  return data
}

export async function fetchWhitelist() {
  return request('/api/whitelist')
}

export async function addWhitelist(ip, reason = 'manual') {
  return request('/api/whitelist', {
    method: 'POST',
    body: JSON.stringify({ ip, reason }),
  })
}

export async function removeWhitelist(ip) {
  return request(`/api/whitelist/${encodeURIComponent(ip)}`, { method: 'DELETE' })
}
