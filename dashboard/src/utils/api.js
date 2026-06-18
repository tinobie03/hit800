const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
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
      mongodb:   'connected',
      threshold: root.threshold ?? 0.40,
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
