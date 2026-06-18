import { useState, useEffect, useCallback, useRef } from 'react'
import {
  fetchHealth, fetchStats, fetchAlerts,
  fetchBlocked, blockIP as apiBlock, unblockIP as apiUnblock,
} from '../utils/api.js'

const POLL_MS    = 10_000
const COUNTDOWN  = 10

export function useIDS(hours = 24) {
  const [health,    setHealth]    = useState(null)
  const [stats,     setStats]     = useState(null)
  const [alerts,    setAlerts]    = useState({ total: 0, alerts: [] })
  const [blocked,   setBlocked]   = useState({ blocked: [] })
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)   // null = connected
  const [countdown, setCountdown] = useState(COUNTDOWN)
  const [lastUpdate, setLastUpdate] = useState(null)

  const timerRef     = useRef(null)
  const countdownRef = useRef(null)

  const poll = useCallback(async () => {
    try {
      const [h, s, a, b] = await Promise.allSettled([
        fetchHealth(),
        fetchStats(hours),
        fetchAlerts(20, hours),
        fetchBlocked(),
      ])

      if (h.status === 'fulfilled') setHealth(h.value)
      if (s.status === 'fulfilled') setStats(s.value)
      if (a.status === 'fulfilled') setAlerts(a.value)
      if (b.status === 'fulfilled') setBlocked(b.value)

      // If health fails AND stats fail, consider the API down
      if (h.status === 'rejected' && s.status === 'rejected') {
        setError('API unreachable — check that the FastAPI service is running.')
      } else {
        setError(null)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
      setLastUpdate(new Date())
      setCountdown(COUNTDOWN)
    }
  }, [hours])

  // Initial fetch + interval
  useEffect(() => {
    poll()
    timerRef.current = setInterval(poll, POLL_MS)
    return () => clearInterval(timerRef.current)
  }, [poll])

  // Countdown ticker
  useEffect(() => {
    countdownRef.current = setInterval(() => {
      setCountdown(c => (c <= 1 ? COUNTDOWN : c - 1))
    }, 1000)
    return () => clearInterval(countdownRef.current)
  }, [])

  const blockIP = useCallback(async (ip, reason) => {
    await apiBlock(ip, reason)
    await poll()
  }, [poll])

  const unblockIP = useCallback(async (ip) => {
    await apiUnblock(ip)
    await poll()
  }, [poll])

  const refreshNow = useCallback(() => {
    setCountdown(COUNTDOWN)
    poll()
  }, [poll])

  return {
    health, stats, alerts, blocked,
    loading, error, countdown, lastUpdate,
    blockIP, unblockIP, refreshNow,
  }
}
