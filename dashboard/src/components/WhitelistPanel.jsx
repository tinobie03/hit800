import React, { useState, useEffect } from 'react'
import { addWhitelist, fetchWhitelist as getWhitelist, removeWhitelist } from '../utils/api.js'

export default function WhitelistPanel() {
  const [whitelist, setWhitelist] = useState([])
  const [ipInput, setIpInput] = useState('')
  const [reason, setReason] = useState('trusted network')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // Fetch whitelist on mount
  useEffect(() => {
    fetchWhitelist()
    const interval = setInterval(fetchWhitelist, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [])

  async function fetchWhitelist() {
    try {
      const data = await getWhitelist()
      setWhitelist(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error('Failed to fetch whitelist:', err)
    }
  }

  async function handleAdd(e) {
    e.preventDefault()
    const ip = ipInput.trim()
    if (!ip) {
      setError('IP address required')
      return
    }

    setLoading(true)
    setError('')
    setSuccess('')

    try {
      await addWhitelist(ip, reason || 'manual')

      setSuccess(`✓ Added ${ip} to whitelist`)
      setIpInput('')
      setReason('trusted network')
      setTimeout(() => {
        fetchWhitelist()
        setSuccess('')
      }, 1000)
    } catch (err) {
      setError(err.message || 'Failed to add IP')
    } finally {
      setLoading(false)
    }
  }

  async function handleRemove(ip) {
    if (!window.confirm(`Remove ${ip} from whitelist?`)) return

    try {
      await removeWhitelist(ip)

      setSuccess(`✓ Removed ${ip}`)
      setTimeout(() => {
        fetchWhitelist()
        setSuccess('')
      }, 1000)
    } catch (err) {
      setError(err.message || 'Failed to remove')
    }
  }

  return (
    <div className="card">
      <p className="card-title">IP Whitelist</p>

      {/* Active whitelist */}
      {whitelist.length === 0 ? (
        <p className="text-sm text-ids-muted py-4 text-center">
          No whitelisted IPs yet
        </p>
      ) : (
        <div className="mb-5 max-h-40 overflow-y-auto space-y-2 pr-1">
          {whitelist.map((item) => (
            <div
              key={item.ip}
              className="flex items-center justify-between py-2 border-b border-ids-border/50 last:border-0"
            >
              <div className="flex-1">
                <span className="font-mono text-sm text-ids-text">{item.ip}</span>
                <p className="text-xs text-ids-muted">{item.reason}</p>
              </div>
              <button
                onClick={() => handleRemove(item.ip)}
                className="text-xs px-2 py-1 rounded text-red-400 hover:bg-red-500/10 transition-colors"
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Badge */}
      {whitelist.length > 0 && (
        <div className="mb-5">
          <span className="badge bg-ids-safe/10 text-ids-safe border border-ids-safe/20">
            {whitelist.length} whitelisted
          </span>
        </div>
      )}

      {/* Add form */}
      <div className="border-t border-ids-border pt-4">
        <p className="text-xs font-semibold text-ids-sub uppercase tracking-widest mb-3">
          Add IP to Whitelist
        </p>

        <form onSubmit={handleAdd} className="space-y-3">
          <div className="flex gap-2">
            <input
              type="text"
              value={ipInput}
              onChange={(e) => {
                setIpInput(e.target.value)
                setError('')
              }}
              placeholder="192.168.1.100"
              className="flex-1 px-3 py-2 rounded-lg text-sm font-mono bg-ids-bg border border-ids-border text-ids-text focus:outline-none focus:border-ids-safe transition-colors"
            />
            <button
              type="submit"
              disabled={loading || !ipInput.trim()}
              className="px-4 py-2 rounded-lg text-sm font-semibold bg-ids-safe text-white hover:bg-green-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
            >
              {loading ? 'Adding...' : 'Add'}
            </button>
          </div>

          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason (e.g., internal network, testing)"
            className="w-full px-3 py-2 rounded-lg text-sm bg-ids-bg border border-ids-border text-ids-text focus:outline-none focus:border-ids-border transition-colors"
          />

          {error && (
            <p className="text-xs text-red-400">{error}</p>
          )}

          {success && (
            <p className="text-xs text-green-400">{success}</p>
          )}
        </form>
      </div>

      <div className="pt-3 border-t border-ids-border/50 text-xs text-ids-muted space-y-1">
        <p>✓ <strong>Whitelisted IPs:</strong> Won't be flagged as attacks</p>
        <p>✓ <strong>Manual Control:</strong> Add/remove IPs anytime</p>
        <p>✓ <strong>Real-time:</strong> Changes apply immediately</p>
      </div>
    </div>
  )
}
