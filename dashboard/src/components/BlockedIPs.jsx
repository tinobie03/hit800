import React, { useState } from 'react'

function IPRow({ ip, onUnblock, unblocking }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-ids-border/50 last:border-0 group">
      <div className="flex items-center gap-3">
        <div className="w-1.5 h-1.5 rounded-full bg-ids-danger flex-shrink-0" />
        <span className="font-mono text-sm text-ids-text">{ip}</span>
      </div>
      <button
        onClick={() => onUnblock(ip)}
        disabled={unblocking === ip}
        className="
          text-xs px-3 py-1 rounded-lg border
          border-ids-safe/30 text-ids-safe
          hover:bg-ids-safe hover:text-white hover:border-ids-safe
          disabled:opacity-40 disabled:cursor-not-allowed
          transition-all duration-150
        "
      >
        {unblocking === ip ? 'Unblocking…' : 'Unblock'}
      </button>
    </div>
  )
}

export default function BlockedIPs({ blocked, onBlock, onUnblock }) {
  const [ipInput,    setIpInput]    = useState('')
  const [reason,     setReason]     = useState('manual')
  const [blocking,   setBlocking]   = useState(false)
  const [unblocking, setUnblocking] = useState(null)
  const [formError,  setFormError]  = useState('')

  const rawIps = blocked?.blocked ?? (Array.isArray(blocked) ? blocked : [])
  const ips = rawIps.map(item => typeof item === 'string' ? item : (item?.ip ?? String(item)))

  function validateIP(ip) {
    // Basic IPv4 validation
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip)
  }

  async function handleBlock(e) {
    e.preventDefault()
    const ip = ipInput.trim()
    if (!validateIP(ip)) {
      setFormError('Enter a valid IPv4 address (e.g. 192.168.64.3)')
      return
    }
    setFormError('')
    setBlocking(true)
    try {
      await onBlock(ip, reason || 'manual')
    } catch (err) {
      setFormError(err.message ?? 'Failed to block IP')
    } finally {
      setBlocking(false)
      setIpInput('')
      setReason('manual')
    }
  }

  async function handleUnblock(ip) {
    setUnblocking(ip)
    try {
      await onUnblock(ip)
    } catch (err) {
      console.error('Unblock failed:', err)
    } finally {
      setUnblocking(null)
    }
  }

  return (
    <div className="card">
      <p className="card-title">Blocked IPs</p>

      {/* Active blocks list */}
      {ips.length === 0 ? (
        <p className="text-sm text-ids-muted py-4 text-center">
          No IPs currently blocked
        </p>
      ) : (
        <div className="mb-5 max-h-60 overflow-y-auto pr-1">
          {ips.map(ip => (
            <IPRow
              key={ip}
              ip={ip}
              onUnblock={handleUnblock}
              unblocking={unblocking}
            />
          ))}
        </div>
      )}

      {/* Block count badge */}
      {ips.length > 0 && (
        <div className="flex items-center gap-2 mb-5">
          <span className="badge bg-ids-orange/10 text-ids-orange border border-ids-orange/20">
            {ips.length} active block{ips.length !== 1 ? 's' : ''}
          </span>
          <span className="text-xs text-ids-muted">via iptables on IDS-Lab VM</span>
        </div>
      )}

      {/* Manual block form */}
      <div className="border-t border-ids-border pt-4">
        <p className="text-xs font-semibold text-ids-sub uppercase tracking-widest mb-3">
          Manual Block
        </p>
        <form onSubmit={handleBlock} className="flex flex-col gap-3">
          <div className="flex gap-2">
            <input
              type="text"
              value={ipInput}
              onChange={e => { setIpInput(e.target.value); setFormError('') }}
              placeholder="192.168.64.3"
              className="
                flex-1 px-3 py-2 rounded-lg text-sm font-mono
                bg-ids-bg border border-ids-border
                text-ids-text placeholder-ids-muted
                focus:outline-none focus:border-ids-danger
                transition-colors
              "
            />
            <button
              type="submit"
              disabled={blocking || !ipInput.trim()}
              className="
                px-4 py-2 rounded-lg text-sm font-semibold
                bg-ids-danger text-white
                hover:bg-red-600
                disabled:opacity-40 disabled:cursor-not-allowed
                transition-colors whitespace-nowrap
              "
            >
              {blocking ? 'Blocking…' : 'Block IP'}
            </button>
          </div>

          <input
            type="text"
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="Reason (optional)"
            className="
              px-3 py-2 rounded-lg text-sm
              bg-ids-bg border border-ids-border
              text-ids-text placeholder-ids-muted
              focus:outline-none focus:border-ids-border
              transition-colors
            "
          />

          {formError && (
            <p className="text-xs text-ids-danger">{formError}</p>
          )}
        </form>
      </div>
    </div>
  )
}
