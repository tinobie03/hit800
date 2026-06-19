import React, { useState, useEffect } from 'react'
import { fetchCorrelated } from '../utils/api.js'

/**
 * CorrelatedAlerts — Objective 2 (multi-source correlation).
 * Shows per-IP fusion of the network CNN score and the auth-log anomaly score.
 * An IP flagged "CORRELATED" tripped both sources in the same window — the
 * strongest evidence and what the IPS escalates on.
 */
function ScoreBar({ value, color }) {
  const pct = Math.min(Math.max((value ?? 0) * 100, 0), 100)
  return (
    <div className="flex items-center gap-2 min-w-[90px]">
      <div className="flex-1 h-1.5 bg-ids-border rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-mono tabular-nums" style={{ color }}>{pct.toFixed(0)}%</span>
    </div>
  )
}

export default function CorrelatedAlerts() {
  const [rows, setRows] = useState([])
  const [onlyCorrelated, setOnlyCorrelated] = useState(false)

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const data = await fetchCorrelated(50, 24, onlyCorrelated)
        if (active) setRows(data.alerts ?? [])
      } catch {
        /* leave previous rows */
      }
    }
    load()
    const id = setInterval(load, 10000)
    return () => { active = false; clearInterval(id) }
  }, [onlyCorrelated])

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-3">
        <p className="card-title mb-0">Multi-Source Correlation</p>
        <label className="flex items-center gap-1 text-xs text-ids-muted cursor-pointer">
          <input
            type="checkbox"
            checked={onlyCorrelated}
            onChange={(e) => setOnlyCorrelated(e.target.checked)}
          />
          Confirmed only
        </label>
      </div>

      <p className="text-xs text-ids-muted mb-3">
        Network (CNN) fused with auth-log anomalies per source IP
      </p>

      {rows.length === 0 ? (
        <div className="h-24 flex items-center justify-center text-ids-muted text-sm">
          No correlated data yet — run an SSH brute-force + a network attack.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-ids-border text-[10px] uppercase tracking-widest text-ids-muted">
                <th className="pb-2 pr-3 text-left">Source IP</th>
                <th className="pb-2 pr-3 text-left">Network</th>
                <th className="pb-2 pr-3 text-left">Auth Log</th>
                <th className="pb-2 pr-3 text-left">Fused</th>
                <th className="pb-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className="border-b border-ids-border/50">
                  <td className="py-2 pr-3 font-mono text-xs text-ids-text">{r.source_ip}</td>
                  <td className="py-2 pr-3"><ScoreBar value={r.network_score} color="#E24B4A" /></td>
                  <td className="py-2 pr-3"><ScoreBar value={r.log_score} color="#F59E0B" /></td>
                  <td className="py-2 pr-3"><ScoreBar value={r.fused_score} color="#8B5CF6" /></td>
                  <td className="py-2">
                    {r.correlated ? (
                      <span className="badge bg-purple-500/15 text-purple-300 border border-purple-500/30">
                        CORRELATED
                      </span>
                    ) : (
                      <span className="badge bg-ids-bg text-ids-muted border border-ids-border">
                        single source
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="pt-3 mt-2 border-t border-ids-border/50 text-xs text-ids-muted space-y-1">
        <p>🔴 Network = CNN flow anomaly · 🟠 Auth Log = failed-login anomaly (IsolationForest)</p>
        <p>🟣 <strong>CORRELATED</strong> = both sources fired for the same IP — highest confidence</p>
      </div>
    </div>
  )
}
