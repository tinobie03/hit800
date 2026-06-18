import React from 'react'

function fmtTime(ts) {
  if (!ts) return '—'
  try {
    return new Date(ts).toLocaleTimeString('en-GB', {
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
  } catch {
    return String(ts).slice(0, 19)
  }
}

function probColor(p) {
  if (p >= 0.8) return '#E24B4A'
  if (p >= 0.6) return '#F97316'
  if (p >= 0.4) return '#F59E0B'
  return '#1D9E75'
}

function ProbBar({ value }) {
  const pct = Math.min(Math.max((value ?? 0) * 100, 0), 100)
  const color = probColor(value ?? 0)
  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <div className="flex-1 h-1.5 bg-ids-border rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-xs font-mono tabular-nums" style={{ color }}>
        {(pct).toFixed(1)}%
      </span>
    </div>
  )
}

function BlockedBadge({ blocked }) {
  return blocked ? (
    <span className="badge bg-ids-danger/15 text-ids-danger border border-ids-danger/30">
      Blocked
    </span>
  ) : (
    <span className="badge bg-ids-safe/10 text-ids-safe border border-ids-safe/20">
      Live
    </span>
  )
}

function attackTypeColor(type) {
  if (!type) return { bg: 'bg-ids-bg', text: 'text-ids-sub' }
  const t = type.toLowerCase()
  if (t.includes('syn'))       return { bg: 'bg-red-900/30',    text: 'text-red-400' }
  if (t.includes('port'))      return { bg: 'bg-orange-900/30', text: 'text-orange-400' }
  if (t.includes('http') || t.includes('flood')) return { bg: 'bg-yellow-900/30', text: 'text-yellow-400' }
  if (t.includes('slow'))      return { bg: 'bg-purple-900/30', text: 'text-purple-400' }
  if (t.includes('brute'))     return { bg: 'bg-pink-900/30',   text: 'text-pink-400' }
  if (t.includes('udp'))       return { bg: 'bg-blue-900/30',   text: 'text-blue-400' }
  return { bg: 'bg-ids-bg', text: 'text-ids-sub' }
}

export default function AlertsTable({ alerts }) {
  const rows = alerts?.alerts ?? (Array.isArray(alerts) ? alerts : [])
  const total = alerts?.total ?? rows.length

  function exportCSV() {
    const headers = ['Time','Source IP','Dest IP','Attack Prob','Confidence','Type','Blocked']
    const csvRows = [headers.join(',')]
    rows.forEach(row => {
      csvRows.push([
        row.timestamp ?? '',
        row.src_ip ?? '',
        row.dst_ip ?? '',
        row.attack_prob ?? '',
        row.confidence ?? '',
        row.attack_type ?? row.traffic_type ?? 'ATTACK',
        row.blocked ? 'true' : 'false',
      ].join(','))
    })
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `onemoney_ids_alerts_${new Date().toISOString().slice(0,10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  if (!rows.length) {
    return (
      <div className="card">
        <p className="card-title">Live Alerts Feed</p>
        <div className="h-32 flex items-center justify-center text-ids-muted text-sm">
          No alerts recorded yet — run an attack simulation to generate data.
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <p className="card-title mb-0">Live Alerts Feed</p>
        <div className="flex items-center gap-2">
          <span className="badge bg-ids-danger/10 text-ids-danger border border-ids-danger/20 text-xs">
            {total.toLocaleString()} total
          </span>
          <button
            onClick={exportCSV}
            className="text-xs px-3 py-1 rounded-lg border border-ids-border text-ids-muted hover:text-ids-text hover:border-ids-accent transition-all"
          >
            Export CSV
          </button>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-ids-border">
              {['Time', 'Source IP', 'Dest IP', 'Attack Prob', 'Confidence', 'Type', 'Status'].map(h => (
                <th
                  key={h}
                  className="pb-2 pr-4 text-left text-[10px] font-semibold uppercase tracking-widest text-ids-muted whitespace-nowrap"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 20).map((row, i) => {
              const attackProb = row.attack_prob ?? row.confidence ?? 0
              const isBlocked  = row.blocked === true
              return (
                <tr
                  key={i}
                  className={`border-b border-ids-border/50 transition-colors ${
                    isBlocked
                      ? 'bg-ids-danger/5 hover:bg-ids-danger/10'
                      : 'hover:bg-ids-card2/60'
                  }`}
                >
                  <td className="py-2.5 pr-4 font-mono text-xs text-ids-sub whitespace-nowrap">
                    {fmtTime(row.timestamp)}
                  </td>
                  <td className="py-2.5 pr-4 font-mono text-xs text-ids-text whitespace-nowrap">
                    {row.src_ip ?? row.source_ip ?? '—'}
                  </td>
                  <td className="py-2.5 pr-4 font-mono text-xs text-ids-sub whitespace-nowrap">
                    {row.dst_ip ?? row.dest_ip ?? row.destination_ip ?? '—'}
                  </td>
                  <td className="py-2.5 pr-4">
                    <ProbBar value={attackProb} />
                  </td>
                  <td className="py-2.5 pr-4 text-xs text-ids-sub whitespace-nowrap">
                    {row.confidence != null
                      ? `${(row.confidence * 100).toFixed(1)}%`
                      : `${(attackProb * 100).toFixed(1)}%`
                    }
                  </td>
                  <td className="py-2.5 pr-4">
                    {(() => {
                      const attackLabel = row.attack_type ?? row.traffic_type ?? row.prediction ?? 'ATTACK'
                      const { bg, text } = attackTypeColor(attackLabel)
                      return (
                        <span className={`text-xs px-2 py-0.5 rounded font-mono whitespace-nowrap ${bg} ${text}`}>
                          {attackLabel}
                        </span>
                      )
                    })()}
                  </td>
                  <td className="py-2.5">
                    <BlockedBadge blocked={isBlocked} />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
