import React, { useMemo } from 'react'
import {
  ResponsiveContainer, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, ReferenceLine,
} from 'recharts'

function fmtHour(raw) {
  if (!raw) return ''
  try {
    const d = new Date(raw)
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  } catch {
    return String(raw)
  }
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-ids-card border border-ids-border rounded-lg px-3 py-2 shadow-xl">
      <p className="text-xs text-ids-sub mb-1">{label}</p>
      <p className="text-sm font-bold text-ids-danger">
        {payload[0].value} alert{payload[0].value !== 1 ? 's' : ''}
      </p>
    </div>
  )
}

export default function AlertsChart({ stats }) {
  const raw = stats?.alerts_per_hour ?? []

  const data = useMemo(() => {
    if (!raw.length) {
      // Generate empty placeholder
      return Array.from({ length: 12 }, (_, i) => ({ hour: `${i * 2}:00`, count: 0 }))
    }
    return raw.map(p => ({
      hour:  fmtHour(p.hour ?? p.time ?? p.timestamp),
      count: p.count ?? p.alert_count ?? 0,
    }))
  }, [raw])

  const maxCount = Math.max(...data.map(d => d.count), 1)

  return (
    <div className="card flex-1 min-w-0">
      <p className="card-title">Alerts Over Time</p>
      <p className="text-xs text-ids-muted mb-4">
        Attack alerts detected per hour · last {stats?.window_hours ?? 24}h
      </p>

      {maxCount === 1 && raw.length === 0 ? (
        <div className="h-48 flex items-center justify-center text-ids-muted text-sm">
          No alert data yet
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3e" />
            <XAxis
              dataKey="hour"
              tick={{ fill: '#6B7280', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              interval="preserveStartEnd"
            />
            <YAxis
              tick={{ fill: '#6B7280', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip content={<CustomTooltip />} />
            {maxCount > 0 && (
              <ReferenceLine y={0} stroke="#2a2d3e" />
            )}
            <Line
              type="monotone"
              dataKey="count"
              stroke="#E24B4A"
              strokeWidth={2}
              dot={{ fill: '#E24B4A', strokeWidth: 0, r: 3 }}
              activeDot={{ r: 5, fill: '#E24B4A', stroke: '#0f1117', strokeWidth: 2 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
