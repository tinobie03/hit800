import React, { useMemo } from 'react'
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Cell,
} from 'recharts'

const COLORS = [
  '#E24B4A', '#E8673C', '#F59E0B', '#F97316',
  '#EF4444', '#DC2626', '#B91C1C', '#991B1B',
]

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-ids-card border border-ids-border rounded-lg px-3 py-2 shadow-xl">
      <p className="text-xs text-ids-sub font-mono">{payload[0]?.payload?.ip}</p>
      <p className="text-sm font-bold text-ids-danger mt-1">
        {payload[0].value} hit{payload[0].value !== 1 ? 's' : ''}
      </p>
    </div>
  )
}

export default function TopIPsChart({ stats }) {
  const raw = stats?.top_attacking_ips ?? stats?.top_attackers ?? []

  const data = useMemo(() =>
    raw.slice(0, 8).map(item => ({
      ip:    item.ip ?? item.source_ip ?? 'unknown',
      count: item.count ?? item.hits ?? 0,
    })),
  [raw])

  if (!data.length) {
    return (
      <div className="card w-full lg:w-80 xl:w-96">
        <p className="card-title">Top Attacking IPs</p>
        <div className="h-48 flex items-center justify-center text-ids-muted text-sm">
          No attacker data yet
        </div>
      </div>
    )
  }

  return (
    <div className="card w-full lg:w-80 xl:w-96">
      <p className="card-title">Top Attacking IPs</p>
      <p className="text-xs text-ids-muted mb-4">Highest-volume source addresses</p>

      <ResponsiveContainer width="100%" height={data.length * 40 + 16}>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 0, right: 8, left: 8, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3e" horizontal={false} />
          <XAxis
            type="number"
            tick={{ fill: '#6B7280', fontSize: 10 }}
            axisLine={false}
            tickLine={false}
            allowDecimals={false}
          />
          <YAxis
            type="category"
            dataKey="ip"
            tick={{ fill: '#9CA3AF', fontSize: 10, fontFamily: 'monospace' }}
            axisLine={false}
            tickLine={false}
            width={100}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(226,75,74,0.08)' }} />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={20}>
            {data.map((_, i) => (
              <Cell key={i} fill={COLORS[i % COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
