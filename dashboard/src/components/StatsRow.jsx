import React from 'react'

function StatCard({ label, value, sub, valueColor, icon }) {
  return (
    <div className="card flex-1 min-w-[180px]">
      <div className="flex items-start justify-between">
        <div>
          <p className="card-title">{label}</p>
          <p className={`text-3xl font-bold tracking-tight leading-none ${valueColor}`}>
            {value}
          </p>
          {sub && (
            <p className="mt-1.5 text-xs text-ids-muted">{sub}</p>
          )}
        </div>
        <div className="text-2xl opacity-60 ml-2 mt-0.5">{icon}</div>
      </div>
    </div>
  )
}

export default function StatsRow({ stats, health, lastAlertTime }) {
  const totalAlerts   = stats?.total_alerts  ?? stats?.total_attacks ?? 0
  const totalBlocked  = stats?.total_blocked ?? stats?.blocked_ips   ?? 0
  const avgConf       = stats?.avg_attack_prob ?? stats?.avg_confidence
  const maxProb       = stats?.max_attack_prob ?? stats?.max_confidence

  const confPct = avgConf != null
    ? `${(avgConf * 100).toFixed(1)}%`
    : '—'

  const maxProbPct = maxProb != null
    ? `${(maxProb * 100).toFixed(1)}%`
    : '—'

  const isOk = health?.status === 'ok' || health?.status === 'running'

  let statusValue, statusSub, statusColor, statusIcon

  if (health == null) {
    statusValue = 'Checking…'
    statusSub   = 'Polling API…'
    statusColor = 'text-ids-muted'
    statusIcon  = '⏳'
  } else if (!isOk) {
    statusValue = 'OFFLINE'
    statusSub   = 'API or model fault'
    statusColor = 'text-ids-danger'
    statusIcon  = '⛔'
  } else if (totalAlerts > 0 && (maxProb > 0.8 || totalBlocked > 0)) {
    statusValue = 'MITIGATING'
    statusSub   = `${totalBlocked} active block${totalBlocked !== 1 ? 's' : ''} · ${maxProb != null ? (maxProb * 100).toFixed(0) : '—'}% peak score`
    statusColor = 'text-ids-orange'
    statusIcon  = '🛡️'
  } else if (totalAlerts > 0) {
    statusValue = 'WARNING'
    statusSub   = `${totalAlerts} alert${totalAlerts !== 1 ? 's' : ''} detected · monitoring`
    statusColor = 'text-ids-orange'
    statusIcon  = '⚠️'
  } else {
    statusValue = 'SECURE'
    statusSub   = `Threshold ${health?.threshold ?? 0.50}`
    statusColor = 'text-ids-safe'
    statusIcon  = '✅'
  }

  return (
    <div className="flex flex-wrap gap-4">
      <StatCard
        label="Total Alerts (24h)"
        value={totalAlerts.toLocaleString()}
        sub={totalAlerts > 0 ? 'Attack traffic detected' : 'No attacks detected'}
        valueColor={totalAlerts > 0 ? 'text-ids-danger' : 'text-ids-safe'}
        icon="🚨"
      />
      <StatCard
        label="Blocked IPs"
        value={totalBlocked.toLocaleString()}
        sub="Active iptables blocks"
        valueColor={totalBlocked > 0 ? 'text-ids-orange' : 'text-ids-text'}
        icon="🚫"
      />
      <StatCard
        label="Avg Model Score"
        value={confPct}
        sub={maxProb != null ? `Peak: ${maxProbPct}` : 'No data'}
        valueColor="text-ids-text"
        icon="🧠"
      />
      <StatCard
        label="System Status"
        value={statusValue}
        sub={statusSub}
        valueColor={statusColor}
        icon={statusIcon}
      />
      {lastAlertTime && (
        <div className="w-full text-xs text-ids-muted flex items-center gap-2 mt-1">
          <span className="w-1.5 h-1.5 rounded-full bg-ids-danger animate-pulse inline-block" />
          Last attack detected: <span className="text-ids-text font-mono ml-1">{lastAlertTime}</span>
        </div>
      )}
    </div>
  )
}
