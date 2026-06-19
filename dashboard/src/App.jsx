import React, { useState } from 'react'
import { useIDS } from './hooks/useIDS.js'
import Header           from './components/Header.jsx'
import StatsRow         from './components/StatsRow.jsx'
import AlertsChart      from './components/AlertsChart.jsx'
import TopIPsChart      from './components/TopIPsChart.jsx'
import AlertsTable      from './components/AlertsTable.jsx'
import BlockedIPs       from './components/BlockedIPs.jsx'
import TimeFilter       from './components/TimeFilter.jsx'
import LiveFlowPredictor from './components/LiveFlowPredictor.jsx'

function Skeleton() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="flex gap-4">
        {[1,2,3,4].map(i => (
          <div key={i} className="flex-1 h-28 bg-ids-card rounded-xl" />
        ))}
      </div>
      <div className="flex gap-4">
        <div className="flex-1 h-64 bg-ids-card rounded-xl" />
        <div className="w-80 h-64 bg-ids-card rounded-xl" />
      </div>
      <div className="h-80 bg-ids-card rounded-xl" />
    </div>
  )
}

function ConnectionBanner({ error }) {
  if (!error) return null
  return (
    <div className="mx-6 mt-4 flex items-start gap-3 rounded-lg border border-ids-danger/40 bg-ids-danger/10 px-4 py-3">
      <svg className="w-4 h-4 text-ids-danger flex-shrink-0 mt-0.5" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
      </svg>
      <div>
        <p className="text-sm font-semibold text-ids-danger">Service Unavailable</p>
        <p className="text-xs text-ids-sub mt-0.5">{error}</p>
        <p className="text-xs text-ids-muted mt-1">
          Ensure the FastAPI backend is running:&nbsp;
          <code className="font-mono bg-ids-bg rounded px-1 py-0.5">docker-compose up -d api</code>
        </p>
      </div>
    </div>
  )
}

export default function App() {
  const [hours, setHours] = useState(24)

  const {
    health, stats, alerts, blocked,
    loading, error, countdown, lastUpdate,
    blockIP, unblockIP, refreshNow,
  } = useIDS(hours)

  const lastAlertTime = alerts?.alerts?.[0]?.timestamp
    ? new Date(alerts.alerts[0].timestamp).toLocaleTimeString('en-GB')
    : null

  return (
    <div className="min-h-screen bg-ids-bg font-sans">
      <Header
        health={health}
        countdown={countdown}
        lastUpdate={lastUpdate}
        onRefresh={refreshNow}
      />

      <ConnectionBanner error={error} />

      <main className="max-w-screen-2xl mx-auto px-6 py-6 space-y-5">

        {loading && !stats ? (
          <Skeleton />
        ) : (
          <>
            {/* ── Row 1: Stat cards ── */}
            <StatsRow stats={stats} health={health} lastAlertTime={lastAlertTime} />

            {/* ── Time filter ── */}
            <div className="flex items-center justify-between flex-wrap gap-3">
              <TimeFilter hours={hours} onChange={setHours} />
              <span className="text-xs text-ids-muted">
                Showing data for the last {hours < 48 ? '24 hours' : hours < 72 ? '2 days' : hours < 168 ? '3 days' : '7 days'}
              </span>
            </div>

            {/* ── Row 2: Charts ── */}
            <div className="flex flex-wrap gap-5">
              <AlertsChart stats={stats} />
              <TopIPsChart stats={stats} />
            </div>

            {/* ── Row 3: Table + Blocked panel ── */}
            <div className="flex flex-wrap gap-5">
              <div className="flex-1 min-w-0">
                <AlertsTable alerts={alerts} />
              </div>
              <div className="w-full lg:w-80 xl:w-96 flex-shrink-0">
                <BlockedIPs
                  blocked={blocked}
                  onBlock={blockIP}
                  onUnblock={unblockIP}
                />
              </div>
            </div>

            {/* ── Row 4: Live Flow Predictor (Real-time + Manual modes) ── */}
            <div className="max-w-3xl">
              <LiveFlowPredictor />
            </div>

            {/* ── Footer ── */}
            <footer className="border-t border-ids-border pt-5 pb-2 flex flex-wrap items-center justify-between gap-3 text-xs text-ids-muted">
              <div className="flex items-center gap-4">
                <span>OneMoney IDS/IPS · CNN 1D · 76 CICFlowMeter Features</span>
                <span className="text-ids-border">|</span>
                <span>Threshold: <span className="text-ids-warn font-mono">0.40</span></span>
                <span className="text-ids-border">|</span>
                <span>Poll: <span className="font-mono">10s</span></span>
              </div>
              <span>HIT 800 Research Project · Tinotenda B Chatora</span>
            </footer>
          </>
        )}
      </main>
    </div>
  )
}
