import React from 'react'

function fmt(date) {
  if (!date) return '—'
  return date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export default function Header({ health, countdown, lastUpdate, onRefresh }) {
  const isOk = health?.status === 'ok' || health?.status === 'running'

  return (
    <header className="sticky top-0 z-50 border-b border-ids-border bg-ids-card/95 backdrop-blur-sm">
      <div className="max-w-screen-2xl mx-auto px-6 py-3 flex flex-wrap items-center gap-4">

        {/* Shield icon + title */}
        <div className="flex items-center gap-3 mr-auto">
          <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-ids-safe/10">
            <svg className="w-5 h-5 text-ids-safe" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
            </svg>
          </div>
          <div>
            <h1 className="text-base font-bold text-ids-text leading-tight tracking-tight">
              MFS Intrusion Detection System
            </h1>
            <p className="text-[10px] text-ids-sub tracking-wide">
              OneMoney · HIT 800 Research · CNN-based IDS/IPS
            </p>
          </div>
        </div>

        {/* System status */}
        <div className="flex items-center gap-2">
          <span
            className={`relative flex h-2.5 w-2.5 ${isOk ? '' : ''}`}
          >
            <span
              className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-60 ${
                isOk ? 'bg-ids-safe' : 'bg-ids-danger'
              }`}
            />
            <span
              className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                isOk ? 'bg-ids-safe' : 'bg-ids-danger'
              }`}
            />
          </span>
          <span className={`text-xs font-medium ${isOk ? 'text-ids-safe' : 'text-ids-danger'}`}>
            {isOk ? 'System Online' : 'System Offline'}
          </span>
        </div>

        {/* CNN threshold badge */}
        <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-ids-bg border border-ids-border">
          <svg className="w-3 h-3 text-ids-warn" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z" />
          </svg>
          <span className="text-xs text-ids-sub">CNN Threshold</span>
          <span className="text-xs font-bold text-ids-warn">
            {health?.threshold ?? '0.50'}
          </span>
        </div>

        {/* Last updated + countdown */}
        <div className="flex items-center gap-3">
          <div className="text-right">
            <p className="text-[10px] text-ids-muted leading-none">Last updated</p>
            <p className="text-xs font-mono text-ids-sub">{fmt(lastUpdate)}</p>
          </div>

          {/* Circular countdown */}
          <button
            onClick={onRefresh}
            title="Refresh now"
            className="relative flex items-center justify-center w-9 h-9 rounded-full border border-ids-border hover:border-ids-safe transition-colors group"
          >
            <svg className="absolute inset-0 w-9 h-9 -rotate-90" viewBox="0 0 36 36">
              <circle
                cx="18" cy="18" r="15"
                fill="none" stroke="#2a2d3e" strokeWidth="2"
              />
              <circle
                cx="18" cy="18" r="15"
                fill="none"
                stroke="#1D9E75"
                strokeWidth="2"
                strokeDasharray={`${(countdown / 10) * 94.25} 94.25`}
                strokeLinecap="round"
              />
            </svg>
            <span className="relative text-[10px] font-bold font-mono text-ids-safe group-hover:text-white">
              {countdown}
            </span>
          </button>
        </div>

      </div>
    </header>
  )
}
