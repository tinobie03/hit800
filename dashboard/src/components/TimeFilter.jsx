import React from 'react'

const OPTIONS = [
  { label: '24h',    hours: 24  },
  { label: '2 days', hours: 48  },
  { label: '3 days', hours: 72  },
  { label: '7 days', hours: 168 },
]

export default function TimeFilter({ hours, onChange }) {
  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-xs text-ids-muted font-semibold uppercase tracking-widest mr-1">
        History:
      </span>
      {OPTIONS.map(opt => (
        <button
          key={opt.hours}
          onClick={() => onChange(opt.hours)}
          className={`
            px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150
            ${hours === opt.hours
              ? 'bg-ids-accent text-white border-ids-accent'
              : 'bg-ids-card border-ids-border text-ids-sub hover:border-ids-accent hover:text-ids-accent'
            }
          `}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}
