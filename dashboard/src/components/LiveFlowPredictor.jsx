import React, { useState, useEffect, useRef } from 'react'
import { fetchAlerts, predict } from '../utils/api.js'

/**
 * LiveFlowPredictor
 *
 * TWO MODES:
 * 1. LIVE/AUTO: Continuously polls /api/alerts, shows real predictions from inference service
 * 2. MANUAL: Same as old FlowPredictor - you paste JSON and click predict
 *
 * The key insight:
 * - LIVE mode shows what the inference service is already detecting
 * - MANUAL mode lets you test new/custom flows
 */

const SAMPLE_FLOW_BENIGN = {
  "Flow Duration": 1000,
  "Tot Fwd Pkts": 50,
  "Tot Bwd Pkts": 45,
  "TotLen Fwd Pkts": 5000,
  "TotLen Bwd Pkts": 4500,
  "Fwd Pkt Len Max": 150,
  "Fwd Pkt Len Min": 50,
  "Fwd Pkt Len Mean": 100,
  "Fwd Pkt Len Std": 20,
  "Bwd Pkt Len Max": 150,
  "Bwd Pkt Len Min": 50,
  "Bwd Pkt Len Mean": 100,
  "Bwd Pkt Len Std": 20,
  "Flow Byts/s": 5.5,
  "Flow Pkts/s": 0.1,
  "Flow IAT Mean": 20,
  "Flow IAT Std": 5,
  "Flow IAT Max": 50,
  "Flow IAT Min": 1,
  "Fwd IAT Tot": 1000,
  "Fwd IAT Mean": 20,
  "Fwd IAT Std": 5,
  "Fwd IAT Max": 50,
  "Fwd IAT Min": 1,
  "Bwd IAT Tot": 900,
  "Bwd IAT Mean": 20,
  "Bwd IAT Std": 5,
  "Bwd IAT Max": 50,
  "Bwd IAT Min": 1,
  "Fwd PSH Flags": 0,
  "Bwd PSH Flags": 0,
  "Fwd URG Flags": 0,
  "Bwd URG Flags": 0,
  "Fwd Header Len": 60,
  "Bwd Header Len": 60,
  "Fwd Pkts/s": 0.05,
  "Bwd Pkts/s": 0.045,
  "Pkt Len Min": 50,
  "Pkt Len Max": 150,
  "Pkt Len Mean": 100,
  "Pkt Len Std": 20,
  "Pkt Len Var": 400,
  "FIN Flag Cnt": 1,
  "SYN Flag Cnt": 1,
  "RST Flag Cnt": 0,
  "PSH Flag Cnt": 0,
  "ACK Flag Cnt": 48,
  "URG Flag Cnt": 0,
  "CWE Flag Count": 0,
  "ECE Flag Cnt": 0,
  "Down/Up Ratio": 0.9,
  "Pkt Size Avg": 100,
  "Fwd Seg Size Avg": 100,
  "Bwd Seg Size Avg": 100,
  "Fwd Byts/b Avg": 100,
  "Fwd Pkts/b Avg": 0.05,
  "Fwd Blk Rate Avg": 0,
  "Bwd Byts/b Avg": 100,
  "Bwd Pkts/b Avg": 0.045,
  "Bwd Blk Rate Avg": 0,
  "Subflow Fwd Pkts": 25,
  "Subflow Fwd Byts": 2500,
  "Subflow Bwd Pkts": 25,
  "Subflow Bwd Byts": 2500,
  "Init Fwd Win Byts": 65535,
  "Init Bwd Win Byts": 65535,
  "Fwd Act Data Pkts": 25,
  "Fwd Seg Size Min": 50,
  "Active Mean": 100,
  "Active Std": 20,
  "Active Max": 200,
  "Active Min": 50,
  "Idle Mean": 500,
  "Idle Std": 100,
  "Idle Max": 1000,
  "Idle Min": 100,
}

const SAMPLE_FLOW_ATTACK = {
  ...SAMPLE_FLOW_BENIGN,
  "Flow Duration": 0.5,
  "Tot Fwd Pkts": 50000,
  "Tot Bwd Pkts": 10,
  "TotLen Fwd Pkts": 500000,
  "TotLen Bwd Pkts": 50,
  "Flow Pkts/s": 100000,
  "Flow Byts/s": 1000000,
  "SYN Flag Cnt": 50000,
  "ACK Flag Cnt": 5,
  "Down/Up Ratio": 0.001,
}

export default function LiveFlowPredictor() {
  const [mode, setMode] = useState('live') // 'live' or 'manual'
  const [isStreaming, setIsStreaming] = useState(true)
  const [predictions, setPredictions] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  // Manual mode state
  const [jsonInput, setJsonInput] = useState(JSON.stringify(SAMPLE_FLOW_BENIGN, null, 2))

  const streamIntervalRef = useRef(null)
  const lastAlertIdRef = useRef(null)

  // LIVE MODE: Poll /api/alerts continuously
  useEffect(() => {
    if (mode !== 'live' || !isStreaming) return

    const pollAlerts = async () => {
      try {
        setLoading(true)
        const data = await fetchAlerts(10, 1) // Last 10 from last 1 hour

        if (data.alerts && data.alerts.length > 0) {
          // Show only recent alerts we haven't shown yet
          const newAlerts = data.alerts.filter(
            a => !lastAlertIdRef.current || a.timestamp > lastAlertIdRef.current
          )

          if (newAlerts.length > 0) {
            setPredictions([
              ...newAlerts.map(a => ({
                ...a,
                isLive: true,
                timestamp: new Date(a.timestamp).toLocaleTimeString()
              })),
              ...predictions
            ].slice(0, 20)) // Keep last 20

            lastAlertIdRef.current = data.alerts[0].timestamp
          }
        }
        setError(null)
      } catch (err) {
        setError(`Stream error: ${err.message}`)
      } finally {
        setLoading(false)
      }
    }

    // Poll immediately and then every 5 seconds
    pollAlerts()
    streamIntervalRef.current = setInterval(pollAlerts, 5000)

    return () => {
      if (streamIntervalRef.current) clearInterval(streamIntervalRef.current)
    }
  }, [mode, isStreaming])

  // MANUAL MODE: Test custom flow
  const handleManualPredict = async () => {
    try {
      setLoading(true)
      setError(null)

      const features = JSON.parse(jsonInput)
      const result = await predict(features)

      setPredictions([
        {
          ...result,
          isLive: false,
          timestamp: new Date().toLocaleTimeString(),
          source_ip: 'MANUAL TEST',
          attack_prob: result.attack_prob,
          prediction: result.prediction,
          severity: result.severity,
        },
        ...predictions
      ].slice(0, 20))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const severityColor = {
    CRITICAL: 'bg-red-500/20 border-red-500/50 text-red-400',
    HIGH: 'bg-orange-500/20 border-orange-500/50 text-orange-400',
    MEDIUM: 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400',
    LOW: 'bg-blue-500/20 border-blue-500/50 text-blue-400',
    NONE: 'bg-green-500/20 border-green-500/50 text-green-400',
  }

  const predictionColor = {
    ATTACK: 'bg-red-500/20 border-l-4 border-red-500',
    BENIGN: 'bg-green-500/20 border-l-4 border-green-500',
  }

  return (
    <div className="rounded-xl border border-ids-border bg-ids-card p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-ids-text">Flow Predictor</h2>
        <div className="flex items-center gap-2">
          {mode === 'live' && (
            <div className="flex items-center gap-1">
              <div className={`w-2 h-2 rounded-full ${isStreaming ? 'bg-green-500 animate-pulse' : 'bg-gray-500'}`} />
              <span className="text-xs text-ids-muted">{isStreaming ? 'LIVE' : 'PAUSED'}</span>
            </div>
          )}
          <span className="text-xs px-2 py-1 rounded bg-ids-bg text-ids-muted">
            {mode === 'live' ? 'Real-time Monitoring' : 'Manual Testing'}
          </span>
        </div>
      </div>

      {/* Mode Selector */}
      <div className="flex gap-2 border-b border-ids-border">
        <button
          onClick={() => {
            setMode('live')
            setPredictions([])
            lastAlertIdRef.current = null
          }}
          className={`px-3 py-2 text-sm font-medium transition-colors ${
            mode === 'live'
              ? 'text-ids-text border-b-2 border-ids-primary'
              : 'text-ids-muted hover:text-ids-text'
          }`}
        >
          🔴 Live Stream
        </button>
        <button
          onClick={() => setMode('manual')}
          className={`px-3 py-2 text-sm font-medium transition-colors ${
            mode === 'manual'
              ? 'text-ids-text border-b-2 border-ids-primary'
              : 'text-ids-muted hover:text-ids-text'
          }`}
        >
          📝 Manual Test
        </button>
      </div>

      {/* LIVE MODE */}
      {mode === 'live' && (
        <div className="space-y-3">
          <div className="flex gap-2">
            <button
              onClick={() => setIsStreaming(!isStreaming)}
              className={`px-3 py-1 text-xs rounded font-semibold transition-colors ${
                isStreaming
                  ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                  : 'bg-gray-500/20 text-gray-400 hover:bg-gray-500/30'
              }`}
            >
              {isStreaming ? '⏸ Pause Stream' : '▶ Resume Stream'}
            </button>
            <button
              onClick={() => {
                setPredictions([])
                lastAlertIdRef.current = null
              }}
              className="px-3 py-1 text-xs rounded bg-ids-border/50 text-ids-text hover:bg-ids-border transition-colors"
            >
              Clear
            </button>
          </div>

          {error && (
            <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/50 text-orange-400 text-xs">
              {error}
            </div>
          )}

          {loading && predictions.length === 0 && (
            <div className="text-center py-4 text-ids-muted text-sm">
              Connecting to live stream... 🔄
            </div>
          )}

          {/* Predictions Stream */}
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {predictions.length === 0 ? (
              <div className="text-center py-8 text-ids-muted text-sm">
                {isStreaming ? 'Waiting for predictions... (refreshes every 5 seconds)' : 'Stream paused'}
              </div>
            ) : (
              predictions.map((pred, i) => (
                <div
                  key={i}
                  className={`p-3 rounded border ${predictionColor[pred.prediction]} space-y-2`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                        pred.prediction === 'ATTACK'
                          ? 'bg-red-500/30 text-red-300'
                          : 'bg-green-500/30 text-green-300'
                      }`}>
                        {pred.prediction}
                      </span>
                      <span className="text-xs text-ids-muted">{pred.timestamp}</span>
                      {pred.isLive && <span className="text-xs text-green-400">●</span>}
                    </div>
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                      severityColor[pred.severity]
                    }`}>
                      {pred.severity}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-ids-muted">IP:</span>
                      <span className="ml-2 text-ids-text font-mono">{pred.source_ip}</span>
                    </div>
                    <div>
                      <span className="text-ids-muted">Confidence:</span>
                      <span className={`ml-2 font-mono ${
                        pred.prediction === 'ATTACK' ? 'text-red-400' : 'text-green-400'
                      }`}>
                        {(pred.attack_prob * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="pt-2 border-t border-ids-border/50 text-xs text-ids-muted space-y-1">
            <p>🔴 <strong>Live Mode:</strong> Shows real detections from the inference service (every 5s)</p>
            <p>📊 <strong>Source:</strong> Automatically fetches /api/alerts</p>
            <p>⚡ <strong>No manual input needed</strong> — just watch the stream!</p>
          </div>
        </div>
      )}

      {/* MANUAL MODE */}
      {mode === 'manual' && (
        <div className="space-y-3">
          <div className="flex gap-2">
            <button
              onClick={() => setJsonInput(JSON.stringify(SAMPLE_FLOW_BENIGN, null, 2))}
              className="px-2 py-1 text-xs rounded bg-green-500/20 text-green-400 hover:bg-green-500/30 transition-colors"
            >
              Benign Sample
            </button>
            <button
              onClick={() => setJsonInput(JSON.stringify(SAMPLE_FLOW_ATTACK, null, 2))}
              className="px-2 py-1 text-xs rounded bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
            >
              Attack Sample
            </button>
          </div>

          <textarea
            value={jsonInput}
            onChange={(e) => setJsonInput(e.target.value)}
            placeholder="Paste CICFlowMeter JSON with 76 features..."
            className="w-full h-32 p-3 rounded-lg bg-ids-bg border border-ids-border text-ids-text text-sm font-mono resize-none focus:outline-none focus:ring-2 focus:ring-ids-primary/50"
          />

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/50 text-red-400 text-sm">
              {error}
            </div>
          )}

          <button
            onClick={handleManualPredict}
            disabled={loading}
            className="w-full px-4 py-2 rounded-lg bg-ids-primary text-white font-semibold hover:bg-ids-primary/80 disabled:opacity-50 transition-colors"
          >
            {loading ? 'Predicting...' : 'Test Flow'}
          </button>

          {/* Results */}
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {predictions.map((pred, i) => (
              <div
                key={i}
                className={`p-3 rounded border ${predictionColor[pred.prediction]}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                    pred.prediction === 'ATTACK'
                      ? 'bg-red-500/30 text-red-300'
                      : 'bg-green-500/30 text-green-300'
                  }`}>
                    {pred.prediction}
                  </span>
                  <span className="text-xs text-ids-muted">{pred.timestamp}</span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-ids-muted">Confidence:</span>
                    <span className="ml-2 font-mono text-ids-text">
                      {(pred.attack_prob * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div>
                    <span className="text-ids-muted">Severity:</span>
                    <span className={`ml-2 font-semibold ${severityColor[pred.severity]}`}>
                      {pred.severity}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="pt-2 border-t border-ids-border/50 text-xs text-ids-muted space-y-1">
            <p>📝 <strong>Manual Mode:</strong> Test individual flows by pasting JSON</p>
            <p>🧪 <strong>Ad-hoc Testing:</strong> Good for debugging and understanding the model</p>
          </div>
        </div>
      )}
    </div>
  )
}
