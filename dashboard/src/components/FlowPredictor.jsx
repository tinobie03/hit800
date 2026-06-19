import React, { useState, useRef } from 'react'
import { predict } from '../utils/api.js'

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

export default function FlowPredictor() {
  const [mode, setMode] = useState('json') // 'json' or 'form'
  const [jsonInput, setJsonInput] = useState(JSON.stringify(SAMPLE_FLOW_BENIGN, null, 2))
  const [prediction, setPrediction] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])
  const formRef = useRef({})

  const handlePredict = async () => {
    try {
      setLoading(true)
      setError(null)

      let features
      if (mode === 'json') {
        features = JSON.parse(jsonInput)
      } else {
        features = formRef.current
      }

      const result = await predict(features)
      setPrediction(result)

      // Add to history
      setHistory([
        { ...result, timestamp: new Date().toLocaleTimeString() },
        ...history.slice(0, 9),
      ])
    } catch (err) {
      setError(err.message)
      setPrediction(null)
    } finally {
      setLoading(false)
    }
  }

  const handleLoadSample = (sample) => {
    setJsonInput(JSON.stringify(sample, null, 2))
    setPrediction(null)
    setError(null)
  }

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (event) => {
      try {
        const data = JSON.parse(event.target.result)
        setJsonInput(JSON.stringify(data, null, 2))
        setError(null)
      } catch (err) {
        setError(`Invalid JSON file: ${err.message}`)
      }
    }
    reader.readAsText(file)
  }

  const severityColor = {
    CRITICAL: 'bg-red-500/20 border-red-500/50 text-red-400',
    HIGH: 'bg-orange-500/20 border-orange-500/50 text-orange-400',
    MEDIUM: 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400',
    LOW: 'bg-blue-500/20 border-blue-500/50 text-blue-400',
    NONE: 'bg-green-500/20 border-green-500/50 text-green-400',
  }

  const predictionColor = {
    ATTACK: 'bg-red-500/20 border-red-500/50',
    BENIGN: 'bg-green-500/20 border-green-500/50',
  }

  return (
    <div className="rounded-xl border border-ids-border bg-ids-card p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-ids-text">Flow Predictor</h2>
        <span className="text-xs px-2 py-1 rounded bg-ids-bg text-ids-muted">Ad-hoc Testing</span>
      </div>

      {/* Input Mode Selector */}
      <div className="flex gap-2 border-b border-ids-border">
        <button
          onClick={() => setMode('json')}
          className={`px-3 py-2 text-sm font-medium transition-colors ${
            mode === 'json'
              ? 'text-ids-text border-b-2 border-ids-primary'
              : 'text-ids-muted hover:text-ids-text'
          }`}
        >
          JSON Input
        </button>
        <button
          onClick={() => setMode('form')}
          className={`px-3 py-2 text-sm font-medium transition-colors ${
            mode === 'form'
              ? 'text-ids-text border-b-2 border-ids-primary'
              : 'text-ids-muted hover:text-ids-text'
          }`}
        >
          Form Input
        </button>
      </div>

      {/* JSON Input Mode */}
      {mode === 'json' && (
        <div className="space-y-3">
          <div className="flex gap-2">
            <button
              onClick={() => handleLoadSample(SAMPLE_FLOW_BENIGN)}
              className="px-2 py-1 text-xs rounded bg-green-500/20 text-green-400 hover:bg-green-500/30 transition-colors"
            >
              Load Benign Sample
            </button>
            <button
              onClick={() => handleLoadSample(SAMPLE_FLOW_ATTACK)}
              className="px-2 py-1 text-xs rounded bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
            >
              Load Attack Sample
            </button>
            <label className="px-2 py-1 text-xs rounded bg-ids-border/50 text-ids-text hover:bg-ids-border transition-colors cursor-pointer">
              Upload JSON
              <input
                type="file"
                accept=".json"
                onChange={handleFileUpload}
                className="hidden"
              />
            </label>
          </div>

          <textarea
            value={jsonInput}
            onChange={(e) => setJsonInput(e.target.value)}
            placeholder="Paste CICFlowMeter JSON with 76 features..."
            className="w-full h-48 p-3 rounded-lg bg-ids-bg border border-ids-border text-ids-text text-sm font-mono resize-none focus:outline-none focus:ring-2 focus:ring-ids-primary/50"
          />
        </div>
      )}

      {/* Form Input Mode */}
      {mode === 'form' && (
        <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto p-2 bg-ids-bg rounded-lg border border-ids-border/50">
          {Object.keys(SAMPLE_FLOW_BENIGN).map((key) => (
            <div key={key} className="flex flex-col gap-1">
              <label className="text-xs text-ids-muted">{key}</label>
              <input
                type="number"
                defaultValue={SAMPLE_FLOW_BENIGN[key]}
                onChange={(e) => {
                  formRef.current[key] = parseFloat(e.target.value) || 0
                }}
                className="px-2 py-1 text-sm rounded bg-ids-card border border-ids-border/50 text-ids-text focus:outline-none focus:ring-1 focus:ring-ids-primary"
              />
            </div>
          ))}
        </div>
      )}

      {/* Error Display */}
      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/50 text-red-400 text-sm">
          <p className="font-semibold">Error:</p>
          <p className="text-xs mt-1">{error}</p>
        </div>
      )}

      {/* Predict Button */}
      <button
        onClick={handlePredict}
        disabled={loading}
        className="w-full px-4 py-2 rounded-lg bg-ids-primary text-white font-semibold hover:bg-ids-primary/80 disabled:opacity-50 transition-colors"
      >
        {loading ? 'Predicting...' : 'Predict Flow'}
      </button>

      {/* Prediction Result */}
      {prediction && (
        <div
          className={`p-4 rounded-lg border-2 ${predictionColor[prediction.prediction]} space-y-3`}
        >
          <div className="flex items-center justify-between">
            <span className="text-sm text-ids-muted">Prediction</span>
            <span className={`px-3 py-1 rounded-full text-sm font-bold ${
              prediction.prediction === 'ATTACK'
                ? 'bg-red-500/30 text-red-300'
                : 'bg-green-500/30 text-green-300'
            }`}>
              {prediction.prediction}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <span className="text-xs text-ids-muted">Confidence</span>
              <div className="mt-1">
                <div className="flex items-baseline gap-2">
                  <span className="text-lg font-bold text-ids-text">
                    {(prediction.attack_prob * 100).toFixed(1)}%
                  </span>
                  <span className="text-xs text-ids-muted">attack</span>
                </div>
                <div className="mt-1 w-full bg-ids-bg rounded-full h-2 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-green-500 to-red-500"
                    style={{ width: `${prediction.attack_prob * 100}%` }}
                  />
                </div>
              </div>
            </div>

            <div>
              <span className="text-xs text-ids-muted">Severity</span>
              <div className={`mt-1 px-3 py-2 rounded ${severityColor[prediction.severity]} text-sm font-semibold`}>
                {prediction.severity}
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-ids-border/50">
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-ids-muted">BENIGN:</span>
                <span className="ml-2 text-green-400 font-mono">
                  {(prediction.probabilities.BENIGN * 100).toFixed(2)}%
                </span>
              </div>
              <div>
                <span className="text-ids-muted">ATTACK:</span>
                <span className="ml-2 text-red-400 font-mono">
                  {(prediction.probabilities.ATTACK * 100).toFixed(2)}%
                </span>
              </div>
              <div>
                <span className="text-ids-muted">Threshold:</span>
                <span className="ml-2 text-ids-text font-mono">{prediction.threshold}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-ids-muted uppercase">Recent Predictions</h3>
          <div className="space-y-1 max-h-32 overflow-y-auto">
            {history.map((item, i) => (
              <div
                key={i}
                className={`flex items-center justify-between p-2 rounded text-xs ${
                  item.prediction === 'ATTACK'
                    ? 'bg-red-500/10 border border-red-500/30'
                    : 'bg-green-500/10 border border-green-500/30'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded font-bold ${
                    item.prediction === 'ATTACK' ? 'bg-red-500/30 text-red-300' : 'bg-green-500/30 text-green-300'
                  }`}>
                    {item.prediction}
                  </span>
                  <span className="text-ids-muted">{item.timestamp}</span>
                </div>
                <span className={`font-mono ${
                  item.prediction === 'ATTACK' ? 'text-red-400' : 'text-green-400'
                }`}>
                  {(item.attack_prob * 100).toFixed(1)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Info */}
      <div className="pt-2 border-t border-ids-border/50 text-xs text-ids-muted space-y-1">
        <p>💡 <strong>Ad-hoc Testing:</strong> Use this to test the CNN model on individual flows.</p>
        <p>📊 <strong>Production Inference:</strong> The background service continuously monitors logs.</p>
        <p>⚡ <strong>Threshold:</strong> attack_prob ≥ {prediction?.threshold ?? 0.50} = ATTACK</p>
      </div>
    </div>
  )
}
