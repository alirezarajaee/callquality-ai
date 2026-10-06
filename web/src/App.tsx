import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties, ChangeEvent, DragEvent } from 'react'
import type {
  AnalyzeResponse,
  CallResult,
  QualityFactor,
  StreamResult,
} from './api'
import { analyzePCAP } from './api'

const API_ENDPOINT = '127.0.0.1:8090'
const MAX_FILE_SIZE = 64 * 1024 * 1024

type MetricIcon = 'pulse' | 'upload' | 'shield' | 'network' | 'brain' | 'alert' | 'clock' | 'packet'

function scoreTone(level: string): string {
  return `tone-${level.toLowerCase().replace(/[^a-z]/g, '')}`
}

function humanize(value: string): string {
  if (!value) return 'Unknown'
  return value
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function formatNumber(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—'
  return value.toFixed(digits)
}

function formatDuration(value: number): string {
  if (value < 1000) return `${Math.round(value)} ms`
  if (value < 60_000) return `${(value / 1000).toFixed(2)} s`
  return `${(value / 60_000).toFixed(2)} min`
}

function percent(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—'
  return `${value.toFixed(1)}%`
}

function formatBytes(value: number): string {
  if (value < 1024 * 1024) return `${Math.max(1, Math.round(value / 1024))} KB`
  return `${(value / (1024 * 1024)).toFixed(1)} MB`
}

function friendlyDiagnosis(value: string): string {
  return value === 'none' || !value ? 'No primary finding' : humanize(value)
}

function Icon({ name }: { name: MetricIcon }) {
  const common = {
    width: 18,
    height: 18,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
  }

  switch (name) {
    case 'pulse':
      return <svg {...common}><path d="M3 12h4l2-7 4 14 2-7h6" /></svg>
    case 'upload':
      return <svg {...common}><path d="M12 16V4m0 0-4 4m4-4 4 4M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4" /></svg>
    case 'shield':
      return <svg {...common}><path d="M12 3l7 3v5c0 4.7-2.9 8-7 10-4.1-2-7-5.3-7-10V6l7-3z" /><path d="m9 12 2 2 4-4" /></svg>
    case 'network':
      return <svg {...common}><rect x="9" y="3" width="6" height="6" rx="1" /><rect x="3" y="15" width="6" height="6" rx="1" /><rect x="15" y="15" width="6" height="6" rx="1" /><path d="M12 9v3M6 15v-3h12v3" /></svg>
    case 'brain':
      return <svg {...common}><path d="M9.4 4.2a3 3 0 0 0-5.4 2 3.3 3.3 0 0 0 .7 2 3.1 3.1 0 0 0 0 5.6A3.1 3.1 0 0 0 7.8 19a3 3 0 0 0 4.2-2.1A3 3 0 0 0 16.2 19a3.1 3.1 0 0 0 3.1-5.2 3.1 3.1 0 0 0 0-5.6 3.1 3.1 0 0 0-5.3-4A3.2 3.2 0 0 0 9.4 4.2Z" /><path d="M12 4v16M8.4 8.5H12M12 12h3.6M8.4 15.5H12" /></svg>
    case 'alert':
      return <svg {...common}><path d="M12 4l8 15H4L12 4z" /><path d="M12 9v5m0 3h.01" /></svg>
    case 'clock':
      return <svg {...common}><circle cx="12" cy="12" r="8.5" /><path d="M12 7v5l3 2" /></svg>
    case 'packet':
      return <svg {...common}><rect x="4" y="5" width="16" height="14" rx="2" /><path d="M8 9h8M8 12h5M8 15h8" /></svg>
  }
}

function ScoreRing({ score, level }: { score: number | null; level: string }) {
  const safeScore = Math.max(0, Math.min(100, score ?? 0))
  return (
    <div
      className={`score-ring ${scoreTone(level)}`}
      style={{ '--score': `${safeScore * 3.6}deg` } as CSSProperties}
      aria-label={`Quality score ${formatNumber(score, 0)} out of 100`}
    >
      <div className="score-ring__inner">
        <span className="score-ring__value">{formatNumber(score, 0)}</span>
        <span className="score-ring__label">/ 100</span>
      </div>
    </div>
  )
}

function MetricCard({ label, value, unit, icon, hint }: {
  label: string
  value: string
  unit?: string
  icon: MetricIcon
  hint?: string
}) {
  return (
    <article className="metric-card">
      <div className="metric-card__top">
        <span className="metric-card__icon"><Icon name={icon} /></span>
        <span>{label}</span>
      </div>
      <div className="metric-card__value">
        {value}
        {unit && <small>{unit}</small>}
      </div>
      {hint && <div className="metric-card__hint">{hint}</div>}
    </article>
  )
}

function FactorBar({ factor }: { factor: QualityFactor }) {
  const normalized = Math.max(0, Math.min(100, factor.penalty))
  return (
    <div className="factor-row">
      <div className="factor-row__head">
        <span>{humanize(factor.name)}</span>
        <strong>{formatNumber(factor.value, factor.unit === 'percent' ? 1 : 2)} {factor.unit}</strong>
      </div>
      <div className="factor-row__track"><span style={{ width: `${normalized}%` }} /></div>
    </div>
  )
}

function ProbabilityBars({ stream }: { stream: StreamResult }) {
  const probabilities = [...stream.ml.probabilities].sort((a, b) => b.value - a.value)
  return (
    <div className="probability-list">
      {probabilities.map((item) => (
        <div className="probability-row" key={item.class}>
          <span className={`probability-row__label ${scoreTone(item.class)}`}>{item.class}</span>
          <div className="probability-row__track">
            <span
              className={`probability-row__fill ${scoreTone(item.class)}`}
              style={{ width: `${Math.max(0, Math.min(100, item.value * 100))}%` }}
            />
          </div>
          <strong>{percent(item.value * 100)}</strong>
        </div>
      ))}
    </div>
  )
}

function StreamPanel({ stream, index }: { stream: StreamResult; index: number }) {
  const level = stream.quality.level || stream.ml.predicted_class
  const primaryFinding = stream.diagnosis.primary_finding ?? 'none'
  const metricRows = [
    ['RTP Loss', percent(stream.rtp.loss_percent)],
    ['Jitter', `${formatNumber(stream.rtp.jitter_ms, 2)} ms`],
    ['Passive RTT', `${formatNumber(stream.rtcp.average_passive_rtt_ms, 1)} ms`],
    ['Reordering', percent(stream.quality.effective.out_of_order_percent)],
    ['Duplicates', percent(stream.quality.effective.duplicate_percent)],
  ]

  return (
    <article className="stream-card">
      <div className="stream-card__header">
        <div>
          <div className="eyebrow">MEDIA STREAM {String(index + 1).padStart(2, '0')}</div>
          <div className="stream-title-line">
            <h3>SSRC {stream.ssrc}</h3>
            <span className={`status-pill ${scoreTone(level)}`}>{humanize(level)}</span>
          </div>
          <p>{stream.codec} · PT {stream.payload_type} · {stream.clock_rate} Hz · {stream.media_direction}</p>
        </div>
        <div className="stream-card__model-chip"><Icon name="brain" /> native ML</div>
      </div>

      <div className="stream-grid">
        <div className="stream-section stream-section--quality">
          <div className="stream-section__title"><Icon name="pulse" /> Engineering quality</div>
          <div className="stream-quality">
            <ScoreRing score={stream.quality.score} level={level} />
            <div className="stream-quality__copy">
              <strong>{humanize(level)}</strong>
              <span>Primary factor · {humanize(stream.quality.primary_factor || 'unknown')}</span>
              <span>Effective loss · {humanize(stream.quality.effective.loss_source || 'unavailable')}</span>
              <span>Effective jitter · {humanize(stream.quality.effective.jitter_source || 'unavailable')}</span>
            </div>
          </div>
          <div className="factor-list">
            {stream.quality.factors.map((factor) => <FactorBar factor={factor} key={factor.name} />)}
          </div>
        </div>

        <div className="stream-section stream-section--ml">
          <div className="stream-section__title"><Icon name="brain" /> ML intelligence</div>
          <div className="ml-banner">
            <div>
              <span>Predicted class</span>
              <strong className={scoreTone(stream.ml.predicted_class)}>{humanize(stream.ml.predicted_class)}</strong>
            </div>
            <div className="ml-vote">{percent(stream.ml.max_class_vote * 100)}<small>max vote</small></div>
          </div>
          <ProbabilityBars stream={stream} />
          <div className="ml-footnote">Model {stream.ml.model_version} · native inference</div>
        </div>
      </div>

      <div className="stream-stats">
        {metricRows.map(([label, value]) => (
          <div key={label}><span>{label}</span><strong>{value}</strong></div>
        ))}
      </div>

      <div className="stream-bottom-grid">
        <div className="info-card">
          <span className="info-card__label">E-model / MOS</span>
          <strong>{formatNumber(stream.emodel.mos, 3)}</strong>
          <small>R-factor {formatNumber(stream.emodel.r_factor, 1)}</small>
        </div>
        <div className="info-card">
          <span className="info-card__label">Diagnosis</span>
          <strong>{friendlyDiagnosis(primaryFinding)}</strong>
          <small>{stream.diagnosis.findings.length} finding{stream.diagnosis.findings.length === 1 ? '' : 's'}</small>
        </div>
        <div className="info-card">
          <span className="info-card__label">RTCP telemetry</span>
          <strong>{stream.rtcp.available ? 'Available' : 'Unavailable'}</strong>
          <small>{stream.rtcp.observation_count} observation{stream.rtcp.observation_count === 1 ? '' : 's'}</small>
        </div>
      </div>

      {stream.diagnosis.findings.length > 0 && (
        <div className="finding-list">
          <div className="finding-list__header"><span className="eyebrow">EVIDENCE</span><span>{stream.diagnosis.findings.length} findings</span></div>
          {stream.diagnosis.findings.map((finding) => (
            <div className="finding" key={`${finding.code}-${finding.value}`}>
              <span className={`finding__dot severity-${finding.severity}`} />
              <div>
                <strong>{finding.title}</strong>
                <p>{finding.description}</p>
              </div>
              <span className="finding__confidence">{percent(finding.confidence * 100)}</span>
            </div>
          ))}
        </div>
      )}
    </article>
  )
}

function AnalysisView({ result, onReset }: { result: AnalyzeResponse; onReset: () => void }) {
  const [selectedCallIndex, setSelectedCallIndex] = useState(0)
  const call: CallResult | undefined = result.calls[selectedCallIndex]

  const qualityLevel = call?.overall_level ?? 'unknown'
  const diagnosis = call?.primary_diagnosis ?? 'none'
  const worstStream = useMemo(() => {
    if (!call?.streams.length) return undefined
    return [...call.streams].sort((a, b) => (a.quality.score ?? Number.POSITIVE_INFINITY) - (b.quality.score ?? Number.POSITIVE_INFINITY))[0]
  }, [call])
  const modelStream = worstStream ?? call?.streams[0]

  useEffect(() => {
    if (selectedCallIndex > result.calls.length - 1) setSelectedCallIndex(0)
  }, [result.calls.length, selectedCallIndex])

  return (
    <>
      <section className="analysis-hero">
        <div className="analysis-hero__main">
          <div className="analysis-meta-row">
            <span className="eyebrow">ANALYSIS COMPLETE</span>
            <span className="meta-dot" />
            <span className="analysis-filename" title={result.source.filename}>{result.source.filename}</span>
          </div>
          <div className="hero-title-row">
            <div>
              <div className="hero-kicker">CALLQUALITY ENGINEERING ASSESSMENT</div>
              <h1>{humanize(qualityLevel)}</h1>
              <p>Overall assessment across {result.capture.calls_reconstructed} reconstructed call{result.capture.calls_reconstructed === 1 ? '' : 's'} and {call?.stream_count ?? 0} media stream{call?.stream_count === 1 ? '' : 's'}.</p>
            </div>
            <span className={`status-pill status-pill--large ${scoreTone(qualityLevel)}`}>{humanize(qualityLevel)}</span>
          </div>
        </div>
        <div className="hero-score-wrap">
          <div className="hero-score-caption">OVERALL SCORE</div>
          <ScoreRing score={call?.overall_score ?? null} level={qualityLevel} />
        </div>
      </section>

      {result.calls.length > 1 && (
        <div className="call-selector-wrap">
          <div className="section-label">RECONSTRUCTED CALLS</div>
          <div className="call-selector">
            {result.calls.map((item, index) => (
              <button key={item.call_id} className={index === selectedCallIndex ? 'is-active' : ''} onClick={() => setSelectedCallIndex(index)}>
                <span>{String(index + 1).padStart(2, '0')}</span>
                <strong>{item.call_id}</strong>
                <em>{humanize(item.overall_level)}</em>
              </button>
            ))}
          </div>
        </div>
      )}

      {!call && (
        <section className="empty-result panel">
          <div className="empty-result__icon"><Icon name="network" /></div>
          <div>
            <div className="eyebrow">NO RECONSTRUCTED CALLS</div>
            <h2>No analyzable call was found in this capture.</h2>
            <p>The API returned capture data, but there is no call result to render.</p>
          </div>
        </section>
      )}

      {call && (
        <>
          <section className="metrics-grid">
            <MetricCard label="Setup time" value={formatDuration(call.setup_duration_ms)} icon="clock" />
            <MetricCard label="Call duration" value={formatDuration(call.call_duration_ms)} icon="clock" />
            <MetricCard label="Average MOS" value={formatNumber(call.average_mos, 3)} hint="E-model network baseline" icon="pulse" />
            <MetricCard
              label="ML prediction"
              value={humanize(modelStream?.ml.predicted_class ?? qualityLevel)}
              hint={modelStream ? `${percent(modelStream.ml.max_class_vote * 100)} max vote · worst stream` : undefined}
              icon="brain"
            />
            <MetricCard label="Packets" value={String(result.capture.packets_analyzed)} hint={`${result.capture.rtcp_streams} RTCP streams`} icon="packet" />
            <MetricCard label="Primary diagnosis" value={friendlyDiagnosis(diagnosis)} hint={call.primary_diagnosis_ssrc != null ? `SSRC ${call.primary_diagnosis_ssrc}` : 'Call-level finding'} icon="alert" />
          </section>

          <section className="snapshot-grid">
            <article className="panel signal-panel">
              <div className="panel__header"><div><div className="eyebrow">CAPTURE TELEMETRY</div><h2>Signal path</h2></div><span className="live-dot"><i /> ready</span></div>
              <div className="signal-path">
                <div><span className="signal-icon"><Icon name="network" /></span><div><strong>{result.capture.sip_packets}</strong><small>SIP packets</small></div></div>
                <span className="signal-line" />
                <div><span className="signal-icon"><Icon name="packet" /></span><div><strong>{call.stream_count}</strong><small>media streams</small></div></div>
                <span className="signal-line" />
                <div><span className="signal-icon"><Icon name="shield" /></span><div><strong>{result.capture.rtcp_streams}</strong><small>RTCP streams</small></div></div>
                <span className="signal-line" />
                <div><span className="signal-icon"><Icon name="brain" /></span><div><strong>{call.analyzed_stream_count}</strong><small>ML analyzed</small></div></div>
              </div>
              <div className="capture-subgrid">
                <div><span>SIP requests</span><strong>{result.capture.sip_requests}</strong></div>
                <div><span>SIP responses</span><strong>{result.capture.sip_responses}</strong></div>
                <div><span>Schema</span><strong>{result.schema_version}</strong></div>
              </div>
            </article>

            <article className={`panel diagnosis-panel ${scoreTone(qualityLevel)}`}>
              <div className="panel__header"><div><div className="eyebrow">ROOT SIGNAL</div><h2>Primary diagnosis</h2></div><span className="diagnosis-icon"><Icon name="alert" /></span></div>
              <div className="diagnosis-highlight">
                <strong>{friendlyDiagnosis(diagnosis)}</strong>
                <span>{call.primary_diagnosis_ssrc != null ? `SSRC ${call.primary_diagnosis_ssrc}` : 'No primary SSRC attached'}</span>
              </div>
              <div className="diagnosis-note"><Icon name="shield" /><span>Call-level diagnosis stays separate from directional stream findings so the evidence trail remains traceable.</span></div>
            </article>
          </section>

          <section className="stream-section-wrap">
            <div className="section-heading">
              <div><div className="eyebrow">MEDIA DEEP DIVE</div><h2>Stream intelligence</h2></div>
              <span>{call.streams.length} stream{call.streams.length === 1 ? '' : 's'} · {call.analyzed_stream_count} ML analyzed</span>
            </div>
            <div className="stream-list">
              {call.streams.map((stream, index) => <StreamPanel key={`${stream.ssrc}-${index}`} stream={stream} index={index} />)}
            </div>
          </section>
        </>
      )}

      <button className="secondary-button reset-button" onClick={onReset}><Icon name="upload" /> Analyze another capture</button>
    </>
  )
}

function App() {
  const inputRef = useRef<HTMLInputElement>(null)
  const abortRef = useRef<AbortController | null>(null)
  const [result, setResult] = useState<AnalyzeResponse | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedName, setSelectedName] = useState('')
  const [apiOnline, setApiOnline] = useState<boolean | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    const timer = window.setTimeout(() => controller.abort(), 2500)

    void fetch('/api/v1/health', { signal: controller.signal })
      .then((response) => setApiOnline(response.ok))
      .catch(() => setApiOnline(false))
      .finally(() => window.clearTimeout(timer))

    return () => {
      window.clearTimeout(timer)
      controller.abort()
    }
  }, [])

  const runAnalysis = useCallback(async (file: File) => {
    const lowerName = file.name.toLowerCase()
    if (!lowerName.endsWith('.pcap')) {
      setError('Please choose a classic .pcap capture file.')
      return
    }
    if (file.size > MAX_FILE_SIZE) {
      setError(`This capture is ${formatBytes(file.size)}. The dashboard limit is ${formatBytes(MAX_FILE_SIZE)}.`)
      return
    }

    setError(null)
    setSelectedName(file.name)
    setIsAnalyzing(true)
    setApiOnline(true)
    abortRef.current?.abort()
    abortRef.current = new AbortController()

    try {
      const data = await analyzePCAP(file, abortRef.current.signal)
      setResult(data)
    } catch (analysisError) {
      if (analysisError instanceof DOMException && analysisError.name === 'AbortError') return
      setApiOnline(false)
      setError(analysisError instanceof Error ? analysisError.message : 'Analysis failed.')
    } finally {
      setIsAnalyzing(false)
    }
  }, [])

  const selectFile = useCallback(() => inputRef.current?.click(), [])

  const onFileChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) void runAnalysis(file)
    event.target.value = ''
  }, [runAnalysis])

  const onDragOver = useCallback((event: DragEvent<HTMLElement>) => {
    event.preventDefault()
    setIsDragging(true)
  }, [])

  const onDragLeave = useCallback((event: DragEvent<HTMLElement>) => {
    const related = event.relatedTarget as Node | null
    if (!related || !event.currentTarget.contains(related)) setIsDragging(false)
  }, [])

  const onDrop = useCallback((event: DragEvent<HTMLElement>) => {
    event.preventDefault()
    setIsDragging(false)
    const file = event.dataTransfer.files?.[0]
    if (file) void runAnalysis(file)
  }, [runAnalysis])

  const reset = useCallback(() => {
    abortRef.current?.abort()
    setResult(null)
    setError(null)
    setSelectedName('')
    setIsAnalyzing(false)
  }, [])

  return (
    <div className="app-shell">
      <div className="ambient-grid" />
      <div className="ambient-glow ambient-glow--one" />
      <div className="ambient-glow ambient-glow--two" />

      <header className="topbar">
        <button className="brand" onClick={reset} type="button" aria-label="Back to CallQuality AI home">
          <div className="brand-mark"><Icon name="pulse" /></div>
          <div><strong>CallQuality</strong><span>AI</span></div>
        </button>
        <div className="topbar__right">
          <div className="endpoint-chip endpoint-chip--web"><span>WEB</span><strong>{window.location.host}</strong></div>
          <div className="endpoint-chip endpoint-chip--api"><span>API</span><strong>{API_ENDPOINT}</strong></div>
          <div className={`engine-status ${apiOnline === false ? 'is-offline' : apiOnline === true ? 'is-online' : 'is-checking'}`}>
            <i /> {apiOnline === false ? 'offline' : apiOnline === true ? 'online' : 'checking'}
          </div>
        </div>
      </header>

      <main
        className={`main-shell ${isDragging ? 'is-dragging' : ''}`}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
      >
        <input ref={inputRef} type="file" accept=".pcap" hidden onChange={onFileChange} />

        {!result && !isAnalyzing && (
          <section className="intro intro--control-room">
            <div className="intro__copy">
              <div className="eyebrow"><span className="eyebrow-line" /> REAL-TIME VOIP OBSERVABILITY</div>
              <h1>See where the<br /><em>call breaks.</em></h1>
              <p>Inspect SIP signaling, trace RTP media, correlate RTCP telemetry and surface network impairments — then compare the engineering verdict with native ML.</p>

              <div className="intro__command-row">
                <button className="primary-button intro__primary" type="button" onClick={selectFile}><Icon name="upload" /> Analyze PCAP</button>
                <div className="intro__security"><span className="micro-dot" /> Local-first · no cloud upload</div>
              </div>

              <div className="pipeline-card">
                <div className="pipeline-card__top"><span className="eyebrow">ANALYSIS PIPELINE</span><span className="pipeline-live"><i /> READY</span></div>
                <div className="pipeline-flow">
                  <div className="pipeline-node"><span><Icon name="network" /></span><strong>SIP</strong><small>signaling</small></div>
                  <div className="pipeline-connector"><i /><i /><i /></div>
                  <div className="pipeline-node"><span><Icon name="packet" /></span><strong>RTP</strong><small>media</small></div>
                  <div className="pipeline-connector"><i /><i /><i /></div>
                  <div className="pipeline-node"><span><Icon name="shield" /></span><strong>RTCP</strong><small>telemetry</small></div>
                  <div className="pipeline-connector"><i /><i /><i /></div>
                  <div className="pipeline-node pipeline-node--ai"><span><Icon name="brain" /></span><strong>ML</strong><small>inference</small></div>
                </div>
              </div>
            </div>

            <button
              className={`capture-console ${isDragging ? 'is-active' : ''}`}
              onClick={selectFile}
              type="button"
              aria-label="Select a PCAP capture for analysis"
            >
              <div className="capture-console__grid" />
              <div className="capture-console__halo capture-console__halo--one" />
              <div className="capture-console__halo capture-console__halo--two" />
              <div className="capture-console__ring capture-console__ring--outer" />
              <div className="capture-console__ring capture-console__ring--inner" />
              <div className="capture-console__orbit capture-console__orbit--a"><i /></div>
              <div className="capture-console__orbit capture-console__orbit--b"><i /></div>
              <div className="capture-console__center">
                <div className="dropzone__icon"><Icon name="upload" /></div>
                <div className="eyebrow">{selectedName || 'PCAP CAPTURE'}</div>
                <h2>{isDragging ? 'Release to analyze' : 'Drop your capture'}</h2>
                <p>or browse for a <strong>.pcap</strong> file</p>
                <span className="dropzone__button"><Icon name="upload" /> Choose capture</span>
              </div>
              <div className="capture-console__telemetry">
                <span><i /> local</span><span>64 MB max</span><span>offline-safe</span>
              </div>
            </button>
          </section>
        )}

        {isAnalyzing && (
          <section className="loading-state loading-state--console">
            <div className="loading-console-visual">
              <div className="loading-console-visual__core"><Icon name="pulse" /></div>
              <div className="loading-console-visual__ring ring-a" />
              <div className="loading-console-visual__ring ring-b" />
              <div className="loading-console-visual__ring ring-c" />
              <span className="loading-packet p1" /><span className="loading-packet p2" /><span className="loading-packet p3" />
            </div>
            <div className="eyebrow">ANALYSIS IN PROGRESS · {selectedName}</div>
            <h2>Tracing the media path<span className="loading-dots">...</span></h2>
            <p>Decoding signaling, correlating RTP + RTCP, computing engineering quality and running native ML.</p>
            <div className="loading-steps"><span className="active">capture</span><span className="active">signaling</span><span className="active">media</span><span className="active">quality</span><span className="active">ml</span></div>
          </section>
        )}

        {error && (
          <div className="error-banner" role="alert">
            <span className="error-banner__icon"><Icon name="alert" /></span>
            <div><strong>Analysis failed</strong><span>{error}</span></div>
            <button onClick={() => setError(null)} type="button">Dismiss</button>
          </div>
        )}

        {result && !isAnalyzing && <AnalysisView result={result} onReset={reset} />}
      </main>

      <footer className="footer"><span>CALLQUALITY AI · LOCAL VOIP ANALYTICS</span><span>v0.1.0 · schema 1.0</span></footer>
    </div>
  )
}

export default App
