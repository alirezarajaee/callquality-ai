export type QualityLevel = 'excellent' | 'good' | 'fair' | 'poor' | 'critical' | 'unknown' | string

export interface Probability {
  class: string
  value: number
}

export interface RTPMetrics {
  packet_count: number
  unique_packets: number
  duplicate_packets: number
  out_of_order_packets: number
  expected_packets: number
  lost_packets: number
  loss_percent: number
  jitter_ms: number | null
}

export interface RTCPMetrics {
  available: boolean
  observation_count: number
  latest_loss_percent: number | null
  average_loss_percent: number | null
  latest_jitter_ms: number | null
  average_jitter_ms: number | null
  latest_passive_rtt_ms: number | null
  average_passive_rtt_ms: number | null
}

export interface QualityFactor {
  name: string
  value: number
  unit: string
  penalty: number
  available: boolean
}

export interface QualityMetrics {
  available: boolean
  score: number | null
  level: string
  primary_factor: string
  effective: {
    loss_percent: number
    loss_source: string
    jitter_ms: number
    jitter_source: string
    rtt_ms: number
    rtt_source: string
    out_of_order_percent: number
    duplicate_percent: number
  }
  factors: QualityFactor[]
}

export interface EModelMetrics {
  available: boolean
  model_version: string
  r_factor: number | null
  mos: number | null
  one_way_delay_ms: number | null
  packet_loss_percent: number | null
  delay_source: string
  loss_source: string
}

export interface DiagnosisFinding {
  code: string
  severity: string
  title: string
  description: string
  value: number
  unit: string
  threshold: number
  available: boolean
  confidence: number
}

export interface DiagnosisMetrics {
  available: boolean
  primary_finding?: string
  quality_level?: string
  quality_score?: number | null
  findings: DiagnosisFinding[]
}

export interface MLMetrics {
  model_version: string
  predicted_class: string
  max_class_vote: number
  probabilities: Probability[]
}

export interface StreamResult {
  ssrc: number
  media_index: number
  stream_id: string
  payload_type: number
  codec: string
  clock_rate: number
  codec_channels: number
  media_direction: string
  rtp: RTPMetrics
  rtcp: RTCPMetrics
  quality: QualityMetrics
  emodel: EModelMetrics
  diagnosis: DiagnosisMetrics
  ml: MLMetrics
}

export interface CallResult {
  call_id: string
  state: string
  setup_duration_ms: number
  call_duration_ms: number
  final_response_code: number
  stream_count: number
  analyzed_stream_count: number
  average_score: number | null
  overall_score: number | null
  overall_level: string
  average_r_factor: number | null
  average_mos: number | null
  primary_diagnosis: string
  primary_diagnosis_ssrc?: number | null
  streams: StreamResult[]
}

export interface AnalyzeResponse {
  schema_version: string
  source: { filename: string }
  capture: {
    packets_analyzed: number
    sip_packets: number
    sip_requests: number
    sip_responses: number
    calls_reconstructed: number
    rtcp_streams: number
  }
  calls: CallResult[]
}

interface APIErrorBody {
  error?: {
    code?: string
    message?: string
  }
}

export async function analyzePCAP(file: File, signal?: AbortSignal): Promise<AnalyzeResponse> {
  const formData = new FormData()
  formData.append('file', file, file.name)

  const response = await fetch('/api/v1/analyze', {
    method: 'POST',
    body: formData,
    signal,
  })

  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as APIErrorBody | null
    const message = body?.error?.message ?? `Analysis failed with HTTP ${response.status}`
    throw new Error(message)
  }

  return (await response.json()) as AnalyzeResponse
}
