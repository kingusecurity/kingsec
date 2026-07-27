export type ExecutionPhase =
  | 'pending'
  | 'preparing'
  | 'running_scanners'
  | 'correlating'
  | 'reporting'
  | 'completed'
  | 'failed'
  | 'cancelled'

export type ScannerProgressStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped'

export interface ScannerProgress {
  scanner_id: string
  name: string
  status: ScannerProgressStatus
  start_time: string | null
  end_time: string | null
  duration_seconds: number | null
  findings_count: number
  warnings: string[]
  error: string | null
  skipped_reason: string | null
}

export interface ExecutionEvent {
  event_type: string
  scanner_id: string | null
  timestamp: string
  message: string
  progress_percent: number
}

export interface ExecutionStatus {
  assessment_id: string
  phase: ExecutionPhase
  progress_percent: number
  scanner_progress: ScannerProgress[]
  started_at: string | null
  completed_at: string | null
  error_message: string | null
}

export interface ExecutionEventsResponse {
  assessment_id: string
  events: ExecutionEvent[]
}

export interface ExecutionProgressResponse {
  assessment_id: string
  progress_percent: number
}
