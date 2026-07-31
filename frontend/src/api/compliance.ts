import { apiRequest } from './client'

export interface Framework {
  id: string
  name: string
  mapping_only: boolean
}

export interface FrameworkControl {
  control_id: string
  title: string
  description: string
  category: string
  framework: string
}

export interface ControlMapping {
  framework: string
  control_id: string
  title: string
  category: string
}

export interface FindingMapping {
  finding_id: string
  finding_title: string
  severity: string
  controls: ControlMapping[]
}

export interface FrameworkCoverage {
  framework: string
  total_controls: number
  passed: number
  failed: number
  not_assessed: number
  coverage_percent: number
}

export interface GapItem {
  control_id: string
  title: string
  category: string
  status: string
  recommendation: string
}

export interface ExecutiveReport {
  report_id: string
  assessment_id: string
  target: string
  generated_at: string
  overall_coverage_percent: number
  overall_passed: number
  overall_failed: number
  overall_not_assessed: number
  total_controls: number
  frameworks: FrameworkCoverage[]
  recommendations: string[]
}

export interface TechnicalReport {
  report_id: string
  assessment_id: string
  target: string
  generated_at: string
  overall_coverage_percent: number
  frameworks: FrameworkCoverage[]
  finding_mappings: FindingMapping[]
  recommendations: string[]
}

export interface GapRemediationReport {
  report_id: string
  assessment_id: string
  target: string
  generated_at: string
  total_gaps: number
  gaps: GapItem[]
}

export const complianceApi = {
  listFrameworks: () =>
    apiRequest<Framework[]>('/compliance/frameworks'),

  getFrameworkControls: (frameworkId: string) =>
    apiRequest<FrameworkControl[]>(`/compliance/frameworks/${frameworkId}/controls`),

  mapFindings: (findings: Array<{ id: string; title: string; description: string; severity: string }>) =>
    apiRequest<{ mappings: FindingMapping[]; total_mappings: number }>('/compliance/map', {
      method: 'POST',
      body: { findings },
    }),

  calculateCoverage: (params: { mappings: FindingMapping[]; frameworks?: string[] }) =>
    apiRequest<FrameworkCoverage[]>('/compliance/coverage', {
      method: 'POST',
      body: params,
    }),

  analyzeGaps: (params: { framework: string; mappings: FindingMapping[] }) =>
    apiRequest<{ framework: string; total_gaps: number; gaps: GapItem[] }>('/compliance/gaps', {
      method: 'POST',
      body: params,
    }),

  generateReport: (params: {
    assessment_id: string
    target: string
    mappings: FindingMapping[]
    frameworks?: string[]
    type: 'executive' | 'technical' | 'gap_remediation'
  }) =>
    apiRequest<ExecutiveReport | TechnicalReport | GapRemediationReport>('/compliance/report', {
      method: 'POST',
      body: params,
    }),
}
