import { apiRequest } from './client'

export interface ExplainFindingResult {
  plain_english: string
  business_impact: string
  technical_impact: string
  risk: string
  recommendation: string
  cvss_score: number | null
}

export interface ExecutiveSummaryResult {
  overall_risk: string
  key_findings: string[]
  immediate_actions: string[]
  long_term_improvements: string[]
  risk_score: number | null
  assessment_id: string
  target: string
}

export interface RemediationPlanResult {
  prioritized_fixes: Array<{
    finding_title: string
    effort: string
    risk_reduction: string
    dependencies: string[]
  }>
}

export interface ChatResult {
  answer: string
  question: string
  suggested_questions: string[]
}

export interface AIHealthResult {
  available: boolean
  provider: string
  model: string
  error?: string
}

export const aiAssistantApi = {
  explainFinding: (findingId: string, assessmentId: string) =>
    apiRequest<ExplainFindingResult>('/api/v1/ai/explain-finding', {
      method: 'POST',
      body: JSON.stringify({ finding_id: findingId, assessment_id: assessmentId }),
    }),

  executiveSummary: (assessmentId: string) =>
    apiRequest<ExecutiveSummaryResult>('/api/v1/ai/executive-summary', {
      method: 'POST',
      body: JSON.stringify({ assessment_id: assessmentId }),
    }),

  remediationPlan: (assessmentId: string) =>
    apiRequest<RemediationPlanResult>('/api/v1/ai/remediation-plan', {
      method: 'POST',
      body: JSON.stringify({ assessment_id: assessmentId }),
    }),

  chat: (question: string, history: Array<{ role: string; content: string }>, assessmentId?: string) =>
    apiRequest<ChatResult>('/api/v1/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ question, history, assessment_id: assessmentId }),
    }),

  health: () =>
    apiRequest<AIHealthResult>('/api/v1/ai/health'),
}
