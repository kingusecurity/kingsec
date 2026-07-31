import { apiRequest } from './client'

export interface CopilotMessage {
  role: 'user' | 'assistant'
  content: string
  timestamp: string
}

export interface CopilotConversation {
  id: string
  title: string
  assessment_id: string | null
  finding_id: string | null
  asset_id: string | null
  cve_id: string | null
  alert_id: string | null
  exposure_id: string | null
  messages: CopilotMessage[]
  created_at: string
  updated_at: string
}

export interface InvestigationNote {
  id: string
  conversation_id: string
  content: string
  author: string
  pinned: boolean
  assessment_id: string | null
  finding_id: string | null
  tags: string[]
  created_at: string
  updated_at: string
}

export interface PromptTemplate {
  id: string
  name: string
  category: string
  description: string
  is_builtin: boolean
}

export interface AskResult {
  answer: string
  question: string
  conversation_id: string
  suggested_questions: string[]
  context: {
    investigation_type: string
    finding: Record<string, unknown> | null
    assessment: Record<string, unknown> | null
    asset: Record<string, unknown> | null
    cve: Record<string, unknown> | null
    alert: Record<string, unknown> | null
    exposure: Record<string, unknown> | null
  }
}

// --- Conversations ---

export function createConversation(body: {
  title?: string
  assessment_id?: string
  finding_id?: string
  asset_id?: string
  cve_id?: string
  alert_id?: string
  exposure_id?: string
}): Promise<CopilotConversation> {
  return apiRequest('/copilot/conversations', { method: 'POST', body })
}

export function listConversations(params?: {
  assessment_id?: string
  finding_id?: string
  asset_id?: string
  cve_id?: string
  limit?: number
}): Promise<CopilotConversation[]> {
  const searchParams = new URLSearchParams()
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null) searchParams.set(k, String(v))
    })
  }
  return apiRequest(`/copilot/conversations?${searchParams.toString()}`)
}

export function searchConversations(q: string, limit?: number): Promise<CopilotConversation[]> {
  const params = new URLSearchParams({ q })
  if (limit) params.set('limit', String(limit))
  return apiRequest(`/copilot/conversations/search?${params.toString()}`)
}

export function getConversation(id: string): Promise<CopilotConversation> {
  return apiRequest(`/copilot/conversations/${encodeURIComponent(id)}`)
}

export function deleteConversation(id: string): Promise<{ status: string }> {
  return apiRequest(`/copilot/conversations/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

// --- Ask ---

export function askCopilot(body: {
  conversation_id: string
  question: string
  template_id?: string
}): Promise<AskResult> {
  return apiRequest('/copilot/ask', { method: 'POST', body })
}

// --- Templates ---

export function listPromptTemplates(): Promise<PromptTemplate[]> {
  return apiRequest('/copilot/templates')
}

// --- Notes ---

export function createNote(body: {
  conversation_id: string
  content: string
  assessment_id?: string
  finding_id?: string
}): Promise<InvestigationNote> {
  return apiRequest('/copilot/notes', { method: 'POST', body })
}

export function listNotes(params?: {
  conversation_id?: string
  assessment_id?: string
  finding_id?: string
  pinned_only?: boolean
  limit?: number
}): Promise<InvestigationNote[]> {
  const searchParams = new URLSearchParams()
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null) searchParams.set(k, String(v))
    })
  }
  return apiRequest(`/copilot/notes?${searchParams.toString()}`)
}

export function getNote(id: string): Promise<InvestigationNote> {
  return apiRequest(`/copilot/notes/${encodeURIComponent(id)}`)
}

export function updateNote(id: string, content: string): Promise<InvestigationNote> {
  return apiRequest(`/copilot/notes/${encodeURIComponent(id)}`, { method: 'PUT', body: { content } })
}

export function pinNote(id: string): Promise<InvestigationNote> {
  return apiRequest(`/copilot/notes/${encodeURIComponent(id)}/pin`, { method: 'POST' })
}

export function unpinNote(id: string): Promise<InvestigationNote> {
  return apiRequest(`/copilot/notes/${encodeURIComponent(id)}/unpin`, { method: 'POST' })
}

export function deleteNote(id: string): Promise<{ status: string }> {
  return apiRequest(`/copilot/notes/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

// --- Export ---

export function exportMarkdown(conversationId: string): Promise<{ markdown: string }> {
  return apiRequest(`/copilot/export/${encodeURIComponent(conversationId)}/markdown`)
}

export function exportJson(conversationId: string): Promise<Record<string, unknown>> {
  return apiRequest(`/copilot/export/${encodeURIComponent(conversationId)}/json`)
}
