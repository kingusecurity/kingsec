import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import * as copilot from '../api/copilot'

// --- Conversations ---

export function useCreateConversation() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Parameters<typeof copilot.createConversation>[0]) => copilot.createConversation(body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['copilot-conversations'] }) },
  })
}

export function useConversations(params?: {
  assessment_id?: string
  finding_id?: string
  asset_id?: string
  cve_id?: string
  limit?: number
}) {
  return useQuery({
    queryKey: ['copilot-conversations', params],
    queryFn: () => copilot.listConversations(params),
  })
}

export function useSearchConversations(q: string) {
  return useQuery({
    queryKey: ['copilot-conversations-search', q],
    queryFn: () => copilot.searchConversations(q),
    enabled: q.length > 0,
  })
}

export function useConversation(id: string | undefined) {
  return useQuery({
    queryKey: ['copilot-conversation', id],
    queryFn: () => copilot.getConversation(id!),
    enabled: !!id,
  })
}

export function useDeleteConversation() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => copilot.deleteConversation(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['copilot-conversations'] }) },
  })
}

// --- Ask ---

export function useAskCopilot() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Parameters<typeof copilot.askCopilot>[0]) => copilot.askCopilot(body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['copilot-conversation'] }) },
  })
}

// --- Templates ---

export function usePromptTemplates() {
  return useQuery({
    queryKey: ['copilot-templates'],
    queryFn: copilot.listPromptTemplates,
    staleTime: 300_000,
  })
}

// --- Notes ---

export function useCreateNote() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Parameters<typeof copilot.createNote>[0]) => copilot.createNote(body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['copilot-notes'] }) },
  })
}

export function useNotes(params?: {
  conversation_id?: string
  assessment_id?: string
  finding_id?: string
  pinned_only?: boolean
  limit?: number
}) {
  return useQuery({
    queryKey: ['copilot-notes', params],
    queryFn: () => copilot.listNotes(params),
  })
}

export function useNote(id: string | undefined) {
  return useQuery({
    queryKey: ['copilot-note', id],
    queryFn: () => copilot.getNote(id!),
    enabled: !!id,
  })
}

export function useUpdateNote() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, content }: { id: string; content: string }) => copilot.updateNote(id, content),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['copilot-notes'] }) },
  })
}

export function usePinNote() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => copilot.pinNote(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['copilot-notes'] }) },
  })
}

export function useUnpinNote() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => copilot.unpinNote(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['copilot-notes'] }) },
  })
}

export function useDeleteNote() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => copilot.deleteNote(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['copilot-notes'] }) },
  })
}

// --- Export ---

export function useExportMarkdown(conversationId: string | undefined) {
  return useQuery({
    queryKey: ['copilot-export-markdown', conversationId],
    queryFn: () => copilot.exportMarkdown(conversationId!),
    enabled: !!conversationId,
  })
}

export function useExportJson(conversationId: string | undefined) {
  return useQuery({
    queryKey: ['copilot-export-json', conversationId],
    queryFn: () => copilot.exportJson(conversationId!),
    enabled: !!conversationId,
  })
}
