import { useState, useRef, useEffect, useCallback } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import {
  useConversations,
  useCreateConversation,
  useConversation,
  useAskCopilot,
  usePromptTemplates,
  useNotes,
  useCreateNote,
  useUpdateNote,
  usePinNote,
  useUnpinNote,
  useDeleteNote,
} from '@/hooks/use-copilot'
import type { CopilotMessage, AskResult } from '@/api/copilot'
import { getAccessToken } from '@/api/client'

const API_BASE = '/api/v1'

// Simple Markdown renderer with copy buttons
function MarkdownBlock({ content }: { content: string }) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)

  const copyCode = async (code: string, index: number) => {
    await navigator.clipboard.writeText(code)
    setCopiedIndex(index)
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  const parts = content.split(/(```\w*\n[\s\S]*?```)/g)

  return (
    <div className="prose prose-sm max-w-none text-text-primary">
      {parts.map((part, i) => {
        const codeMatch = part.match(/```(\w*)\n([\s\S]*?)```/)
        if (codeMatch) {
          const lang = codeMatch[1] || 'text'
          const code = codeMatch[2] ?? ''
          return (
            <div key={i} className="group relative my-2 rounded-lg bg-bg-secondary">
              <div className="flex items-center justify-between rounded-t-lg border-b border-border-primary px-3 py-1.5 text-xs text-text-muted">
                <span>{lang}</span>
                <button
                  onClick={() => copyCode(code, i)}
                  className="rounded px-2 py-0.5 text-xs transition-colors hover:bg-surface-tertiary"
                >
                  {copiedIndex === i ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <pre className="overflow-x-auto p-3 text-sm"><code>{code}</code></pre>
            </div>
          )
        }
        return <p key={i} className="whitespace-pre-wrap">{part}</p>
      })}
    </div>
  )
}

function MessageBubble({ msg }: { msg: CopilotMessage }) {
  const isUser = msg.role === 'user'
  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-3`}>
      <div
        className={`max-w-[85%] rounded-lg px-4 py-2.5 ${
          isUser
            ? 'bg-accent-primary text-white'
            : 'bg-bg-secondary text-text-primary'
        }`}
      >
        {isUser ? (
          <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
        ) : (
          <MarkdownBlock content={msg.content} />
        )}
        <p className={`mt-1 text-xs ${isUser ? 'text-white/60' : 'text-text-muted'}`}>
          {new Date(msg.timestamp).toLocaleTimeString()}
        </p>
      </div>
    </div>
  )
}

function NoteEditor({
  conversationId,
  onClose,
}: {
  conversationId: string
  onClose: () => void
}) {
  const [content, setContent] = useState('')
  const createNote = useCreateNote()

  const handleSave = () => {
    if (!content.trim()) return
    createNote.mutate(
      { conversation_id: conversationId, content: content.trim() },
      { onSuccess: () => { setContent(''); onClose() } },
    )
  }

  return (
    <div className="mb-3 rounded-lg border border-border-primary bg-bg-secondary p-3">
      <textarea
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder="Write your investigation note (markdown supported)..."
        className="mb-2 w-full resize-none rounded bg-surface-primary p-2 text-sm text-text-primary outline-none"
        rows={4}
      />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose} variant="outline" className="text-xs">Cancel</Button>
        <Button onClick={handleSave} variant="primary" className="text-xs" disabled={!content.trim() || createNote.isPending}>
          {createNote.isPending ? 'Saving...' : 'Save Note'}
        </Button>
      </div>
    </div>
  )
}

type PanelTab = 'conversation' | 'evidence' | 'notes'

export function AICopilotPage() {
  const [activeConvId, setActiveConvId] = useState<string | null>(null)
  const [question, setQuestion] = useState('')
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null)
  const [showTemplates, setShowTemplates] = useState(false)
  const [showNoteEditor, setShowNoteEditor] = useState(false)
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null)
  const [editNoteContent, setEditNoteContent] = useState('')
  const [panel, setPanel] = useState<PanelTab>('conversation')
  const [lastResult, setLastResult] = useState<AskResult | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const { data: conversations } = useConversations()
  const { data: conv, isLoading: convLoading } = useConversation(activeConvId ?? undefined)
  const { data: templates } = usePromptTemplates()
  const { data: notes, isLoading: notesLoading } = useNotes({
    conversation_id: activeConvId ?? undefined,
  })
  const askMutation = useAskCopilot()
  const createConv = useCreateConversation()
  const updateNote = useUpdateNote()
  const pinNote = usePinNote()
  const unpinNote = useUnpinNote()
  const deleteNote = useDeleteNote()

  const messages = conv?.messages ?? []

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [])

  useEffect(() => { scrollToBottom() }, [messages, scrollToBottom])

  const handleNewConversation = () => {
    createConv.mutate({ title: 'New Investigation' })
  }

  const handleSend = () => {
    if (!question.trim() || !activeConvId) return
    askMutation.mutate(
      {
        conversation_id: activeConvId,
        question: question.trim(),
        template_id: selectedTemplate || undefined,
      },
      {
        onSuccess: (result) => {
          setLastResult(result)
          setQuestion('')
          setSelectedTemplate(null)
          setShowTemplates(false)
        },
      },
    )
  }

  const handleTemplateClick = (templateId: string) => {
    setSelectedTemplate(templateId)
    setShowTemplates(false)
  }

  const handleNewNote = () => {
    setShowNoteEditor(true)
  }

  const handleEditNote = (noteId: string, content: string) => {
    setEditingNoteId(noteId)
    setEditNoteContent(content)
  }

  const handleSaveEditNote = () => {
    if (editingNoteId && editNoteContent.trim()) {
      updateNote.mutate({ id: editingNoteId, content: editNoteContent.trim() })
      setEditingNoteId(null)
      setEditNoteContent('')
    }
  }

  const handleExportMarkdown = () => {
    if (!activeConvId) return
    const token = getAccessToken()
    fetch(`${API_BASE}/copilot/export/${encodeURIComponent(activeConvId)}/markdown`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then((r) => {
        if (!r.ok) throw new Error('Export failed')
        return r.blob()
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `investigation-${activeConvId}.md`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
      })
      .catch(() => {
        // Best-effort export; the button remains usable if the user retries.
      })
  }

  const handleExportJson = () => {
    if (!activeConvId) return
    const token = getAccessToken()
    fetch(`${API_BASE}/copilot/export/${encodeURIComponent(activeConvId)}/json`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then((r) => {
        if (!r.ok) throw new Error('Export failed')
        return r.json()
      })
      .then((data) => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `investigation-${activeConvId}.json`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
      })
      .catch(() => {
        // Best-effort export; the button remains usable if the user retries.
      })
  }

  return (
    <PageContainer>
      <PageHeader title="AI Security Copilot" description="Investigate findings, analyze threats, and plan remediation with AI assistance" />

      <div className="flex gap-4" style={{ height: 'calc(100vh - 220px)' }}>
        {/* Left sidebar: Conversation list */}
        <div className="w-64 shrink-0 overflow-y-auto rounded-lg border border-border-primary bg-surface-secondary">
          <div className="border-b border-border-primary p-3">
            <Button onClick={handleNewConversation} variant="primary" className="w-full text-xs" disabled={createConv.isPending}>
              {createConv.isPending ? 'Creating...' : '+ New Investigation'}
            </Button>
          </div>
          <div className="p-2">
            {conversations && conversations.length > 0 ? (
              conversations.map((c) => (
                <button
                  key={c.id}
                  onClick={() => setActiveConvId(c.id)}
                  className={`w-full rounded-lg px-3 py-2 text-left text-sm transition-colors ${
                    activeConvId === c.id
                      ? 'bg-accent-primary/10 text-accent-primary'
                      : 'text-text-muted hover:bg-surface-tertiary hover:text-text-primary'
                  }`}
                >
                  <p className="truncate font-medium">{c.title}</p>
                  <p className="text-xs text-text-muted">
                    {c.messages.length > 0
                      ? `${c.messages.length} messages`
                      : 'No messages'}
                  </p>
                </button>
              ))
            ) : (
              <p className="px-3 py-4 text-center text-sm text-text-muted">
                No investigations yet. Start a new one.
              </p>
            )}
          </div>
        </div>

        {/* Main content area */}
        <div className="flex flex-1 gap-4 overflow-hidden">
          {/* Conversation panel */}
          <div className={`flex flex-col ${panel === 'evidence' || panel === 'notes' ? 'w-1/2' : 'flex-1'}`}>
            <div className="mb-2 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Button
                  onClick={() => setPanel('conversation')}
                  variant={panel === 'conversation' ? 'primary' : 'outline'}
                  className="text-xs"
                >
                  Chat
                </Button>
                <Button
                  onClick={() => setPanel('evidence')}
                  variant={panel === 'evidence' ? 'primary' : 'outline'}
                  className="text-xs"
                >
                  Evidence
                </Button>
                <Button
                  onClick={() => setPanel('notes')}
                  variant={panel === 'notes' ? 'primary' : 'outline'}
                  className="text-xs"
                >
                  Notes
                </Button>
              </div>
              {activeConvId && (
                <div className="flex items-center gap-2">
                  <Button onClick={handleExportMarkdown} variant="outline" className="text-xs">
                    Export MD
                  </Button>
                  <Button onClick={handleExportJson} variant="outline" className="text-xs">
                    Export JSON
                  </Button>
                </div>
              )}
            </div>

            {!activeConvId ? (
              <div className="flex flex-1 items-center justify-center text-sm text-text-muted">
                <div className="text-center">
                  <p className="mb-2 text-lg">🔍 AI Security Copilot</p>
                  <p>Select an investigation or create a new one to start.</p>
                </div>
              </div>
            ) : (
              <>
                {/* Messages area */}
                <div className="flex-1 overflow-y-auto rounded-lg border border-border-primary bg-surface-secondary p-4">
                  {convLoading ? (
                    <div className="flex justify-center py-8"><Spinner /></div>
                  ) : messages.length > 0 ? (
                    messages.map((msg, i) => <MessageBubble key={i} msg={msg} />)
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-text-muted">
                      <div className="text-center">
                        <p className="mb-3">Ask a question to start the investigation.</p>
                        {templates && templates.length > 0 && (
                          <div className="flex flex-wrap justify-center gap-2">
                            {templates.slice(0, 4).map((t) => (
                              <button
                                key={t.id}
                                onClick={() => {
                                  if (activeConvId) {
                                    askMutation.mutate({
                                      conversation_id: activeConvId,
                                      question: `Use template: ${t.name}`,
                                      template_id: t.id,
                                    })
                                  }
                                }}
                                className="rounded-lg border border-border-primary bg-surface-primary px-3 py-2 text-xs text-text-muted hover:border-accent-primary hover:text-accent-primary"
                              >
                                {t.name}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                  <div ref={messagesEndRef} />
                </div>

                {/* Input area */}
                <div className="mt-2">
                  <div className="flex items-center gap-2">
                    <Button
                      onClick={() => setShowTemplates(!showTemplates)}
                      variant="outline"
                      className="shrink-0 text-xs"
                      title="Use a prompt template"
                    >
                      Templates
                    </Button>
                    <input
                      type="text"
                      value={question}
                      onChange={(e) => setQuestion(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend() }
                      }}
                      placeholder="Ask a question about your security context..."
                      className="flex-1 rounded-lg border border-border-primary bg-surface-secondary px-3 py-2 text-sm text-text-primary outline-none"
                      disabled={askMutation.isPending}
                    />
                    <Button onClick={handleSend} variant="primary" className="shrink-0 text-xs" disabled={!question.trim() || askMutation.isPending}>
                      {askMutation.isPending ? <Spinner /> : 'Send'}
                    </Button>
                  </div>

                  {showTemplates && templates && (
                    <div className="mt-2 flex flex-wrap gap-2 rounded-lg border border-border-primary bg-surface-secondary p-2">
                      {templates.map((t) => (
                        <button
                          key={t.id}
                          onClick={() => handleTemplateClick(t.id)}
                          className={`rounded px-2 py-1 text-xs ${
                            selectedTemplate === t.id
                              ? 'bg-accent-primary text-white'
                              : 'bg-surface-primary text-text-muted hover:text-text-primary'
                          }`}
                          title={t.description}
                        >
                          {t.name}
                        </button>
                      ))}
                      {selectedTemplate && (
                        <button
                          onClick={() => setSelectedTemplate(null)}
                          className="text-xs text-text-muted hover:text-red-500"
                        >
                          Clear
                        </button>
                      )}
                    </div>
                  )}

                  {askMutation.isPending && (
                    <div className="mt-2 flex items-center gap-2 text-sm text-text-muted">
                      <Spinner />
                      <span>AI is analyzing your security context...</span>
                    </div>
                  )}

                  {lastResult && lastResult.suggested_questions.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {lastResult.suggested_questions.map((sq, i) => (
                        <button
                          key={i}
                          onClick={() => {
                            setQuestion(sq)
                          }}
                          className="rounded-full border border-border-primary px-3 py-1 text-xs text-text-muted hover:border-accent-primary hover:text-accent-primary"
                        >
                          {sq}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>

          {/* Evidence / Notes panel */}
          {(panel === 'evidence' || panel === 'notes') && activeConvId && (
            <div className="w-1/2 overflow-y-auto rounded-lg border border-border-primary bg-surface-secondary p-4">
              {panel === 'evidence' && lastResult && (
                <div>
                  <h3 className="mb-3 text-sm font-semibold text-text-primary">Context</h3>

                  {lastResult.context.finding && (
                    <div className="mb-3 rounded-lg bg-bg-secondary p-3">
                      <p className="text-xs font-medium text-accent-primary">Finding</p>
                      <p className="text-sm text-text-primary">{(lastResult.context.finding as Record<string, string>).title}</p>
                      <Badge variant="warning" className="mt-1">{(lastResult.context.finding as Record<string, string>).severity}</Badge>
                    </div>
                  )}

                  {lastResult.context.assessment && (
                    <div className="mb-3 rounded-lg bg-bg-secondary p-3">
                      <p className="text-xs font-medium text-accent-primary">Assessment</p>
                      <p className="text-sm text-text-primary">{(lastResult.context.assessment as Record<string, string>).target}</p>
                      <p className="text-xs text-text-muted">Status: {(lastResult.context.assessment as Record<string, string>).status}</p>
                      <p className="text-xs text-text-muted">Findings: {(lastResult.context.assessment as Record<string, number>).finding_count}</p>
                    </div>
                  )}

                  {lastResult.context.asset && (
                    <div className="mb-3 rounded-lg bg-bg-secondary p-3">
                      <p className="text-xs font-medium text-accent-primary">Asset</p>
                      <p className="text-sm text-text-primary">{(lastResult.context.asset as Record<string, string>).hostname}</p>
                      <p className="text-xs text-text-muted">{(lastResult.context.asset as Record<string, string>).ip_address}</p>
                      <Badge variant="neutral" className="mt-1">{(lastResult.context.asset as Record<string, string>).asset_type}</Badge>
                    </div>
                  )}

                  {lastResult.context.cve && (
                    <div className="mb-3 rounded-lg bg-bg-secondary p-3">
                      <p className="text-xs font-medium text-accent-primary">CVE</p>
                      <p className="text-sm font-medium text-text-primary">{(lastResult.context.cve as Record<string, string>).cve_code}</p>
                      <p className="text-xs text-text-muted">Severity: {(lastResult.context.cve as Record<string, string>).severity}</p>
                      <p className="text-xs text-text-muted">Threat Score: {(lastResult.context.cve as Record<string, number>).threat_score}</p>
                    </div>
                  )}

                  {lastResult.context.alert && (
                    <div className="mb-3 rounded-lg bg-bg-secondary p-3">
                      <p className="text-xs font-medium text-accent-primary">Alert</p>
                      <p className="text-sm text-text-primary">{(lastResult.context.alert as Record<string, string>).title}</p>
                      <Badge variant="danger" className="mt-1">{(lastResult.context.alert as Record<string, string>).severity}</Badge>
                    </div>
                  )}

                  {lastResult.context.exposure && (
                    <div className="mb-3 rounded-lg bg-bg-secondary p-3">
                      <p className="text-xs font-medium text-accent-primary">Exposure</p>
                      <p className="text-sm text-text-primary">{(lastResult.context.exposure as Record<string, string>).exposure_type}</p>
                      <Badge variant="warning" className="mt-1">{(lastResult.context.exposure as Record<string, string>).severity}</Badge>
                    </div>
                  )}

                  {!lastResult.context.finding && !lastResult.context.assessment && !lastResult.context.asset &&
                   !lastResult.context.cve && !lastResult.context.alert && !lastResult.context.exposure && (
                    <p className="text-sm text-text-muted">No specific context for this investigation.</p>
                  )}
                </div>
              )}

              {panel === 'evidence' && !lastResult && (
                <div className="flex h-full items-center justify-center text-sm text-text-muted">
                  Ask a question to see contextual evidence.
                </div>
              )}

              {panel === 'notes' && (
                <div>
                  <div className="mb-3 flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-text-primary">Investigation Notes</h3>
                    {!showNoteEditor && (
                      <Button onClick={handleNewNote} variant="outline" className="text-xs">+ Add Note</Button>
                    )}
                  </div>

                  {showNoteEditor && (
                    <NoteEditor
                      conversationId={activeConvId}
                      onClose={() => setShowNoteEditor(false)}
                    />
                  )}

                  {notesLoading ? (
                    <div className="flex justify-center py-4"><Spinner /></div>
                  ) : notes && notes.length > 0 ? (
                    <div className="space-y-3">
                      {notes.map((note) => (
                        <div key={note.id} className="rounded-lg border border-border-primary bg-bg-secondary p-3">
                          <div className="mb-1 flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-medium text-text-primary">{note.author}</span>
                              <span className="text-xs text-text-muted">{new Date(note.created_at).toLocaleDateString()}</span>
                              {note.pinned && <Badge variant="neutral">📌 Pinned</Badge>}
                            </div>
                            <div className="flex items-center gap-1">
                              <button
                                onClick={() => note.pinned ? unpinNote.mutate(note.id) : pinNote.mutate(note.id)}
                                className="text-xs text-text-muted hover:text-accent-primary"
                                title={note.pinned ? 'Unpin' : 'Pin'}
                              >
                                📌
                              </button>
                              <button
                                onClick={() => handleEditNote(note.id, note.content)}
                                className="text-xs text-text-muted hover:text-accent-primary"
                                title="Edit"
                              >
                                ✏️
                              </button>
                              <button
                                onClick={() => deleteNote.mutate(note.id)}
                                className="text-xs text-text-muted hover:text-red-500"
                                title="Delete"
                              >
                                🗑️
                              </button>
                            </div>
                          </div>

                          {editingNoteId === note.id ? (
                            <div>
                              <textarea
                                value={editNoteContent}
                                onChange={(e) => setEditNoteContent(e.target.value)}
                                className="mb-2 w-full resize-none rounded bg-surface-primary p-2 text-sm text-text-primary outline-none"
                                rows={3}
                              />
                              <div className="flex justify-end gap-2">
                                <Button onClick={() => setEditingNoteId(null)} variant="outline" className="text-xs">Cancel</Button>
                                <Button onClick={handleSaveEditNote} variant="primary" className="text-xs" disabled={!editNoteContent.trim()}>Save</Button>
                              </div>
                            </div>
                          ) : (
                            <div className="text-sm text-text-primary whitespace-pre-wrap">{note.content}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-text-muted">
                      No notes yet. Add notes to document your investigation.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </PageContainer>
  )
}
