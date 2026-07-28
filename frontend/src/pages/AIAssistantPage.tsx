import { useState, useRef, useEffect } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { toast } from '@/components/ui/Toast'
import { useAIHealth, useAIChat } from '@/hooks/use-ai-assistant'
import { Bot, Send, AlertCircle, RefreshCw, MessageSquare } from 'lucide-react'

const SUGGESTED = [
  'What is my biggest risk?',
  'How should I prioritize fixes?',
  'Explain common vulnerability types',
  'What is a CVSS score?',
  'How can I improve security posture?',
]

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

export function AIAssistantPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [assessmentId, setAssessmentId] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  const { data: health, isLoading: healthLoading, refetch: refetchHealth } = useAIHealth()
  const chatMutation = useAIChat()

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSend = async (question: string) => {
    if (!question.trim()) return
    const userMsg: ChatMessage = { role: 'user', content: question }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    try {
      const result = await chatMutation.mutateAsync({
        question: question.trim(),
        history: messages.slice(-10).map((m) => ({ role: m.role, content: m.content })),
        assessmentId: assessmentId || undefined,
      })
      setMessages((prev) => [...prev, { role: 'assistant', content: result.answer }])
    } catch {
      toast.error('AI chat failed. Check your AI provider configuration.')
      setMessages((prev) => [...prev, { role: 'assistant', content: 'Sorry, I encountered an error. Please try again.' }])
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend(input)
    }
  }

  return (
    <PageContainer>
      <PageHeader
        title="AI Assistant"
        description="Ask security questions, get finding explanations, and prioritize remediation"
        actions={
          <div className="flex items-center gap-2">
            {health && (
              <Badge variant={health.available ? 'success' : 'critical'} size="sm">
                {health.available ? `${health.provider} · ${health.model}` : 'Unavailable'}
              </Badge>
            )}
            <Button variant="outline" size="sm" onClick={() => refetchHealth()} iconLeft={<RefreshCw className="h-3 w-3" />}>
              Health
            </Button>
          </div>
        }
      />

      {!healthLoading && health && !health.available && (
        <Card className="p-4 mb-4 bg-red-900/10 border-red-800/50">
          <div className="flex items-center gap-3">
            <AlertCircle className="h-5 w-5 text-red-400 shrink-0" />
            <div className="text-sm text-text-secondary">
              AI provider is not available. Configure your AI settings or check the provider status.
            </div>
          </div>
        </Card>
      )}

      <Card className="p-4 mb-4">
        <div className="flex items-center gap-2">
          <Input
            placeholder="Assessment ID (optional — provides context for answers)"
            value={assessmentId}
            onChange={(e) => setAssessmentId(e.target.value)}
            className="flex-1 text-sm"
          />
        </div>
      </Card>

      <Card className="flex flex-col h-[60vh] min-h-[400px]">
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center space-y-4">
              <Bot className="h-12 w-12 text-text-muted" />
              <div>
                <h3 className="text-sm font-medium text-text-primary">Ask KingSec AI</h3>
                <p className="text-xs text-text-muted mt-1">Ask security questions or get help with your assessments</p>
              </div>
              <div className="flex flex-wrap gap-2 justify-center max-w-md">
                {SUGGESTED.map((q) => (
                  <button
                    key={q}
                    onClick={() => handleSend(q)}
                    className="text-xs px-3 py-1.5 rounded-full bg-surface-tertiary text-text-secondary hover:bg-surface-tertiary/80 transition-colors"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((msg, i) => (
              <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : ''}`}>
                {msg.role === 'assistant' && (
                  <div className="h-8 w-8 rounded-full bg-accent/20 flex items-center justify-center shrink-0">
                    <Bot className="h-4 w-4 text-accent" />
                  </div>
                )}
                <div
                  className={`max-w-[75%] rounded-xl px-4 py-2 text-sm ${
                    msg.role === 'user'
                      ? 'bg-accent text-white'
                      : 'bg-surface-tertiary text-text-primary'
                  }`}
                >
                  <p className="whitespace-pre-wrap">{msg.content}</p>
                </div>
                {msg.role === 'user' && (
                  <div className="h-8 w-8 rounded-full bg-surface-tertiary flex items-center justify-center shrink-0">
                    <MessageSquare className="h-4 w-4 text-text-muted" />
                  </div>
                )}
              </div>
            ))
          )}
          <div ref={bottomRef} />
        </div>

        <div className="border-t border-border p-4">
          <div className="flex gap-2">
            <Input
              placeholder="Ask a security question..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              className="flex-1"
              disabled={chatMutation.isPending}
            />
            <Button
              onClick={() => handleSend(input)}
              disabled={!input.trim() || chatMutation.isPending}
              loading={chatMutation.isPending}
              iconLeft={<Send className="h-4 w-4" />}
            >
              Send
            </Button>
          </div>
        </div>
      </Card>
    </PageContainer>
  )
}
