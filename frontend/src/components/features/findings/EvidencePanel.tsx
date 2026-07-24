import { FileText, Terminal, Image } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'

interface EvidenceItem {
  label: string
  content: string
}

interface EvidencePanelProps {
  evidence?: EvidenceItem[]
  loading?: boolean
}

function getEvidenceIcon(label: string) {
  const l = label.toLowerCase()
  if (l.includes('screenshot') || l.includes('image') || l.includes('png') || l.includes('jpg')) {
    return Image
  }
  if (l.includes('command') || l.includes('output') || l.includes('log')) {
    return Terminal
  }
  return FileText
}

export function EvidencePanel({ evidence, loading }: EvidencePanelProps) {
  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-24" />
          <Skeleton className="h-4 w-32" />
        </CardHeader>
        <div className="px-5 pb-5 space-y-2">
          <Skeleton className="h-16 w-full rounded-lg" />
          <Skeleton className="h-16 w-full rounded-lg" />
        </div>
      </Card>
    )
  }

  if (!evidence || evidence.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Evidence</CardTitle>
          <CardDescription>No evidence recorded</CardDescription>
        </CardHeader>
        <div className="px-5 pb-5">
          <div className="flex flex-col items-center gap-2 py-4 text-center">
            <FileText className="h-6 w-6 text-text-muted" />
            <p className="text-sm text-text-muted">No evidence available for this finding.</p>
          </div>
        </div>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Evidence ({evidence.length})</CardTitle>
        <CardDescription>Supporting evidence for this finding</CardDescription>
      </CardHeader>
      <div className="px-5 pb-5 space-y-3">
        {evidence.map((item, i) => {
          const Icon = getEvidenceIcon(item.label)
          return (
            <details key={i} className="group rounded-lg border border-border overflow-hidden">
              <summary className="flex cursor-pointer items-center gap-3 bg-surface-tertiary/50 px-4 py-3 text-sm font-medium text-text-primary hover:bg-surface-tertiary transition-colors">
                <Icon className="h-4 w-4 text-text-muted shrink-0" />
                <span className="flex-1">{item.label}</span>
                <span className="text-xs text-text-muted group-open:rotate-180 transition-transform">▼</span>
              </summary>
              <div className="border-t border-border bg-surface px-4 py-3">
                <pre className="text-xs text-text-secondary whitespace-pre-wrap font-mono leading-relaxed">
                  {item.content}
                </pre>
              </div>
            </details>
          )
        })}
      </div>
    </Card>
  )
}
