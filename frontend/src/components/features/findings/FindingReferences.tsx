import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { ExternalLink, BookOpen } from 'lucide-react'

interface FindingReferencesProps {
  cve?: string[]
  cwe?: string[]
  cvssScore?: number
  cvssVector?: string
}

export function FindingReferences({ cve, cwe, cvssScore, cvssVector }: FindingReferencesProps) {
  const hasData = (cve && cve.length > 0) || (cwe && cwe.length > 0) || cvssScore !== undefined

  if (!hasData) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>References</CardTitle>
        </CardHeader>
        <div className="px-5 pb-5">
          <div className="flex flex-col items-center gap-2 py-4 text-center">
            <BookOpen className="h-6 w-6 text-text-muted" />
            <p className="text-sm text-text-muted">No references available from the current API.</p>
          </div>
        </div>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>References</CardTitle>
      </CardHeader>
      <div className="px-5 pb-5 space-y-4">
        {cve && cve.length > 0 && (
          <div>
            <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-2">CVE Identifiers</p>
            <div className="flex flex-wrap gap-2">
              {cve.map((id) => (
                <a
                  key={id}
                  href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 rounded-md bg-red-900/30 px-2 py-1 text-xs font-mono text-red-400 hover:bg-red-900/50 transition-colors"
                >
                  {id}
                  <ExternalLink className="h-3 w-3" />
                </a>
              ))}
            </div>
          </div>
        )}
        {cwe && cwe.length > 0 && (
          <div>
            <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-2">CWE Classifications</p>
            <div className="flex flex-wrap gap-2">
              {cwe.map((id) => (
                <a
                  key={id}
                  href={`https://cwe.mitre.org/data/definitions/${id.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 rounded-md bg-orange-900/30 px-2 py-1 text-xs font-mono text-orange-400 hover:bg-orange-900/50 transition-colors"
                >
                  {id}
                  <ExternalLink className="h-3 w-3" />
                </a>
              ))}
            </div>
          </div>
        )}
        {cvssScore !== undefined && (
          <div>
            <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-2">CVSS Score</p>
            <div className="flex items-center gap-3">
              <span className="text-2xl font-bold text-text-primary">{cvssScore.toFixed(1)}</span>
              {cvssVector && (
                <code className="rounded bg-surface-tertiary px-2 py-1 text-xs text-text-secondary">{cvssVector}</code>
              )}
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}
