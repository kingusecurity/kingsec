import { useState } from 'react'
import { FileText, Download, ShieldAlert } from 'lucide-react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { useReports } from '@/hooks/use-reports'

const SEVERITY_BADGES: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10',
  HIGH: 'text-orange-400 bg-orange-500/10',
  MEDIUM: 'text-yellow-400 bg-yellow-500/10',
  LOW: 'text-blue-400 bg-blue-500/10',
  INFORMATIONAL: 'text-gray-400 bg-gray-500/10',
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return 'N/A'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let size = bytes
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++ }
  return `${size.toFixed(1)} ${units[i]}`
}

export function ReportsPage() {
  const [offset, setOffset] = useState(0)
  const limit = 25
  const { data, isLoading, error } = useReports({ limit, offset })

  return (
    <PageContainer>
      <PageHeader
        title="Reports"
        description="Generated assessment reports"
        actions={
          <div className="flex items-center gap-2 text-sm text-text-muted">
            <FileText className="h-4 w-4" />
            <span>Reports overview</span>
          </div>
        }
      />
      {isLoading ? (
        <Spinner size="lg" />
      ) : error ? (
        <Card>
          <div className="p-6">
            <div className="rounded-lg border border-border bg-surface-tertiary/50 px-5 py-8 text-center">
              <ShieldAlert className="mx-auto mb-2 h-8 w-8 text-red-400" />
              <p className="text-sm text-red-400">Failed to load reports</p>
            </div>
          </div>
        </Card>
      ) : data?.items.length === 0 ? (
        <Card>
          <div className="p-6">
            <div className="rounded-lg border border-border bg-surface-tertiary/50 px-5 py-8 text-center">
              <h3 className="text-sm font-medium text-text-primary">No Reports Yet</h3>
              <p className="mt-2 text-sm text-text-muted">
                Reports are generated when an assessment is completed. Navigate to an assessment and use the report action to generate one.
              </p>
            </div>
          </div>
        </Card>
      ) : (
        <div className="space-y-4">
          <Card>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-4 py-3 text-left font-medium text-text-muted">Target</th>
                    <th className="px-4 py-3 text-left font-medium text-text-muted">Generated</th>
                    <th className="px-4 py-3 text-left font-medium text-text-muted">Verdict</th>
                    <th className="px-4 py-3 text-left font-medium text-text-muted">Highest Severity</th>
                    <th className="px-4 py-3 text-left font-medium text-text-muted">Findings</th>
                    <th className="px-4 py-3 text-left font-medium text-text-muted">Format</th>
                    <th className="px-4 py-3 text-left font-medium text-text-muted">Size</th>
                    <th className="px-4 py-3 text-left font-medium text-text-muted">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {data?.items.map((r) => (
                    <tr key={r.assessment_id} className="border-b border-border hover:bg-surface-tertiary/50">
                      <td className="px-4 py-3 text-text-primary">{r.target}</td>
                      <td className="px-4 py-3 text-text-muted">{new Date(r.generated_at).toLocaleDateString()}</td>
                      <td className="px-4 py-3 text-text-primary max-w-xs truncate">{r.verdict_headline}</td>
                      <td className="px-4 py-3">
                        {r.verdict_highest_severity ? (
                          <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${SEVERITY_BADGES[r.verdict_highest_severity] || 'text-text-muted bg-surface-tertiary'}`}>
                            {r.verdict_highest_severity}
                          </span>
                        ) : (
                          <span className="text-xs text-text-muted">None</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-text-muted">{r.total_findings}</td>
                      <td className="px-4 py-3 text-text-muted uppercase">{r.format}</td>
                      <td className="px-4 py-3 text-text-muted">{formatFileSize(r.file_size)}</td>
                      <td className="px-4 py-3">
                        <a
                          href={`/api/v1/reports/${r.assessment_id}/download`}
                          className="inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1 text-xs text-text-muted hover:text-text-primary hover:bg-surface-tertiary transition-colors"
                          title="Download report"
                        >
                          <Download className="h-3.5 w-3.5" />
                          Download
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-border px-4 py-3 text-sm text-text-muted">
              <span>{(data?.total ?? 0)} total reports</span>
              <div className="flex gap-2">
                <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))} className="rounded border border-border px-3 py-1 text-sm disabled:opacity-40 hover:bg-surface-tertiary">Previous</button>
                <button disabled={(data?.total ?? 0) <= offset + limit} onClick={() => setOffset(offset + limit)} className="rounded border border-border px-3 py-1 text-sm disabled:opacity-40 hover:bg-surface-tertiary">Next</button>
              </div>
            </div>
          </Card>
        </div>
      )}
    </PageContainer>
  )
}
