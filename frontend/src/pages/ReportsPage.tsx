import { useState, useEffect, useCallback } from 'react'
import {
  FileText, Download, RotateCw, Search, X, Eye, AlertTriangle,
  ChevronLeft, ChevronRight, SlidersHorizontal,
} from 'lucide-react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { Drawer } from '@/components/ui/Drawer'
import { useReports, useRegenerateReport } from '@/hooks/use-reports'
import { adminApi } from '@/api/admin'
import { toast } from '@/components/ui/Toast'
import { formatDate, cn } from '@/lib/utils'
import type { ReportListEntry } from '@/types/api'

const SEVERITY_OPTIONS = [
  { label: 'All', value: '' },
  { label: 'Critical', value: 'CRITICAL' },
  { label: 'High', value: 'HIGH' },
  { label: 'Medium', value: 'MEDIUM' },
  { label: 'Low', value: 'LOW' },
] as const

const SORT_OPTIONS = [
  { label: 'Newest', orderBy: 'generated_at', orderDir: 'desc' },
  { label: 'Oldest', orderBy: 'generated_at', orderDir: 'asc' },
  { label: 'Highest Risk', orderBy: 'executive_score', orderDir: 'asc' },
  { label: 'Lowest Risk', orderBy: 'executive_score', orderDir: 'desc' },
  { label: 'A-Z', orderBy: 'target', orderDir: 'asc' },
  { label: 'Z-A', orderBy: 'target', orderDir: 'desc' },
] as const

const SEVERITY_BADGES: Record<string, string> = {
  CRITICAL: 'bg-red-900/50 text-red-400 border-red-800',
  HIGH: 'bg-orange-900/50 text-orange-400 border-orange-800',
  MEDIUM: 'bg-yellow-900/50 text-yellow-400 border-yellow-800',
  LOW: 'bg-blue-900/50 text-blue-400 border-blue-800',
  INFORMATIONAL: 'bg-gray-800 text-gray-400 border-gray-700',
}

function scoreColor(score: number): string {
  if (score >= 80) return 'text-emerald-400'
  if (score >= 60) return 'text-yellow-400'
  if (score >= 40) return 'text-orange-400'
  return 'text-red-400'
}

function scoreRingColor(score: number): string {
  if (score >= 80) return 'stroke-emerald-500'
  if (score >= 60) return 'stroke-yellow-500'
  if (score >= 40) return 'stroke-orange-500'
  return 'stroke-red-500'
}

function scoreBgColor(score: number): string {
  if (score >= 80) return 'bg-emerald-900/20 border-emerald-800/40'
  if (score >= 60) return 'bg-yellow-900/20 border-yellow-800/40'
  if (score >= 40) return 'bg-orange-900/20 border-orange-800/40'
  return 'bg-red-900/20 border-red-800/40'
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return 'N/A'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let size = bytes
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++ }
  return `${size.toFixed(1)} ${units[i]}`
}

function useDebouncedValue(value: string, delay: number): string {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debounced
}

function ReportCard({
  report,
  onPreview,
  onDownload,
  onRegenerate,
  regenerating,
}: {
  report: ReportListEntry
  onPreview: (r: ReportListEntry) => void
  onDownload: (r: ReportListEntry) => void
  onRegenerate: (r: ReportListEntry) => void
  regenerating: boolean
}) {
  const score = report.executive_score ?? 0
  return (
    <Card className="group relative flex flex-col">
      <div className="flex items-start gap-4 p-5">
        <div
          className={cn(
            'flex h-16 w-16 shrink-0 items-center justify-center rounded-xl border-2',
            scoreBgColor(score),
          )}
        >
          <svg className="h-12 w-12" viewBox="0 0 40 40">
            <circle cx="20" cy="20" r="16" fill="none" stroke="currentColor" strokeWidth="3" className="text-gray-700" />
            <circle
              cx="20" cy="20" r="16" fill="none" strokeWidth="3"
              strokeDasharray={`${(score / 100) * 100.53} 100.53`}
              transform="rotate(-90 20 20)"
              className={scoreRingColor(score)}
              strokeLinecap="round"
            />
            <text x="20" y="24" textAnchor="middle" className={cn('text-xs font-bold fill-current', scoreColor(score))}>
              {Math.round(score)}
            </text>
          </svg>
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="truncate text-sm font-semibold text-text-primary" title={report.target}>
            {report.target}
          </h3>
          <p className="mt-0.5 text-xs text-text-muted">
            {formatDate(report.generated_at)}
          </p>
          <p className="mt-1.5 text-xs text-text-secondary line-clamp-2">
            {report.verdict_headline}
          </p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {report.critical_count > 0 && (
              <Badge variant="critical" size="sm">{report.critical_count} Critical</Badge>
            )}
            {report.high_count > 0 && (
              <Badge variant="high" size="sm">{report.high_count} High</Badge>
            )}
            {report.medium_count > 0 && (
              <Badge variant="medium" size="sm">{report.medium_count} Medium</Badge>
            )}
            {report.low_count > 0 && (
              <Badge variant="low" size="sm">{report.low_count} Low</Badge>
            )}
          </div>
          {report.verdict_action_required && (
            <div className="mt-1.5 flex items-center gap-1 text-xs text-yellow-400">
              <AlertTriangle className="h-3 w-3" />
              <span>Action required</span>
            </div>
          )}
        </div>
      </div>
      <div className="flex items-center gap-1 border-t border-border px-5 py-3">
        <button
          onClick={() => onPreview(report)}
          className="inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-xs text-text-muted hover:text-text-primary hover:bg-surface-tertiary transition-colors"
          aria-label={`Preview report for ${report.target}`}
        >
          <Eye className="h-3.5 w-3.5" />
          Preview
        </button>
        <button
          onClick={() => onDownload(report)}
          className="inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-xs text-text-muted hover:text-text-primary hover:bg-surface-tertiary transition-colors"
          aria-label={`Download report for ${report.target}`}
        >
          <Download className="h-3.5 w-3.5" />
          Download
        </button>
        <button
          onClick={() => onRegenerate(report)}
          disabled={regenerating}
          className="inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-xs text-text-muted hover:text-text-primary hover:bg-surface-tertiary transition-colors disabled:opacity-40"
          aria-label={`Regenerate report for ${report.target}`}
        >
          <RotateCw className={cn('h-3.5 w-3.5', regenerating && 'animate-spin')} />
          {regenerating ? 'Generating...' : 'Regenerate'}
        </button>
      </div>
    </Card>
  )
}

function ReportCardSkeleton() {
  return (
    <Card>
      <div className="p-5 space-y-3">
        <div className="flex gap-4">
          <Skeleton className="h-16 w-16 shrink-0 rounded-xl" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-3 w-1/2" />
            <Skeleton className="h-3 w-full" />
          </div>
        </div>
        <div className="flex gap-2">
          <Skeleton className="h-5 w-20 rounded-md" />
          <Skeleton className="h-5 w-16 rounded-md" />
        </div>
      </div>
      <div className="flex gap-1 border-t border-border px-5 py-3">
        <Skeleton className="h-7 w-20 rounded-md" />
        <Skeleton className="h-7 w-24 rounded-md" />
      </div>
    </Card>
  )
}

function PreviewDrawer({
  report,
  open,
  onClose,
  onDownload,
  onRegenerate,
  regenerating,
}: {
  report: ReportListEntry | null
  open: boolean
  onClose: () => void
  onDownload: (r: ReportListEntry) => void
  onRegenerate: (r: ReportListEntry) => void
  regenerating: boolean
}) {
  if (!report) return null
  const score = report.executive_score ?? 0
  const totalFindings = report.critical_count + report.high_count + report.medium_count + report.low_count + report.info_count
  const maxCount = Math.max(report.critical_count, report.high_count, report.medium_count, report.low_count, report.info_count, 1)

  const severityBars = [
    { label: 'Critical', count: report.critical_count, color: 'bg-red-500' },
    { label: 'High', count: report.high_count, color: 'bg-orange-500' },
    { label: 'Medium', count: report.medium_count, color: 'bg-yellow-500' },
    { label: 'Low', count: report.low_count, color: 'bg-blue-500' },
    { label: 'Info', count: report.info_count, color: 'bg-gray-500' },
  ]

  return (
    <Drawer open={open} onClose={onClose} title="Report Preview">
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <div
            className={cn(
              'flex h-20 w-20 shrink-0 items-center justify-center rounded-xl border-2',
              scoreBgColor(score),
            )}
          >
            <svg className="h-16 w-16" viewBox="0 0 40 40">
              <circle cx="20" cy="20" r="16" fill="none" stroke="currentColor" strokeWidth="3" className="text-gray-700" />
              <circle
                cx="20" cy="20" r="16" fill="none" strokeWidth="3"
                strokeDasharray={`${(score / 100) * 100.53} 100.53`}
                transform="rotate(-90 20 20)"
                className={scoreRingColor(score)}
                strokeLinecap="round"
              />
              <text x="20" y="24" textAnchor="middle" className={cn('text-base font-bold fill-current', scoreColor(score))}>
                {Math.round(score)}
              </text>
            </svg>
          </div>
          <div>
            <h3 className="text-base font-semibold text-text-primary">{report.target}</h3>
            <p className="text-sm text-text-muted">Executive Score</p>
          </div>
        </div>

        <div>
          <h4 className="mb-2 text-sm font-semibold text-text-primary">Executive Summary</h4>
          <p className="text-sm text-text-secondary leading-relaxed">{report.verdict_headline}</p>
        </div>

        <div>
          <h4 className="mb-2 text-sm font-semibold text-text-primary">Risk Summary</h4>
          <div className="space-y-2">
            {severityBars.map(({ label, count, color }) => (
              <div key={label}>
                <div className="mb-0.5 flex items-center justify-between text-xs">
                  <span className="text-text-secondary">{label}</span>
                  <span className="font-medium text-text-primary">{count}</span>
                </div>
                <div className="h-1.5 rounded-full bg-surface-tertiary overflow-hidden">
                  <div className={cn('h-1.5 rounded-full transition-all', color)} style={{ width: `${(count / maxCount) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-border bg-surface-tertiary/50 p-4 space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-muted">Total Findings</span>
            <span className="font-medium text-text-primary">{totalFindings}</span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-muted">Highest Severity</span>
            {report.verdict_highest_severity ? (
              <span className={cn('inline-block rounded px-1.5 py-0.5 text-xs font-medium', SEVERITY_BADGES[report.verdict_highest_severity] || 'text-text-muted')}>
                {report.verdict_highest_severity}
              </span>
            ) : (
              <span className="text-xs text-text-muted">None</span>
            )}
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-muted">Action Required</span>
            <span className={cn('text-xs font-medium', report.verdict_action_required ? 'text-yellow-400' : 'text-emerald-400')}>
              {report.verdict_action_required ? 'Yes' : 'No'}
            </span>
          </div>
        </div>

        <div className="rounded-lg border border-border bg-surface-tertiary/50 p-4 space-y-2">
          <h4 className="text-sm font-semibold text-text-primary mb-2">Metadata</h4>
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-muted">Generated</span>
            <span className="text-text-primary">{formatDate(report.generated_at)}</span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-muted">Assessment</span>
            <span className="text-xs text-text-primary font-mono truncate max-w-[180px]" title={report.assessment_id}>
              {report.assessment_id}
            </span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-muted">Format</span>
            <span className="uppercase text-xs text-text-primary">{report.format}</span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-muted">Size</span>
            <span className="text-text-primary">{formatFileSize(report.file_size)}</span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2 pt-2">
        <Button
          variant="outline"
          size="sm"
          fullWidth
          onClick={() => onDownload(report)}
          iconLeft={<Download className="h-4 w-4" />}
        >
          Download
        </Button>
        <Button
          variant="primary"
          size="sm"
          fullWidth
          onClick={() => onRegenerate(report)}
          loading={regenerating}
          iconLeft={<RotateCw className="h-4 w-4" />}
        >
          {regenerating ? 'Generating...' : 'Regenerate'}
        </Button>
      </div>
    </Drawer>
  )
}

export function ReportsPage() {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [sortKey, setSortKey] = useState(0)
  const [offset, setOffset] = useState(0)
  const [previewReport, setPreviewReport] = useState<ReportListEntry | null>(null)
  const [regeneratingId, setRegeneratingId] = useState<string | null>(null)
  const limit = 24

  const debouncedSearch = useDebouncedValue(search, 300)
  const sort = SORT_OPTIONS[sortKey] ?? SORT_OPTIONS[0]

  const { data, isLoading, error, refetch } = useReports({
    limit,
    offset,
    search: debouncedSearch || undefined,
    severity: severityFilter || undefined,
    order_by: sort.orderBy,
    order_dir: sort.orderDir,
  })

  const { mutateAsync: regenerateReport } = useRegenerateReport()

  useEffect(() => { setOffset(0) }, [debouncedSearch, severityFilter, sortKey])

  const totalPages = data ? Math.ceil(data.total / limit) : 0
  const currentPage = Math.floor(offset / limit) + 1

  const handlePreview = useCallback((r: ReportListEntry) => setPreviewReport(r), [])
  const handleClosePreview = useCallback(() => setPreviewReport(null), [])

  const handleDownload = useCallback(async (r: ReportListEntry) => {
    try {
      await adminApi.downloadReport(r.assessment_id)
    } catch (err) {
      toast.error('Download failed', (err as Error).message)
    }
  }, [])

  const handleRegenerate = useCallback(async (r: ReportListEntry) => {
    setRegeneratingId(r.assessment_id)
    try {
      await regenerateReport(r.assessment_id)
    } catch (err) {
      toast.error('Regeneration failed', (err as Error).message)
    } finally {
      setRegeneratingId(null)
      setPreviewReport(null)
    }
  }, [regenerateReport])

  const clearAllFilters = () => {
    setSearch('')
    setSeverityFilter('')
    setSortKey(0)
    setOffset(0)
  }

  const hasActiveFilters = search || severityFilter || sortKey !== 0

  return (
    <PageContainer>
      <PageHeader
        title="Report Center"
        description="Professional report management and analysis"
        actions={
          <div className="flex items-center gap-2 text-sm text-text-muted">
            <FileText className="h-4 w-4" />
            <span>{data?.total ?? 0} reports</span>
          </div>
        }
      />

      <Card>
        <div className="space-y-4 p-5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
              <input
                type="text"
                placeholder="Search by target, assessment ID, or verdict..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full rounded-lg border border-border bg-surface-secondary py-2 pl-9 pr-3 text-sm text-text-primary placeholder-text-muted focus:border-accent focus:outline-none"
                aria-label="Search reports"
              />
              {search && (
                <button
                  onClick={() => setSearch('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
                  aria-label="Clear search"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
            <div className="flex items-center gap-2">
              <SlidersHorizontal className="h-4 w-4 text-text-muted shrink-0" />
              <select
                value={sortKey}
                onChange={(e) => setSortKey(Number(e.target.value))}
                className="rounded-lg border border-border bg-surface-secondary px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
                aria-label="Sort reports"
              >
                {SORT_OPTIONS.map((opt, i) => (
                  <option key={i} value={i}>{opt.label}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Severity filter">
            {SEVERITY_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setSeverityFilter(opt.value)}
                className={cn(
                  'rounded-full px-3 py-1 text-xs font-medium transition-colors',
                  severityFilter === opt.value
                    ? 'bg-accent/10 text-accent border border-accent/30'
                    : 'text-text-muted hover:text-text-primary border border-transparent hover:border-border',
                )}
                aria-pressed={severityFilter === opt.value}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      </Card>

      {isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <ReportCardSkeleton key={i} />
          ))}
        </div>
      ) : error ? (
        <ErrorState
          title="Failed to load reports"
          message={(error as Error).message}
          onRetry={refetch}
        />
      ) : data?.items.length === 0 && hasActiveFilters ? (
        <Card>
          <div className="flex flex-col items-center gap-3 py-16 text-center">
            <Search className="h-10 w-10 text-text-muted" />
            <h3 className="text-base font-semibold text-text-primary">No matching reports</h3>
            <p className="max-w-sm text-sm text-text-muted">
              No reports match your current filters. Try adjusting your search or filter criteria.
            </p>
            <Button variant="outline" size="sm" onClick={clearAllFilters}>
              Clear all filters
            </Button>
          </div>
        </Card>
      ) : data?.items.length === 0 ? (
        <Card>
          <div className="flex flex-col items-center gap-3 py-16 text-center">
            <FileText className="h-10 w-10 text-text-muted" />
            <h3 className="text-base font-semibold text-text-primary">No reports yet</h3>
            <p className="max-w-sm text-sm text-text-muted">
              Reports are generated when an assessment is completed. Navigate to an assessment and generate a report.
            </p>
          </div>
        </Card>
      ) : (
        <>
          <div className="flex items-center justify-between text-sm text-text-muted">
            <span>
              Showing {offset + 1}–{Math.min(offset + limit, data?.total ?? 0)} of {data?.total ?? 0} reports
            </span>
            {hasActiveFilters && (
              <button onClick={clearAllFilters} className="text-accent hover:text-accent/80 transition-colors text-xs">
                Clear all filters
              </button>
            )}
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {data?.items.map((r) => (
              <ReportCard
                key={r.assessment_id}
                report={r}
                onPreview={handlePreview}
                onDownload={handleDownload}
                onRegenerate={handleRegenerate}
                regenerating={regeneratingId === r.assessment_id}
              />
            ))}
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between border-t border-border pt-4 text-sm text-text-muted">
              <span>Page {currentPage} of {totalPages}</span>
              <div className="flex gap-2">
                <button
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  className="inline-flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-surface-tertiary transition-colors"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-4 w-4" />
                  Previous
                </button>
                <button
                  disabled={(data?.total ?? 0) <= offset + limit}
                  onClick={() => setOffset(offset + limit)}
                  className="inline-flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-surface-tertiary transition-colors"
                  aria-label="Next page"
                >
                  Next
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </>
      )}

      <PreviewDrawer
        report={previewReport}
        open={!!previewReport}
        onClose={handleClosePreview}
        onDownload={handleDownload}
        onRegenerate={handleRegenerate}
        regenerating={regeneratingId === previewReport?.assessment_id}
      />
    </PageContainer>
  )
}
