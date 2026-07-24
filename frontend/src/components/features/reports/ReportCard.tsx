import { Link } from 'react-router-dom'
import { FileText, Download, ArrowRight, Trash2 } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { formatDate } from '@/lib/utils'

const verdictVariant: Record<string, 'success' | 'warning' | 'critical' | 'neutral'> = {
  safe: 'success',
  minor: 'warning',
  moderate: 'warning',
  critical: 'critical',
  unknown: 'neutral',
}

interface ReportCardProps {
  assessmentId: string
  target: string
  verdict?: string
  totalFindings: number
  highestSeverity?: string | null
  createdAt: string
  downloadUrl?: string
  onDownload?: () => void
  onDelete?: () => void
  loading?: boolean
}

export function ReportCard({
  assessmentId,
  target,
  verdict,
  totalFindings,
  highestSeverity,
  createdAt,
  downloadUrl,
  onDownload,
  onDelete,
  loading,
}: ReportCardProps) {
  if (loading) {
    return (
      <Card>
        <CardHeader>
          <div className="h-5 w-3/4 animate-pulse rounded bg-surface-tertiary" />
          <div className="h-4 w-1/2 animate-pulse rounded bg-surface-tertiary" />
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card className="hover:border-border-light transition-colors">
      <div className="p-5 space-y-4">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-accent/10">
              <FileText className="h-5 w-5 text-accent" />
            </div>
            <div>
              <Link to={`/reports/${assessmentId}`} className="font-medium text-text-primary hover:text-accent transition-colors">
                {target}
              </Link>
              <p className="text-xs text-text-muted mt-0.5">{formatDate(createdAt)}</p>
            </div>
          </div>
          {verdict && (
            <Badge variant={verdictVariant[verdict.toLowerCase()] ?? 'neutral'}>{verdict}</Badge>
          )}
        </div>

        <div className="flex items-center gap-4 text-sm">
          <div>
            <span className="text-text-secondary">Findings</span>
            <p className="font-medium text-text-primary">{totalFindings}</p>
          </div>
          {highestSeverity && (
            <div>
              <span className="text-text-secondary">Highest</span>
              <p className="font-medium">
                <Badge variant={verdictVariant[highestSeverity.toLowerCase()] ?? 'neutral'} size="sm">
                  {highestSeverity}
                </Badge>
              </p>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 pt-1">
          {downloadUrl && (
            <Button
              variant="outline"
              size="xs"
              onClick={() => window.open(downloadUrl, '_blank')}
              aria-label={`Download report for ${target}`}
            >
              <Download className="h-3.5 w-3.5" />
            </Button>
          )}
          {onDownload && (
            <Button
              variant="outline"
              size="xs"
              onClick={onDownload}
              aria-label={`Download report for ${target}`}
            >
              <Download className="h-3.5 w-3.5" />
            </Button>
          )}
          <Link
            to={`/reports/${assessmentId}`}
            className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-text-muted hover:text-text-primary hover:bg-surface-tertiary transition-colors"
            aria-label={`View report for ${target}`}
          >
            <ArrowRight className="h-4 w-4" />
          </Link>
          {onDelete && (
            <Button
              variant="ghost"
              size="xs"
              onClick={onDelete}
              className="ml-auto text-text-muted hover:text-red-400"
              aria-label={`Delete report for ${target}`}
            >
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
      </div>
    </Card>
  )
}
