import { useState, useCallback, useEffect } from 'react'
import { Shield, ShieldOff, AlertTriangle, CheckCircle, RefreshCw, Package, Wifi, WifiOff, Search, Filter, Copy, Terminal, ExternalLink, FileText } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { Button } from '@/components/ui/Button'
import { toast } from '@/components/ui/Toast'
import { cn } from '@/lib/utils'
import { useScannerHealth, useScannerDetail, useScannerInstallInfo } from '@/hooks/use-scanner-health'
import type { ScannerStatus, InstallCommand } from '@/api/scanner-health'

type FilterMode = 'all' | 'installed' | 'missing' | 'warning'

interface ScannerHealthPanelProps {
  className?: string
}

const scannerIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  nmap: Wifi,
  nuclei: Search,
  nikto: Shield,
  ffuf: Filter,
  gobuster: Package,
  trivy: Shield,
  semgrep: Search,
  amass: Wifi,
  zap: Shield,
}

function HealthBar({ score }: { score: number }) {
  const color =
    score >= 80 ? 'bg-emerald-500' :
    score >= 50 ? 'bg-yellow-500' :
    'bg-red-500'
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 flex-1 rounded-full bg-surface-tertiary overflow-hidden">
        <div
          className={cn('h-full rounded-full transition-all duration-500', color)}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className="text-xs font-medium text-text-secondary tabular-nums min-w-[3ch] text-right">
        {score}%
      </span>
    </div>
  )
}

function ScannerRow({
  scanner,
  onSelect,
}: {
  scanner: ScannerStatus
  onSelect: (id: string) => void
}) {
  const Icon = scannerIcons[scanner.scanner_id] ?? Shield
  const isUsable = scanner.usable
  const isInstalled = scanner.installed

  return (
    <button
      onClick={() => onSelect(scanner.scanner_id)}
      className={cn(
        'w-full flex items-center gap-3 rounded-lg p-3 text-left transition-colors',
        'hover:bg-surface-tertiary/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
      )}
    >
      <div
        className={cn(
          'flex h-8 w-8 shrink-0 items-center justify-center rounded-lg',
          isUsable
            ? 'bg-emerald-900/30 text-emerald-400'
            : isInstalled
              ? 'bg-yellow-900/30 text-yellow-400'
              : 'bg-red-900/30 text-red-400',
        )}
      >
        <Icon className="h-4 w-4" />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-text-primary truncate">
            {scanner.name}
          </span>
          {isUsable && <CheckCircle className="h-3.5 w-3.5 text-emerald-400 shrink-0" />}
          {isInstalled && !isUsable && <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 shrink-0" />}
          {!isInstalled && <WifiOff className="h-3.5 w-3.5 text-red-400 shrink-0" />}
        </div>
        <div className="mt-0.5 flex items-center gap-2 text-xs text-text-muted">
          {isInstalled && scanner.version && (
            <span>v{scanner.version}</span>
          )}
          {isInstalled && scanner.executable_path && (
            <span className="truncate max-w-[200px]" title={scanner.executable_path}>
              {scanner.executable_path}
            </span>
          )}
          {!isInstalled && (
            <span>Not installed</span>
          )}
        </div>
        {scanner.warnings.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-1">
            {scanner.warnings.map((w, i) => (
              <Badge key={i} variant="warning" size="sm">{w}</Badge>
            ))}
          </div>
        )}
      </div>
    </button>
  )
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text)
      toast.success('Copied', `${label} copied to clipboard`)
    } catch {
      toast.error('Copy failed', 'Could not copy to clipboard')
    }
  }, [text, label])

  return (
    <button
      onClick={handleCopy}
      className="inline-flex items-center gap-1 text-xs text-accent hover:text-accent/80 transition-colors"
      title={`Copy ${label}`}
    >
      <Copy className="h-3 w-3" />
      Copy
    </button>
  )
}

function FixButton({ scannerId }: { scannerId: string }) {
  const { data: installInfo, isLoading } = useScannerInstallInfo(scannerId)
  const [copied, setCopied] = useState(false)

  const handleFix = useCallback(async () => {
    if (!installInfo?.best_command?.command) return
    try {
      await navigator.clipboard.writeText(installInfo.best_command.command)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
      toast.success('Command copied', 'Paste and run in your terminal')
    } catch {
      toast.error('Copy failed', 'Could not copy command to clipboard')
    }
  }, [installInfo])

  if (isLoading) return <Skeleton className="h-7 w-24 rounded-md" />
  if (!installInfo?.best_command) return null

  return (
    <Button
      variant="outline"
      size="xs"
      onClick={handleFix}
      iconLeft={<Terminal className="h-3 w-3" />}
    >
      {copied ? 'Copied!' : 'Copy Install Command'}
    </Button>
  )
}

function ScannerDetailPanel({
  scannerId,
  onClose,
}: {
  scannerId: string
  onClose: () => void
}) {
  const { data, isLoading, error } = useScannerDetail(scannerId)
  const { data: installInfo } = useScannerInstallInfo(scannerId)
  const scanner = data

  if (isLoading) {
    return (
      <div className="space-y-3 p-4">
        <Skeleton className="h-5 w-1/3" />
        <Skeleton className="h-4 w-1/2" />
        <Skeleton className="h-20 w-full" />
      </div>
    )
  }

  if (error || !scanner) return null

  return (
    <div className="border-t border-border p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-text-primary">{scanner.name} Details</h4>
        <div className="flex items-center gap-2">
          {!scanner.installed && <FixButton scannerId={scannerId} />}
          <Button variant="ghost" size="xs" onClick={onClose}>Close</Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 text-xs">
        <div>
          <span className="text-text-muted block">Status</span>
          <span className={cn(
            'font-medium',
            scanner.usable ? 'text-emerald-400' : scanner.installed ? 'text-yellow-400' : 'text-red-400',
          )}>
            {scanner.usable ? 'Usable' : scanner.installed ? 'Partial' : 'Missing'}
          </span>
        </div>
        <div>
          <span className="text-text-muted block">Version</span>
          <span className="font-medium text-text-primary">{scanner.version || 'N/A'}</span>
        </div>
        <div className="col-span-2">
          <span className="text-text-muted block">Executable</span>
          <span className="font-medium text-text-primary break-all">{scanner.executable_path || 'Not found'}</span>
        </div>
        <div>
          <span className="text-text-muted block">Permissions</span>
          <span className={cn('font-medium', scanner.permissions_ok ? 'text-emerald-400' : 'text-yellow-400')}>
            {scanner.permissions_ok ? 'OK' : 'Check'}
          </span>
        </div>
        <div>
          <span className="text-text-muted block">Min Version</span>
          <span className="font-medium text-text-primary">{installInfo?.min_version || 'N/A'}</span>
        </div>
      </div>

      {scanner.availability_reason && (
        <div className="rounded-lg bg-yellow-900/20 p-2.5 text-xs text-yellow-300">
          <p className="font-medium mb-1">Reason</p>
          <p>{scanner.availability_reason}</p>
        </div>
      )}

      {scanner.recommendations.length > 0 && (
        <div>
          <span className="text-xs text-text-muted block mb-1">Recommendations</span>
          <ul className="space-y-1">
            {scanner.recommendations.map((r, i) => (
              <li key={i} className="flex items-center gap-2 text-xs text-blue-300">
                <Terminal className="h-3 w-3 shrink-0" />
                <span className="flex-1">{r}</span>
                <CopyButton text={r} label="recommendation" />
              </li>
            ))}
          </ul>
        </div>
      )}

      {scanner.missing_assets.length > 0 && (
        <div>
          <span className="text-xs text-text-muted block mb-1">Missing Assets</span>
          <ul className="space-y-1">
            {scanner.missing_assets.map((a, i) => (
              <li key={i} className="flex items-center gap-2 text-xs text-yellow-300">
                <AlertTriangle className="h-3 w-3 shrink-0" />
                {a}
              </li>
            ))}
          </ul>
        </div>
      )}

      {installInfo?.website && (
        <div className="flex items-center gap-2 text-xs">
          <ExternalLink className="h-3 w-3 text-text-muted" />
          <a
            href={installInfo.website}
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent hover:text-accent/80 transition-colors"
          >
            {installInfo.website}
          </a>
        </div>
      )}

      {installInfo?.best_command && (
        <div>
          <span className="text-xs text-text-muted block mb-1">Recommended Install</span>
          <div className="flex items-center gap-2 rounded-lg bg-surface-tertiary px-3 py-2">
            <code className="flex-1 text-xs text-text-primary font-mono">{installInfo.best_command.command}</code>
            <CopyButton text={installInfo.best_command.command} label="install command" />
          </div>
          <div className="mt-1 flex items-center gap-2 text-[10px] text-text-muted">
            <span>via {installInfo.best_command.manager}</span>
            {installInfo.best_command.requires_admin && <Badge variant="warning" size="sm">Admin required</Badge>}
          </div>
        </div>
      )}

      {installInfo?.verify_command && scanner.installed && (
        <div>
          <span className="text-xs text-text-muted block mb-1">Verify</span>
          <div className="flex items-center gap-2 rounded-lg bg-surface-tertiary px-3 py-2">
            <code className="flex-1 text-xs text-text-primary font-mono">{installInfo.verify_command}</code>
            <CopyButton text={installInfo.verify_command} label="verify command" />
          </div>
        </div>
      )}

      {installInfo?.commands && installInfo.commands.length > 1 && (
        <div>
          <span className="text-xs text-text-muted block mb-1">Other Installation Options</span>
          <div className="space-y-1">
            {installInfo.commands.map((cmd, i) => (
              <div key={i} className="flex items-center gap-2 rounded bg-surface-tertiary/50 px-2.5 py-1.5">
                <span className="text-[10px] font-medium text-text-muted w-16 shrink-0">{cmd.manager}</span>
                <code className="flex-1 text-xs text-text-secondary font-mono truncate">{cmd.command}</code>
                <CopyButton text={cmd.command} label={`${cmd.manager} command`} />
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex items-center gap-2 pt-1">
        <Button
          variant="ghost"
          size="xs"
          onClick={() => {
            const exportUrl = `/api/v1/scanners/${scannerId}/diagnostics?fmt=markdown`
            window.open(exportUrl, '_blank')
          }}
          iconLeft={<FileText className="h-3 w-3" />}
        >
          Export Markdown
        </Button>
        <Button
          variant="ghost"
          size="xs"
          onClick={() => {
            const exportUrl = `/api/v1/scanners/${scannerId}/diagnostics?fmt=text`
            window.open(exportUrl, '_blank')
          }}
          iconLeft={<FileText className="h-3 w-3" />}
        >
          Export Text
        </Button>
      </div>
    </div>
  )
}

export function ScannerHealthPanel({ className }: ScannerHealthPanelProps) {
  const { data, isLoading, error, refetch } = useScannerHealth()
  const [filter, setFilter] = useState<FilterMode>('all')
  const [selectedScanner, setSelectedScanner] = useState<string | null>(null)

  if (error) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle>Scanner Health</CardTitle>
        </CardHeader>
        <ErrorState
          title="Failed to load scanner status"
          message={(error as Error).message}
          onRetry={() => refetch()}
        />
      </Card>
    )
  }

  const scanners = data?.scanners ?? []
  const healthScore = data?.health_score ?? 0

  const filtered = scanners.filter((s) => {
    if (filter === 'installed') return s.installed
    if (filter === 'missing') return !s.installed
    if (filter === 'warning') return s.warnings.length > 0
    return true
  })

  const filterOptions: { key: FilterMode; label: string; count: number }[] = [
    { key: 'all', label: 'All', count: scanners.length },
    { key: 'installed', label: 'Installed', count: data?.installed ?? 0 },
    { key: 'missing', label: 'Missing', count: data?.missing ?? 0 },
    { key: 'warning', label: 'Warnings', count: scanners.filter(s => s.warnings.length > 0).length },
  ]

  return (
    <Card className={cn(className)}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Scanner Health</CardTitle>
            <CardDescription>
              {data?.usable ?? 0} of {data?.total ?? 0} scanners ready
            </CardDescription>
          </div>
          <Button variant="ghost" size="xs" onClick={() => refetch()} iconLeft={<RefreshCw className="h-3 w-3" />}>
            Refresh
          </Button>
        </div>
      </CardHeader>

      <div className="px-5 pb-3">
        <HealthBar score={healthScore} />
      </div>

      <div className="px-5 pb-3">
        <div className="flex gap-1.5 flex-wrap">
          {filterOptions.map((opt) => (
            <button
              key={opt.key}
              onClick={() => { setFilter(opt.key); setSelectedScanner(null) }}
              className={cn(
                'px-2.5 py-1 text-xs rounded-lg font-medium transition-colors',
                filter === opt.key
                  ? 'bg-accent/20 text-accent'
                  : 'text-text-muted hover:text-text-primary hover:bg-surface-tertiary',
              )}
            >
              {opt.label}
              <span className="ml-1 text-[10px] opacity-70">({opt.count})</span>
            </button>
          ))}
        </div>
      </div>

      <div className="px-3 pb-3 space-y-1">
        {isLoading ? (
          Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 rounded-lg p-3">
              <Skeleton className="h-8 w-8 rounded-lg" />
              <div className="flex-1 space-y-1.5">
                <Skeleton className="h-4 w-1/3" />
                <Skeleton className="h-3 w-1/2" />
              </div>
            </div>
          ))
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<ShieldOff className="h-8 w-8" />}
            title="No scanners match filter"
            description="Try changing the filter selection"
          />
        ) : (
          filtered.map((scanner) => (
            <div key={scanner.scanner_id}>
              <ScannerRow scanner={scanner} onSelect={setSelectedScanner} />
              {selectedScanner === scanner.scanner_id && (
                <ScannerDetailPanel
                  scannerId={scanner.scanner_id}
                  onClose={() => setSelectedScanner(null)}
                />
              )}
            </div>
          ))
        )}
      </div>
    </Card>
  )
}
