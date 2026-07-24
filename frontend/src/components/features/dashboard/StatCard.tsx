import { Card, CardTitle, CardDescription } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { cn } from '@/lib/utils'

interface StatCardProps {
  icon: React.ComponentType<{ className?: string }>
  label: string
  value: string | number
  description?: string
  loading?: boolean
  variant?: 'default' | 'danger' | 'success' | 'warning'
}

const iconColors: Record<string, string> = {
  default: 'text-accent bg-accent/10',
  danger: 'text-red-400 bg-red-900/30',
  success: 'text-emerald-400 bg-emerald-900/30',
  warning: 'text-yellow-400 bg-yellow-900/30',
}

export function StatCard({
  icon: Icon,
  label,
  value,
  description,
  loading,
  variant = 'default',
}: StatCardProps) {
  return (
    <Card variant="default">
      <div className="p-5">
        <div className="flex items-center gap-3">
          <div className={cn('flex h-10 w-10 items-center justify-center rounded-lg', iconColors[variant])}>
            <Icon className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <CardTitle className="text-sm font-medium text-text-secondary">{label}</CardTitle>
            {loading ? (
              <Skeleton className="h-8 w-20 mt-1" />
            ) : (
              <p className="text-2xl font-semibold text-text-primary">{value}</p>
            )}
          </div>
        </div>
        {description && !loading && (
          <CardDescription className="mt-2">{description}</CardDescription>
        )}
      </div>
    </Card>
  )
}
