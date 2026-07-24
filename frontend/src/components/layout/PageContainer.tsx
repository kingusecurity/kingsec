import { cn } from '@/lib/utils'

interface PageContainerProps {
  children: React.ReactNode
  className?: string
}

export function PageContainer({ children, className }: PageContainerProps) {
  return (
    <div className={cn('space-y-6', className)}>
      {children}
    </div>
  )
}

interface PageHeaderProps {
  title: string
  description?: string
  actions?: React.ReactNode
  className?: string
}

export function PageHeader({ title, description, actions, className }: PageHeaderProps) {
  return (
    <div className={cn('flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between', className)}>
      <div className="space-y-1">
        <h1 className="text-2xl font-bold text-text-primary">{title}</h1>
        {description && (
          <p className="text-sm text-text-secondary">{description}</p>
        )}
      </div>
      {actions && (
        <div className="flex items-center gap-3">
          {actions}
        </div>
      )}
    </div>
  )
}

interface ContentSectionProps {
  title?: string
  description?: string
  children: React.ReactNode
  className?: string
}

export function ContentSection({ title, description, children, className }: ContentSectionProps) {
  return (
    <section className={cn('space-y-4', className)}>
      {title && (
        <div>
          <h2 className="text-lg font-semibold text-text-primary">{title}</h2>
          {description && (
            <p className="text-sm text-text-secondary">{description}</p>
          )}
        </div>
      )}
      {children}
    </section>
  )
}

interface StatGridProps {
  children: React.ReactNode
  className?: string
  columns?: 2 | 3 | 4
}

const columnClasses = {
  2: 'sm:grid-cols-2',
  3: 'sm:grid-cols-2 lg:grid-cols-3',
  4: 'sm:grid-cols-2 lg:grid-cols-4',
}

export function StatGrid({ children, className, columns = 4 }: StatGridProps) {
  return (
    <div className={cn('grid gap-4', columnClasses[columns], className)}>
      {children}
    </div>
  )
}

interface ResponsiveGridProps {
  children: React.ReactNode
  className?: string
  minWidth?: string
}

export function ResponsiveGrid({ children, className, minWidth = '16rem' }: ResponsiveGridProps) {
  return (
    <div
      className={cn('grid gap-4', className)}
      style={{ gridTemplateColumns: `repeat(auto-fill, minmax(${minWidth}, 1fr))` }}
    >
      {children}
    </div>
  )
}

interface PanelProps {
  children: React.ReactNode
  className?: string
  title?: string
  actions?: React.ReactNode
}

export function Panel({ children, className, title, actions }: PanelProps) {
  return (
    <div className={cn('rounded-xl border border-border bg-surface-secondary', className)}>
      {title && (
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
          {actions && (
            <div className="flex items-center gap-2">{actions}</div>
          )}
        </div>
      )}
      {children}
    </div>
  )
}
