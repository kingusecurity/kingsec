import { ChevronRight } from 'lucide-react'
import { cn } from '@/lib/utils'

interface BreadcrumbProps {
  className?: string
  children: React.ReactNode
}

interface BreadcrumbItemProps {
  className?: string
  children: React.ReactNode
  href?: string
  isCurrent?: boolean
}

interface BreadcrumbSeparatorProps {
  className?: string
}

export function Breadcrumb({ className, children }: BreadcrumbProps) {
  return (
    <nav aria-label="Breadcrumb" className={cn('', className)}>
      <ol className="flex items-center gap-1.5 text-sm text-text-muted">
        {children}
      </ol>
    </nav>
  )
}

export function BreadcrumbItem({
  className,
  children,
  href,
  isCurrent,
}: BreadcrumbItemProps) {
  const content = href ? (
    <a
      href={href}
      className={cn(
        'transition-colors hover:text-text-primary',
        isCurrent && 'text-text-primary font-medium',
        className,
      )}
      aria-current={isCurrent ? 'page' : undefined}
    >
      {children}
    </a>
  ) : (
    <span
      className={cn(
        isCurrent && 'text-text-primary font-medium',
        className,
      )}
      aria-current={isCurrent ? 'page' : undefined}
    >
      {children}
    </span>
  )

  return <li className="inline-flex items-center gap-1.5">{content}</li>
}

export function BreadcrumbSeparator({ className }: BreadcrumbSeparatorProps) {
  return (
    <li className="inline-flex items-center" aria-hidden="true">
      <ChevronRight className={cn('h-4 w-4', className)} />
    </li>
  )
}
