import { Link } from 'react-router-dom'
import { Plus, FileText, Settings, BarChart3 } from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { useAuthStore } from '@/store/auth'

const actions = [
  { label: 'New Assessment', description: 'Create a security assessment', href: '/assessments/new', icon: Plus },
  { label: 'View Reports', description: 'Browse generated reports', href: '/reports', icon: FileText },
  { label: 'Dashboard', description: 'View security overview', href: '/dashboard', icon: BarChart3 },
  { label: 'Settings', description: 'Configure system', href: '/settings', icon: Settings },
]

interface QuickActionsProps {
  /** True for an account with no assessment history - highlights "New
   * Assessment" as the suggested first step instead of an unranked grid. */
  suggestFirst?: boolean
}

export function QuickActions({ suggestFirst = false }: QuickActionsProps) {
  const role = useAuthStore((s) => s.user?.role.toLowerCase())
  const canCreate = role === 'analyst' || role === 'admin'
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {actions.filter((action) => canCreate || action.label !== 'New Assessment').map((action) => {
        const Icon = action.icon
        const isSuggested = suggestFirst && action.label === 'New Assessment'
        return (
          <Link key={action.label} to={action.href} className="block">
            <Card
              variant={isSuggested ? 'success' : 'outlined'}
              className="p-4 transition-colors hover:bg-surface-tertiary/50 cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/10">
                  <Icon className="h-4 w-4 text-accent" />
                </div>
                <div>
                  <p className="flex items-center gap-1.5 text-sm font-medium text-text-primary">
                    {action.label}
                    {isSuggested && <Badge variant="success" size="sm">Start here</Badge>}
                  </p>
                  <p className="text-xs text-text-muted">{action.description}</p>
                </div>
              </div>
            </Card>
          </Link>
        )
      })}
    </div>
  )
}
