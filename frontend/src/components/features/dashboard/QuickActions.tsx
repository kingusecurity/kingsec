import { Link } from 'react-router-dom'
import { Plus, FileText, Settings, BarChart3 } from 'lucide-react'
import { Card } from '@/components/ui/Card'

const actions = [
  { label: 'New Assessment', description: 'Create a security assessment', href: '/assessments/new', icon: Plus },
  { label: 'View Reports', description: 'Browse generated reports', href: '/assessments?status=completed', icon: FileText },
  { label: 'Dashboard', description: 'View security overview', href: '/dashboard', icon: BarChart3 },
  { label: 'Settings', description: 'Configure system', href: '/settings', icon: Settings },
]

export function QuickActions() {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {actions.map((action) => {
        const Icon = action.icon
        return (
          <Link key={action.label} to={action.href} className="block">
            <Card variant="outlined" className="p-4 transition-colors hover:bg-surface-tertiary/50 cursor-pointer">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/10">
                  <Icon className="h-4 w-4 text-accent" />
                </div>
                <div>
                  <p className="text-sm font-medium text-text-primary">{action.label}</p>
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
