import { useNavigate } from 'react-router-dom'
import { Bell } from 'lucide-react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { NotificationList } from '@/components/features/monitoring/NotificationList'
import { Card } from '@/components/ui/Card'

export function NotificationsPage() {
  const navigate = useNavigate()

  return (
    <PageContainer>
      <PageHeader
        title="Notifications"
        description="View and manage system notifications"
        actions={
          <div className="flex items-center gap-2 text-sm text-text-muted">
            <Bell className="h-4 w-4" />
            <span>All notifications</span>
          </div>
        }
      />
      <Card>
        <div className="p-6">
          <NotificationList
            onNavigate={(assessmentId) => navigate('/assessments/' + assessmentId)}
          />
        </div>
      </Card>
    </PageContainer>
  )
}
