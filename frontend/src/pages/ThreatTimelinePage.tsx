import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { useTITimeline } from '@/hooks/use-threat-intelligence'

export function ThreatTimelinePage() {
  const [days, setDays] = useState(30)
  const { data: events, isLoading } = useTITimeline(days)

  return (
    <PageContainer>
      <PageHeader title="Threat Timeline" description="Chronological view of CVE activity and threat events">
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="rounded border border-border-primary bg-bg-secondary px-2 py-1 text-xs text-text-primary"
        >
          <option value={7}>7 days</option>
          <option value={30}>30 days</option>
          <option value={90}>90 days</option>
        </select>
      </PageHeader>

      {isLoading ? (
        <div className="flex justify-center py-8"><Spinner /></div>
      ) : events && events.length > 0 ? (
        <div className="relative space-y-0">
          {events.map((ev, i) => (
            <div key={`${ev.cve_code}-${i}`} className="relative flex gap-4 pb-4 pl-6 before:absolute before:left-2 before:top-2 before:h-full before:w-0.5 before:bg-border-primary last:before:hidden">
              <div className="absolute left-1 top-2 h-3 w-3 rounded-full bg-accent-primary" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-text-muted">{ev.date}</span>
                  <Badge variant={ev.severity === 'CRITICAL' ? 'danger' : ev.severity === 'HIGH' ? 'warning' : 'neutral'}>{ev.severity}</Badge>
                  {ev.is_kev && <Badge variant="danger">KEV</Badge>}
                </div>
                <a href={`/threat-intelligence/cves/${encodeURIComponent(ev.cve_code)}`} className="text-sm font-medium text-accent-primary hover:underline">{ev.cve_code}</a>
                <p className="text-xs text-text-muted line-clamp-2">{ev.description}</p>
                <div className="mt-1 flex items-center gap-2 text-xs">
                  <span className="text-text-muted">Threat Score:</span>
                  <span className="font-bold text-text-primary">{ev.threat_score.toFixed(1)}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="py-8 text-center text-sm text-text-muted">No threat events in this period</p>
      )}
    </PageContainer>
  )
}
