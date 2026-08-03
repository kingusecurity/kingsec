import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Pagination } from '@/components/ui/Pagination'
import { useKevEntries } from '@/hooks/use-threat-intelligence'

export function KevViewPage() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [ransomwareOnly, setRansomwareOnly] = useState(false)
  const { data, isLoading } = useKevEntries({ search: search || undefined, known_ransomware: ransomwareOnly || undefined, page, page_size: 20 })

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.ceil(total / 20)

  return (
    <PageContainer>
      <PageHeader
        title="Known Exploited Vulnerabilities"
        description="CISA KEV catalog — vulnerabilities known to be exploited in the wild"
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <input
          type="text"
          placeholder="Search KEV entries..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1) }}
          className="rounded border border-border-primary bg-bg-secondary px-3 py-1.5 text-sm text-text-primary"
        />
        <label className="flex items-center gap-2 text-sm text-text-muted">
          <input type="checkbox" checked={ransomwareOnly} onChange={(e) => { setRansomwareOnly(e.target.checked); setPage(1) }} className="rounded" />
          Ransomware Campaign Only
        </label>
        <span className="text-xs text-text-muted">{total} entries</span>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8"><Spinner /></div>
      ) : items.length > 0 ? (
        <div className="space-y-2">
          {items.map((cve) => cve.kev_entry && (
            <Card key={cve.id}>
              <div className="px-5 py-3">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <a href={`/threat-intelligence/cves/${cve.id}`} className="text-sm font-medium text-accent-primary hover:underline">{cve.cve_code}</a>
                      <Badge variant="danger">KEV</Badge>
                      {cve.kev_entry.known_ransomware_campaign_use && <Badge variant="danger">Ransomware</Badge>}
                      <span className="text-xs text-text-muted">{cve.kev_entry.vulnerability_name}</span>
                    </div>
                    <div className="mt-1 grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-text-primary">
                      <span><span className="text-text-muted">Vendor:</span> {cve.kev_entry.vendor_project}</span>
                      <span><span className="text-text-muted">Product:</span> {cve.kev_entry.product}</span>
                      <span><span className="text-text-muted">Date Added:</span> {cve.kev_entry.date_added}</span>
                      <span><span className="text-text-muted">Due Date:</span> {cve.kev_entry.due_date}</span>
                    </div>
                    <p className="mt-1 text-xs text-text-muted">{cve.kev_entry.required_action}</p>
                  </div>
                  <div className="ml-4 flex flex-col items-end">
                    <span className="text-lg font-bold text-text-primary">{cve.threat_score.toFixed(1)}</span>
                    <span className="text-xs text-text-muted">Score</span>
                  </div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      ) : (
        <p className="py-8 text-center text-sm text-text-muted">No KEV entries found</p>
      )}

      <div className="mt-4 flex justify-center">
        <Pagination currentPage={page} totalPages={totalPages} onPageChange={setPage} />
      </div>
    </PageContainer>
  )
}
