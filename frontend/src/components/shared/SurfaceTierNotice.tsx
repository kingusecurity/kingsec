import { Globe } from 'lucide-react'
import { Alert } from '@/components/ui/Alert'

/**
 * The one shared piece of copy explaining Phase 4's "Blocking-1"
 * surface-tier mechanism: a URL-scoped grant authorizes the web
 * application at that URL, never a host-level scan of the server it
 * runs on. Used in two places that must never read differently - the
 * Authorization Grants create form (where the distinction is chosen)
 * and the new-assessment flow's refusal guidance (where an operator
 * who didn't build the grant discovers why their scan was refused).
 * Sourced once here so neither can drift from the other.
 */
export function SurfaceTierNotice({ title = 'This does not authorize a host scan' }: { title?: string }) {
  return (
    <Alert variant="warning" title={title} icon={<Globe className="h-5 w-5" />}>
      A URL grant authorizes scanning <strong>the web application at that URL only</strong> - it does{' '}
      <strong>not</strong> authorize a full port/host scan of the server it runs on. A web-scan against this
      URL will succeed; a host-level scan (for example, a port sweep across the whole machine) will still be
      refused until you also create a separate <strong>IP Address</strong> or <strong>Hostname</strong> grant
      for the underlying host.
    </Alert>
  )
}
