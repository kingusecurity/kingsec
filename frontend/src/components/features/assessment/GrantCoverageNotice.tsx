import { Link } from 'react-router-dom'
import { Alert } from '@/components/ui/Alert'
import { SurfaceTierNotice } from '@/components/shared/SurfaceTierNotice'
import type { CheckGrantCoverageResponse } from '@/api/grants'

interface GrantCoverageNoticeProps {
  result: CheckGrantCoverageResponse
}

/**
 * Renders at the point the target+profile are known, before the
 * authorization-scope refusal would otherwise only appear after the full
 * form is submitted. Two distinct cases, per Phase 4's real enforcement:
 *
 *  - no grant covers this target at all (every required tier uncovered)
 *  - Blocking-1: a grant DOES cover this target, just not at the tier
 *    this profile's scanners need (e.g. a URL-prefix grant when a
 *    host-level scan is required) - at least one tier shows a grant_id
 *    even though fully_covered is false.
 *
 * The Blocking-1 wording reuses SurfaceTierNotice - the same component
 * the Authorization Grants create form uses - never a second copy.
 */
export function GrantCoverageNotice({ result }: GrantCoverageNoticeProps) {
  if (!result.enforced || result.fully_covered) {
    return null
  }

  const isBlocking1 = result.required_tiers.some((t) => t.covered)

  return (
    <div className="space-y-2">
      {isBlocking1 ? (
        <SurfaceTierNotice title="A grant exists, but not at the tier this scan needs" />
      ) : (
        <Alert variant="warning" title="No authorization grant covers this target">
          This profile needs a grant to run, and none currently covers{' '}
          <strong>{result.target_value}</strong>. Create one before continuing - KingSec will refuse to
          run this assessment without it.
        </Alert>
      )}
      <Link
        to="/grants"
        target="_blank"
        rel="noopener noreferrer"
        className="inline-block text-sm text-emerald-500 hover:text-emerald-400"
      >
        Create a covering grant (opens in a new tab) &rarr;
      </Link>
    </div>
  )
}
