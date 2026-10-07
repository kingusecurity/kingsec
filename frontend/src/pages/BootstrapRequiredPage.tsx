import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useHealth } from '@/hooks/use-settings'

export function BootstrapRequiredPage() {
  const { data, refetch, isFetching } = useHealth()
  const navigate = useNavigate()

  // The "check again" button refetches health, but without this effect the
  // page never leaves even when an admin now exists — a dead end.
  useEffect(() => {
    if (data && !data.bootstrap_required) {
      navigate('/login', { replace: true })
    }
  }, [data, navigate])

  return (
    <div className="space-y-4">
      <h1 className="text-center text-xl font-semibold">Instance needs initializing</h1>

      <p className="text-sm text-text-secondary">
        No administrator account exists yet on this KingSec instance. For security, the first
        administrator cannot be created through this page - it has to be created on the machine
        running KingSec, with access to its command line.
      </p>

      <div className="rounded-lg border border-border-light bg-surface-tertiary p-3">
        <p className="mb-1 text-xs text-text-muted">On that machine, run:</p>
        <code className="block overflow-x-auto whitespace-pre text-sm text-emerald-400">
          kingsec-bootstrap --username &lt;name&gt; --password &lt;secret&gt;
        </code>
      </div>

      <p className="text-sm text-text-secondary">
        Once that command succeeds, sign in here with the username and password you chose.
      </p>

      <button
        type="button"
        onClick={() => refetch()}
        disabled={isFetching}
        className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm font-medium text-text-primary transition-colors hover:border-emerald-500 disabled:opacity-50"
      >
        {isFetching ? 'Checking...' : "I've run it - check again"}
      </button>
    </div>
  )
}
