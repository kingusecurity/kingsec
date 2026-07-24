import { useParams, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { useAssessment } from '@/hooks/use-assessments'

export function AssessmentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data, isLoading } = useAssessment(id ?? '')

  if (isLoading) {
    return <div className="text-gray-500">Loading...</div>
  }

  if (!data) {
    return <div className="text-gray-500">Assessment not found.</div>
  }

  return (
    <div className="space-y-6">
      <Link
        to="/assessments"
        className="flex items-center gap-2 text-sm text-gray-400 hover:text-white"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to assessments
      </Link>

      <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
        <h1 className="text-2xl font-bold">{data.target}</h1>
        <div className="mt-4 grid gap-4 sm:grid-cols-3">
          <div>
            <span className="text-xs text-gray-500">Status</span>
            <p className="font-medium">{data.status}</p>
          </div>
          <div>
            <span className="text-xs text-gray-500">Authorized</span>
            <p className="font-medium">{data.is_authorized ? 'Yes' : 'No'}</p>
          </div>
          <div>
            <span className="text-xs text-gray-500">Created</span>
            <p className="font-medium">{data.created_at}</p>
          </div>
        </div>
      </div>

      {data.findings.length > 0 && (
        <div className="rounded-lg border border-gray-800">
          <div className="border-b border-gray-800 px-4 py-3">
            <h2 className="font-semibold">Findings ({data.findings.length})</h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 bg-gray-900">
                <th className="px-4 py-3 text-left font-medium text-gray-400">Title</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Severity</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Status</th>
              </tr>
            </thead>
            <tbody>
              {data.findings.map((finding) => (
                <tr key={finding.finding_id} className="border-b border-gray-800">
                  <td className="px-4 py-3">{finding.title}</td>
                  <td className="px-4 py-3">
                    <span className={`rounded px-2 py-0.5 text-xs ${
                      finding.severity === 'critical' ? 'bg-red-900 text-red-400' :
                      finding.severity === 'high' ? 'bg-orange-900 text-orange-400' :
                      finding.severity === 'medium' ? 'bg-yellow-900 text-yellow-400' :
                      'bg-gray-800 text-gray-400'
                    }`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400">{finding.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
