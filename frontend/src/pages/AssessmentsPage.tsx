import { Link } from 'react-router-dom'
import { Plus } from 'lucide-react'
import { useAuthStore } from '@/store/auth'
import { useAssessments } from '@/hooks/use-assessments'

export function AssessmentsPage() {
  const user = useAuthStore((s) => s.user)
  const canCreate = user && (user.role.toLowerCase() === 'analyst' || user.role.toLowerCase() === 'admin')
  const { data, isLoading } = useAssessments()

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Assessments</h1>
        {canCreate && (
          <Link
            to="/assessments/new"
            className="flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500"
          >
            <Plus className="h-4 w-4" />
            New Assessment
          </Link>
        )}
      </div>

      {isLoading ? (
        <div className="text-center text-gray-500">Loading...</div>
      ) : data && data.items.length > 0 ? (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 bg-gray-900">
                <th className="px-4 py-3 text-left font-medium text-gray-400">Target</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Status</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Findings</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Created</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((item) => (
                <tr
                  key={item.assessment_id}
                  className="border-b border-gray-800 transition-colors hover:bg-gray-900"
                >
                  <td className="px-4 py-3">
                    <Link
                      to={`/assessments/${item.assessment_id}`}
                      className="text-emerald-500 hover:text-emerald-400"
                    >
                      {item.target}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded bg-gray-800 px-2 py-0.5 text-xs">
                      {item.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400">{item.findings_count}</td>
                  <td className="px-4 py-3 text-gray-400">{item.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="text-center text-gray-500">No assessments yet.</div>
      )}
    </div>
  )
}
