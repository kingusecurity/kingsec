import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useNavigate, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { useCreateAssessment } from '@/hooks/use-assessments'

const createSchema = z.object({
  target_value: z.string().min(1).max(2048),
  target_type: z.enum(['ip_address', 'hostname', 'url', 'network']),
  authorized_by: z.string().min(1).max(256),
  scope: z.string().min(1).max(2048),
})

type CreateForm = z.infer<typeof createSchema>

export function CreateAssessmentPage() {
  const navigate = useNavigate()
  const createAssessment = useCreateAssessment()

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<CreateForm>({
    resolver: zodResolver(createSchema),
    defaultValues: { target_type: 'ip_address' },
  })

  const onSubmit = (data: CreateForm) => {
    createAssessment.mutate(data, {
      onSuccess: (result) => {
        navigate(`/assessments/${result.assessment_id}`, { replace: true })
      },
    })
  }

  return (
    <div className="mx-auto max-w-lg space-y-6">
      <Link
        to="/assessments"
        className="flex items-center gap-2 text-sm text-gray-400 hover:text-white"
      >
        <ArrowLeft className="h-4 w-4" />
        Back
      </Link>

      <h1 className="text-2xl font-bold">New Assessment</h1>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        <div>
          <label className="block text-sm text-gray-400">Target</label>
          <input
            {...register('target_value')}
            placeholder="10.0.0.5"
            className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none"
          />
          {errors.target_value && (
            <p className="mt-1 text-xs text-red-400">{errors.target_value.message}</p>
          )}
        </div>

        <div>
          <label className="block text-sm text-gray-400">Target Type</label>
          <select
            {...register('target_type')}
            className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm focus:border-emerald-500 focus:outline-none"
          >
            <option value="ip_address">IP Address</option>
            <option value="hostname">Hostname</option>
            <option value="url">URL</option>
            <option value="network">Network</option>
          </select>
        </div>

        <div>
          <label className="block text-sm text-gray-400">Authorized By</label>
          <input
            {...register('authorized_by')}
            placeholder="admin@company.com"
            className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none"
          />
          {errors.authorized_by && (
            <p className="mt-1 text-xs text-red-400">{errors.authorized_by.message}</p>
          )}
        </div>

        <div>
          <label className="block text-sm text-gray-400">Scope</label>
          <input
            {...register('scope')}
            placeholder="10.0.0.0/24"
            className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none"
          />
          {errors.scope && (
            <p className="mt-1 text-xs text-red-400">{errors.scope.message}</p>
          )}
        </div>

        <button
          type="submit"
          disabled={createAssessment.isPending}
          className="w-full rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:opacity-50"
        >
          {createAssessment.isPending ? 'Creating...' : 'Create Assessment'}
        </button>
      </form>
    </div>
  )
}
