import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useRegister } from '@/hooks/use-auth'
import { useAuthStore } from '@/store/auth'

const registerSchema = z.object({
  username: z.string().min(3).max(64),
  email: z.string().min(5).max(254).email(),
  password: z.string().min(8).max(128),
})

type RegisterForm = z.infer<typeof registerSchema>

export function RegisterPage() {
  const navigate = useNavigate()
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const registerMutation = useRegister()

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
  })

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }

  const onSubmit = (data: RegisterForm) => {
    registerMutation.mutate(data, {
      onSuccess: () => navigate('/login', { replace: true }),
    })
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      <h1 className="text-center text-xl font-semibold">Create account</h1>

      {registerMutation.error && (
        <div className="rounded-md bg-red-900/50 px-3 py-2 text-sm text-red-400">
          {registerMutation.error.message}
        </div>
      )}

      {registerMutation.isSuccess && (
        <div className="rounded-md bg-emerald-900/50 px-3 py-2 text-sm text-emerald-400">
          Account created. You can now sign in.
        </div>
      )}

      <div>
        <input
          {...register('username')}
          placeholder="Username"
          className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none"
        />
        {errors.username && (
          <p className="mt-1 text-xs text-red-400">{errors.username.message}</p>
        )}
      </div>

      <div>
        <input
          {...register('email')}
          type="email"
          placeholder="Email"
          className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none"
        />
        {errors.email && (
          <p className="mt-1 text-xs text-red-400">{errors.email.message}</p>
        )}
      </div>

      <div>
        <input
          {...register('password')}
          type="password"
          placeholder="Password (min 8 chars)"
          className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none"
        />
        {errors.password && (
          <p className="mt-1 text-xs text-red-400">{errors.password.message}</p>
        )}
      </div>

      <button
        type="submit"
        disabled={registerMutation.isPending}
        className="w-full rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:opacity-50"
      >
        {registerMutation.isPending ? 'Creating...' : 'Create account'}
      </button>

      <p className="text-center text-sm text-gray-500">
        Already have an account?{' '}
        <Link to="/login" className="text-emerald-500 hover:text-emerald-400">
          Sign in
        </Link>
      </p>
    </form>
  )
}
