import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useLogin } from '@/hooks/use-auth'
import { useAuthStore } from '@/store/auth'

const loginSchema = z.object({
  username: z.string().min(3).max(64),
  password: z.string().min(1).max(128),
})

type LoginForm = z.infer<typeof loginSchema>

export function LoginPage() {
  const navigate = useNavigate()
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const login = useLogin()

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
  })

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }

  const onSubmit = (data: LoginForm) => {
    login.mutate(data, {
      onSuccess: () => navigate('/dashboard', { replace: true }),
    })
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      <h1 className="text-center text-xl font-semibold">Sign in</h1>

      {login.error && (
        <div className="rounded-md bg-red-900/50 px-3 py-2 text-sm text-red-400">
          {login.error.message}
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
          {...register('password')}
          type="password"
          placeholder="Password"
          className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none"
        />
        {errors.password && (
          <p className="mt-1 text-xs text-red-400">{errors.password.message}</p>
        )}
      </div>

      <button
        type="submit"
        disabled={login.isPending}
        className="w-full rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:opacity-50"
      >
        {login.isPending ? 'Signing in...' : 'Sign in'}
      </button>

      <p className="text-center text-sm text-gray-500">
        No account?{' '}
        <Link to="/register" className="text-emerald-500 hover:text-emerald-400">
          Register
        </Link>
      </p>
    </form>
  )
}
