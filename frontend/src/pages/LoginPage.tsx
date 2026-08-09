import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useLogin, useRecoveryLogin, useVerifyMfa } from '@/hooks/use-auth'
import { useAuthStore } from '@/store/auth'

const loginSchema = z.object({
  username: z.string().min(3).max(64),
  password: z.string().min(1).max(128),
})

type LoginForm = z.infer<typeof loginSchema>

const totpSchema = z.object({
  totp_code: z.string().min(6).max(10),
})

type TotpForm = z.infer<typeof totpSchema>

const recoverySchema = z.object({
  recovery_code: z.string().min(1).max(64),
})

type RecoveryForm = z.infer<typeof recoverySchema>

export function LoginPage() {
  const navigate = useNavigate()
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const login = useLogin()
  const verifyMfa = useVerifyMfa()
  const recoveryLogin = useRecoveryLogin()

  // Held only in component state, never persisted - it's single-use and
  // expires in minutes, so there's nothing to gain from storing it anywhere
  // more durable than this page.
  const [pendingToken, setPendingToken] = useState<string | null>(null)
  const [useRecoveryCode, setUseRecoveryCode] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
  })

  const {
    register: registerTotp,
    handleSubmit: handleTotpSubmit,
    formState: { errors: totpErrors },
  } = useForm<TotpForm>({
    resolver: zodResolver(totpSchema),
  })

  const {
    register: registerRecovery,
    handleSubmit: handleRecoverySubmit,
    formState: { errors: recoveryErrors },
  } = useForm<RecoveryForm>({
    resolver: zodResolver(recoverySchema),
  })

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }

  const onSubmit = (data: LoginForm) => {
    login.mutate(data, {
      onSuccess: (result) => {
        if (result.mfa_required && result.pending_token) {
          setPendingToken(result.pending_token)
          return
        }
        navigate('/dashboard', { replace: true })
      },
    })
  }

  const onTotpSubmit = (data: TotpForm) => {
    if (!pendingToken) return
    verifyMfa.mutate(
      { pending_token: pendingToken, totp_code: data.totp_code },
      { onSuccess: () => navigate('/dashboard', { replace: true }) },
    )
  }

  const onRecoverySubmit = (data: RecoveryForm) => {
    if (!pendingToken) return
    recoveryLogin.mutate(
      { pending_token: pendingToken, recovery_code: data.recovery_code },
      { onSuccess: () => navigate('/dashboard', { replace: true }) },
    )
  }

  if (pendingToken) {
    const mfaError = useRecoveryCode ? recoveryLogin.error : verifyMfa.error
    const isPending = useRecoveryCode ? recoveryLogin.isPending : verifyMfa.isPending

    return (
      <form
        onSubmit={useRecoveryCode ? handleRecoverySubmit(onRecoverySubmit) : handleTotpSubmit(onTotpSubmit)}
        className="space-y-4"
      >
        <h1 className="text-center text-xl font-semibold">Two-factor verification</h1>
        <p className="text-center text-sm text-gray-500">
          {useRecoveryCode
            ? 'Enter one of your unused recovery codes.'
            : 'Enter the 6-digit code from your authenticator app.'}
        </p>

        {mfaError && (
          <div className="rounded-md bg-red-900/50 px-3 py-2 text-sm text-red-400">
            {mfaError.message}
          </div>
        )}

        {useRecoveryCode ? (
          <div>
            <input
              {...registerRecovery('recovery_code')}
              placeholder="Recovery code"
              autoFocus
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none"
            />
            {recoveryErrors.recovery_code && (
              <p className="mt-1 text-xs text-red-400">{recoveryErrors.recovery_code.message}</p>
            )}
          </div>
        ) : (
          <div>
            <input
              {...registerTotp('totp_code')}
              placeholder="123456"
              inputMode="numeric"
              autoFocus
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none"
            />
            {totpErrors.totp_code && (
              <p className="mt-1 text-xs text-red-400">{totpErrors.totp_code.message}</p>
            )}
          </div>
        )}

        <button
          type="submit"
          disabled={isPending}
          className="w-full rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:opacity-50"
        >
          {isPending ? 'Verifying...' : 'Verify'}
        </button>

        <div className="flex items-center justify-between text-sm">
          <button
            type="button"
            onClick={() => setUseRecoveryCode((v) => !v)}
            className="text-emerald-500 hover:text-emerald-400"
          >
            {useRecoveryCode ? 'Use authenticator code instead' : "Lost your device? Use a recovery code"}
          </button>
          <button
            type="button"
            onClick={() => setPendingToken(null)}
            className="text-gray-500 hover:text-gray-400"
          >
            Back
          </button>
        </div>
      </form>
    )
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
