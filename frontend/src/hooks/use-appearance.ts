import { useState, useEffect, useCallback } from 'react'

type Theme = 'dark' | 'light' | 'system'

const STORAGE_KEY = 'kingsec-theme'

function getStoredTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'dark' || stored === 'light' || stored === 'system') return stored
  } catch {}
  return 'system'
}

function getResolvedTheme(theme: Theme): 'dark' | 'light' {
  if (theme === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }
  return theme
}

export function useAppearance() {
  const [theme, setThemeState] = useState<Theme>(getStoredTheme)

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t)
    try {
      localStorage.setItem(STORAGE_KEY, t)
    } catch {}
  }, [])

  useEffect(() => {
    const resolved = getResolvedTheme(theme)
    document.documentElement.classList.toggle('dark', resolved === 'dark')
    document.documentElement.classList.toggle('light', resolved === 'light')
  }, [theme])

  useEffect(() => {
    if (theme !== 'system') return

    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const handler = () => {
      const resolved = mq.matches ? 'dark' : 'light'
      document.documentElement.classList.toggle('dark', resolved === 'dark')
      document.documentElement.classList.toggle('light', resolved === 'light')
    }
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [theme])

  const resolvedTheme = getResolvedTheme(theme)

  return { theme, resolvedTheme, setTheme }
}
