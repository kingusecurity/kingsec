import { useEffect, useRef } from 'react'

interface ShortcutMap {
  [key: string]: () => void
}

export function useKeyboardShortcuts(shortcuts: ShortcutMap) {
  const shortcutsRef = useRef(shortcuts)
  shortcutsRef.current = shortcuts

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement) {
        return
      }

      const shortcut = shortcutsRef.current[e.key]
      if (shortcut) {
        e.preventDefault()
        shortcut()
      }
    }

    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])
}
