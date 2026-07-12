import { useEffect, useRef } from "react"

export function SkipToContent(): React.ReactElement {
  const ref = useRef<HTMLAnchorElement>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && document.activeElement === ref.current) {
        ref.current?.blur()
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [])

  return (
    <a
      ref={ref}
      href="#main-content"
      className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[200] focus:rounded-lg focus:bg-[hsl(var(--primary))] focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-[hsl(var(--primary-fg))] focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
    >
      Skip to content
    </a>
  )
}
