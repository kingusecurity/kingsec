import { useCallback, useRef, useState } from "react"

export function useCopyToClipboard(): { copy: (text: string) => Promise<boolean>; copied: boolean } {
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>()
  const [copied, setCopied] = useState(false)

  const copy = useCallback(async (text: string): Promise<boolean> => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      if (timeoutRef.current) clearTimeout(timeoutRef.current)
      timeoutRef.current = setTimeout(() => setCopied(false), 2000)
      return true
    } catch {
      const textarea = document.createElement("textarea")
      textarea.value = text
      textarea.style.position = "fixed"
      textarea.style.opacity = "0"
      document.body.appendChild(textarea)
      textarea.select()
      const result = document.execCommand("copy")
      document.body.removeChild(textarea)
      setCopied(result)
      if (timeoutRef.current) clearTimeout(timeoutRef.current)
      timeoutRef.current = setTimeout(() => setCopied(false), 2000)
      return result
    }
  }, [])

  return { copy, copied }
}
