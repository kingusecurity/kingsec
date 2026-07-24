import { useState } from 'react'
import { cn } from '@/lib/utils'

interface AvatarProps {
  src?: string
  alt?: string
  initials?: string
  fallback?: string
  size?: 'sm' | 'md' | 'lg' | 'xl'
  className?: string
}

const sizes = {
  sm: 'h-8 w-8 text-xs',
  md: 'h-10 w-10 text-sm',
  lg: 'h-12 w-12 text-base',
  xl: 'h-16 w-16 text-lg',
}

export function Avatar({
  src,
  alt = '',
  initials,
  fallback,
  size = 'md',
  className,
}: AvatarProps) {
  const [imgError, setImgError] = useState(false)

  const hasImage = src && !imgError
  const showInitials = initials && !hasImage
  const showFallback = !hasImage && !showInitials

  const letter = initials ?? fallback?.[0] ?? '?'

  return (
    <div
      className={cn(
        'relative inline-flex items-center justify-center rounded-full bg-surface-tertiary font-medium text-text-secondary overflow-hidden',
        sizes[size],
        className,
      )}
      aria-label={alt || initials || 'Avatar'}
    >
      {hasImage && (
        <img
          src={src}
          alt={alt}
          onError={() => setImgError(true)}
          className="h-full w-full object-cover"
        />
      )}
      {showInitials && <span>{letter.slice(0, 2).toUpperCase()}</span>}
      {showFallback && (
        <svg className="h-full w-full" viewBox="0 0 40 40" fill="none">
          <rect width="40" height="40" fill="currentColor" opacity="0.1" />
          <text
            x="20"
            y="20"
            textAnchor="middle"
            dominantBaseline="central"
            fill="currentColor"
            fontSize="16"
          >
            {letter.toUpperCase()}
          </text>
        </svg>
      )}
    </div>
  )
}
