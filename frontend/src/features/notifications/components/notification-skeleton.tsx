import { Skeleton } from "@/shared/components/loading-skeleton"

interface NotificationSkeletonProps {
  count?: number
}

export function NotificationSkeleton({ count = 5 }: NotificationSkeletonProps): React.ReactElement {
  return (
    <div className="divide-y divide-[hsl(var(--border))]">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="flex gap-3 px-4 py-3">
          <Skeleton className="size-4 shrink-0 rounded-full" />
          <div className="flex-1 space-y-2">
            <div className="flex items-center justify-between">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-3 w-12" />
            </div>
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-2/3" />
          </div>
        </div>
      ))}
    </div>
  )
}
