import { lazy } from "react"

export const LazyFindingsTab = lazy(() =>
  import("../components/findings-tab").then((m) => ({ default: m.FindingsTab }))
)

export const LazyEvidenceTab = lazy(() =>
  import("../components/evidence-tab").then((m) => ({ default: m.EvidenceTab }))
)

export const LazyRecommendationsTab = lazy(() =>
  import("../components/recommendations-tab").then((m) => ({ default: m.RecommendationsTab }))
)

export const LazyTimelineTab = lazy(() =>
  import("../components/timeline-tab").then((m) => ({ default: m.TimelineTab }))
)

export const LazyReportsTab = lazy(() =>
  import("../components/reports-tab").then((m) => ({ default: m.ReportsTab }))
)

export const LazyLiveEventsTab = lazy(() =>
  import("@/widgets/live-events/live-events-widget").then((m) => ({ default: m.LiveEventsTab }))
)
