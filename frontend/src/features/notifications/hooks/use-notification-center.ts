import { useCallback } from "react"
import { useGlobalSSE, type GlobalSSEEvent } from "./use-global-sse"
import { useNotificationStore, selectUnreadCount } from "./use-notification-store"
import { sseEventToNotification } from "./use-notification-mapper"

export function useNotificationCenter() {
  const addNotification = useNotificationStore((s) => s.addNotification)

  const handleSSEEvent = useCallback(
    (event: GlobalSSEEvent) => {
      const notification = sseEventToNotification(event)
      if (notification) {
        addNotification(notification)
      }
    },
    [addNotification],
  )

  const sse = useGlobalSSE({
    enabled: true,
    onEvent: handleSSEEvent,
  })

  const panelOpen = useNotificationStore((s) => s.panelOpen)
  const togglePanel = useNotificationStore((s) => s.togglePanel)
  const setPanelOpen = useNotificationStore((s) => s.setPanelOpen)
  const unreadCount = useNotificationStore(selectUnreadCount)

  return {
    unreadCount,
    panelOpen,
    togglePanel,
    setPanelOpen,
    isConnected: sse.isConnected,
    sseError: sse.error,
    reconnect: sse.reconnect,
  }
}
