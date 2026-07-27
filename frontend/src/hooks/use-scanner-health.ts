import { useQuery } from '@tanstack/react-query'
import { scannerHealthApi } from '@/api/scanner-health'

const POLL_INTERVAL = 15000

export function useScannerHealth() {
  return useQuery({
    queryKey: ['scanner-health'],
    queryFn: () => scannerHealthApi.health(),
    refetchInterval: POLL_INTERVAL,
  })
}

export function useScannerDetail(scannerId: string | null) {
  return useQuery({
    queryKey: ['scanner-detail', scannerId],
    queryFn: () => scannerHealthApi.detail(scannerId!),
    enabled: !!scannerId,
  })
}

export function useScannerList() {
  return useQuery({
    queryKey: ['scanner-list'],
    queryFn: () => scannerHealthApi.list(),
    refetchInterval: POLL_INTERVAL,
  })
}
