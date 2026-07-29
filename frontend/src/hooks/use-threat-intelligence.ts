import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import * as ti from '../api/threat-intelligence'

// --- Summary ---
export function useTISummary() {
  return useQuery({
    queryKey: ['ti-summary'],
    queryFn: ti.getTISummary,
    refetchInterval: 120_000,
  })
}

// --- CVEs ---
export function useCves(filter?: ti.CveFilter) {
  return useQuery({
    queryKey: ['cves', filter],
    queryFn: () => ti.listCves(filter),
  })
}

export function useCve(id: string | undefined) {
  return useQuery({
    queryKey: ['cve', id],
    queryFn: () => ti.getCveById(id!),
    enabled: !!id,
  })
}

export function useSyncCve() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (cveCode: string) => ti.syncCve(cveCode),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cves'] })
      qc.invalidateQueries({ queryKey: ['ti-summary'] })
    },
  })
}

export function useDeleteCve() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => ti.deleteCve(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cves'] })
      qc.invalidateQueries({ queryKey: ['ti-summary'] })
    },
  })
}

export function useCveRiskAssessment(id: string | undefined) {
  return useQuery({
    queryKey: ['cve-risk', id],
    queryFn: () => ti.getCveRiskAssessment(id!),
    enabled: !!id,
  })
}

// --- KEV ---
export function useKevEntries(filter?: {
  search?: string
  known_ransomware?: boolean
  vendor?: string
  product?: string
  page?: number
  page_size?: number
}) {
  return useQuery({
    queryKey: ['kev-entries', filter],
    queryFn: () => ti.listKevEntries(filter),
  })
}

// --- EPSS ---
export function useEpssScore(cveCode: string | undefined) {
  return useQuery({
    queryKey: ['epss', cveCode],
    queryFn: () => ti.getEpssScore(cveCode!),
    enabled: !!cveCode,
  })
}

// --- Trending ---
export function useTrendingThreats(limit?: number) {
  return useQuery({
    queryKey: ['trending-threats', limit],
    queryFn: () => ti.getTrendingThreats(limit),
    refetchInterval: 300_000,
  })
}

// --- Trends ---
export function useTITrends(days?: number) {
  return useQuery({
    queryKey: ['ti-trends', days],
    queryFn: () => ti.getTITrends(days),
  })
}

// --- Timeline ---
export function useTITimeline(days?: number) {
  return useQuery({
    queryKey: ['ti-timeline', days],
    queryFn: () => ti.getTITimeline(days),
  })
}

// --- Critical ---
export function useCriticalCves(limit?: number) {
  return useQuery({
    queryKey: ['critical-cves', limit],
    queryFn: () => ti.getCriticalCves(limit),
    refetchInterval: 120_000,
  })
}

// --- Feeds ---
export function useFeeds() {
  return useQuery({
    queryKey: ['ti-feeds'],
    queryFn: ti.listFeeds,
  })
}

export function useRegisterFeed() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (args: { feedType: string; title: string; sourceUrl?: string }) =>
      ti.registerFeed(args.feedType, args.title, args.sourceUrl),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ti-feeds'] })
    },
  })
}

// --- Reports ---
export function useThreatReport(days?: number) {
  return useQuery({
    queryKey: ['ti-report-threat', days],
    queryFn: () => ti.generateThreatReport(days),
    enabled: false,
  })
}

export function useExecutiveReport(days?: number) {
  return useQuery({
    queryKey: ['ti-report-executive', days],
    queryFn: () => ti.generateExecutiveReport(days),
    enabled: false,
  })
}

export function useKevReport() {
  return useQuery({
    queryKey: ['ti-report-kev'],
    queryFn: ti.generateKevReport,
    enabled: false,
  })
}

export function useHighRiskReport(minScore?: number) {
  return useQuery({
    queryKey: ['ti-report-high-risk', minScore],
    queryFn: () => ti.generateHighRiskReport(minScore),
    enabled: false,
  })
}
