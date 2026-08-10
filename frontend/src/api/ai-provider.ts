import { apiRequest } from './client'

export interface AIProviderConfig {
  provider: string
  model: string | null
  /** The real model that will actually be used if `model` is blank —
   * provider-specific, never the raw AISettings default from another
   * provider (that mismatch is what caused the Gemini 404). */
  effective_model: string
  base_url: string | null
  api_key_masked: string | null
  source: 'database' | 'environment' | 'none'
  updated_at: string | null
}

export interface SaveAIProviderConfigBody {
  provider: string
  api_key?: string | null
  model?: string | null
  base_url?: string | null
}

export interface TestAIProviderConfigBody {
  provider: string
  api_key: string
  model?: string | null
  base_url?: string | null
}

export interface TestAIProviderConfigResult {
  success: boolean
  message: string
}

export const aiProviderApi = {
  get: () => apiRequest<AIProviderConfig>('/settings/ai-provider'),

  save: (body: SaveAIProviderConfigBody) =>
    apiRequest<{ status: string; provider: string }>('/settings/ai-provider', {
      method: 'PUT',
      body,
    }),

  test: (body: TestAIProviderConfigBody) =>
    apiRequest<TestAIProviderConfigResult>('/settings/ai-provider/test', {
      method: 'POST',
      body,
    }),
}
