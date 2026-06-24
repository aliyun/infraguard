// Typed client for the InfraGuard server API.

export type Severity = 'high' | 'medium' | 'low'

export interface I18nString {
  [lang: string]: string
}

export interface WaiverInfo {
  status: 'active' | 'expired'
  source: 'inline' | 'file'
  reason: string
  owner?: string
  expires?: string
}

export interface SnippetLine {
  line_num: number
  content: string
  highlight: boolean
}

export interface Violation {
  severity: Severity
  id: string
  resource_id: string
  file: string
  line: number
  snippet_lines: SnippetLine[]
  reason: string
  recommendation: string
  waiver?: WaiverInfo
}

export interface Summary {
  total_violations: number
  severity_counts: Record<string, number>
  files_scanned: number
  files_with_violations: number
  waived_count: number
  expired_waiver_count: number
}

export interface ScanResult {
  iac: string
  summary: Summary
  violations: Violation[]
}

export interface RuleSummary {
  id: string
  name: I18nString
  severity: Severity
  iac_types: string[]
  resource_types: string[]
  services: string[]
}

export interface PackSummary {
  id: string
  name: I18nString
  description: I18nString
  rule_count: number
}

export interface RuleDetail {
  id: string
  name: I18nString
  severity: Severity
  description: I18nString
  reason: I18nString
  recommendation: I18nString
  iac_types: string[]
  resource_types: string[]
  implementations: Record<string, { content: string; file_path: string; package_name: string }>
}

export interface Coverage {
  total_rules: number
  total_packs: number
  by_severity: Record<string, number>
  by_iac: Record<string, number>
  by_service: { key: string; count: number }[]
  by_framework: { id: string; name: I18nString; rules: number }[]
  resource_types: string[]
}

export interface Waiver {
  rule: string
  resource?: string
  files?: string[]
  reason: string
  expires?: string
  owner?: string
}

export interface WaiverIssue {
  index: number
  rule: string
  severity: string
  code: string
  detail?: string
}

export interface WaiversResponse {
  path: string
  waivers: Waiver[]
  issues: WaiverIssue[]
}

async function request<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(opts?.headers || {}) },
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : {}
  if (!res.ok) {
    throw new Error(data.error || `request failed (${res.status})`)
  }
  return data as T
}

export const api = {
  meta: () => request<{ version: string; languages: string[] }>('/api/meta'),
  scan: (body: unknown) => request<ScanResult>('/api/scan', { method: 'POST', body: JSON.stringify(body) }),
  policies: (params: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString()
    return request<{ rules: RuleSummary[]; packs: PackSummary[] }>(`/api/policies${qs ? '?' + qs : ''}`)
  },
  policyDetail: (id: string) =>
    request<{ kind: string; rule?: RuleDetail; pack?: PackSummary; rules?: RuleSummary[] }>(
      `/api/policies/${encodeURIComponent(id)}`,
    ),
  coverage: () => request<Coverage>('/api/coverage'),
  ruleEval: (body: unknown) => request<{ iac: string; violations: Violation[] }>('/api/rule/eval', { method: 'POST', body: JSON.stringify(body) }),
  ruleTest: (body: unknown) =>
    request<{ iac: string; pass: boolean; compliant: { violations: number; pass: boolean; error?: string }; violation: { violations: number; pass: boolean; error?: string } }>(
      '/api/rule/test',
      { method: 'POST', body: JSON.stringify(body) },
    ),
  waivers: () => request<WaiversResponse>('/api/waivers'),
  saveWaivers: (waivers: Waiver[]) => request<WaiversResponse>('/api/waivers', { method: 'POST', body: JSON.stringify({ waivers }) }),
}
