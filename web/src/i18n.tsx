import { createContext, useContext, useState, type ReactNode } from 'react'

type Lang = 'en' | 'zh'

const dict: Record<string, Record<Lang, string>> = {
  'nav.playground': { en: 'Playground', zh: '在线扫描' },
  'nav.report': { en: 'Report', zh: '报告' },
  'nav.catalog': { en: 'Policies', zh: '策略目录' },
  'nav.studio': { en: 'Rule Studio', zh: '规则工作台' },
  'sub.playground': { en: 'Scan a template against compliance rules in real time.', zh: '对模板实时执行合规规则扫描。' },
  'sub.report': { en: 'Load a scan report and explore the findings.', zh: '加载扫描报告并浏览结果。' },
  'sub.catalog': { en: 'Browse built-in rules and packs, and coverage.', zh: '浏览内置规则、合规包与覆盖情况。' },
  'sub.studio': { en: 'Write a Rego rule and evaluate or test it instantly.', zh: '编写 Rego 规则并即时评估或测试。' },
  'common.scan': { en: 'Scan', zh: '扫描' },
  'common.run': { en: 'Run', zh: '运行' },
  'common.test': { en: 'Test', zh: '测试' },
  'common.loading': { en: 'Loading…', zh: '加载中…' },
  'common.search': { en: 'Search', zh: '搜索' },
  'common.severity': { en: 'Severity', zh: '严重级别' },
  'common.resource': { en: 'Resource', zh: '资源' },
  'common.rule': { en: 'Rule', zh: '规则' },
  'common.all': { en: 'All', zh: '全部' },
  'common.chooseFile': { en: 'Choose file', zh: '选择文件' },
  'common.noViolations': { en: 'No violations found.', zh: '未发现违规。' },
  'tab.overview': { en: 'Overview', zh: '总览' },
  'tab.packs': { en: 'Packs', zh: '合规包' },
  'tab.rules': { en: 'Rules', zh: '规则' },
  'catalog.coverage': { en: 'Coverage by service', zh: '按服务覆盖' },
  'scan.policies': { en: 'Policies', zh: '策略' },
  'scan.allPolicies': { en: 'All policies', zh: '全部策略' },
  'report.drop': { en: 'Paste a scan JSON report, or load a file', zh: '粘贴扫描 JSON 报告，或加载文件' },
  'studio.template': { en: 'Template', zh: '模板' },
  'studio.compliant': { en: 'Compliant fixture', zh: '合规夹具' },
  'studio.violation': { en: 'Violation fixture', zh: '违规夹具' },
  'studio.rego': { en: 'Rego rule', zh: 'Rego 规则' },
  'studio.pass': { en: 'PASS', zh: '通过' },
  'studio.fail': { en: 'FAIL', zh: '失败' },
}

interface I18nCtx {
  lang: Lang
  setLang: (l: Lang) => void
  t: (key: string) => string
}

const Ctx = createContext<I18nCtx>({ lang: 'en', setLang: () => {}, t: (k) => k })

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>((localStorage.getItem('ig_lang') as Lang) || 'en')
  const setLang = (l: Lang) => {
    localStorage.setItem('ig_lang', l)
    setLangState(l)
  }
  const t = (key: string) => dict[key]?.[lang] ?? key
  return <Ctx.Provider value={{ lang, setLang, t }}>{children}</Ctx.Provider>
}

export function useI18n() {
  return useContext(Ctx)
}

// pick returns the value for the current language from an i18n map, falling back to en.
export function pick(m: Record<string, string> | undefined, lang: string): string {
  if (!m) return ''
  return m[lang] || m['en'] || Object.values(m)[0] || ''
}
