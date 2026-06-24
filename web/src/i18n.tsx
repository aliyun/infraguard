import { createContext, useContext, useState, type ReactNode } from 'react'

type Lang = 'en' | 'zh'

const dict: Record<string, Record<Lang, string>> = {
  'nav.playground': { en: 'Playground', zh: '扫描' },
  'nav.catalog': { en: 'Policies', zh: '策略' },
  'nav.studio': { en: 'Rule Studio', zh: '规则工作台' },
  'sub.playground': { en: 'Scan a template against compliance rules in real time.', zh: '对模板实时执行合规规则扫描。' },
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
  'common.back': { en: 'Back', zh: '返回' },
  'common.noViolations': { en: 'No violations found.', zh: '未发现违规。' },
  'detail.resources': { en: 'Resources', zh: '资源类型' },
  'detail.description': { en: 'Description', zh: '描述' },
  'filter.product': { en: 'Product', zh: '产品' },
  'filter.resourceType': { en: 'Resource type', zh: '资源类型' },
  'tab.overview': { en: 'Overview', zh: '总览' },
  'tab.packs': { en: 'Packs', zh: '合规包' },
  'tab.rules': { en: 'Rules', zh: '规则' },
  'catalog.coverage': { en: 'Coverage by service', zh: '按服务覆盖' },
  'scan.policies': { en: 'Policies', zh: '策略' },
  'scan.allPolicies': { en: 'All policies', zh: '全部策略' },
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

function detectLang(): Lang {
  const saved = localStorage.getItem('ig_lang')
  if (saved === 'en' || saved === 'zh') return saved
  if (typeof navigator !== 'undefined' && (navigator.language || '').toLowerCase().startsWith('zh')) return 'zh'
  return 'en'
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(detectLang)
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
