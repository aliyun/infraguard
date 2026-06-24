import { createContext, useContext, useState, type ReactNode } from 'react'

type Lang = 'en' | 'zh'

const dict: Record<string, Record<Lang, string>> = {
  'nav.playground': { en: 'Playground', zh: '在线扫描' },
  'nav.report': { en: 'Report', zh: '报告' },
  'nav.catalog': { en: 'Policies', zh: '策略目录' },
  'nav.studio': { en: 'Rule Studio', zh: '规则工作台' },
  'nav.waivers': { en: 'Waivers', zh: '豁免' },
  'sub.playground': { en: 'Scan a template against compliance rules in real time.', zh: '对模板实时执行合规规则扫描。' },
  'sub.report': { en: 'Load a scan report and explore the findings.', zh: '加载扫描报告并浏览结果。' },
  'sub.catalog': { en: 'Browse built-in rules and packs, and coverage.', zh: '浏览内置规则、合规包与覆盖情况。' },
  'sub.studio': { en: 'Write a Rego rule and evaluate or test it instantly.', zh: '编写 Rego 规则并即时评估或测试。' },
  'sub.waivers': { en: 'Review and edit the workspace waiver file.', zh: '查看并编辑工作区豁免文件。' },
  'common.scan': { en: 'Scan', zh: '扫描' },
  'common.run': { en: 'Run', zh: '运行' },
  'common.test': { en: 'Test', zh: '测试' },
  'common.save': { en: 'Save', zh: '保存' },
  'common.loading': { en: 'Loading…', zh: '加载中…' },
  'common.search': { en: 'Search', zh: '搜索' },
  'common.severity': { en: 'Severity', zh: '严重级别' },
  'common.resource': { en: 'Resource', zh: '资源' },
  'common.rule': { en: 'Rule', zh: '规则' },
  'common.all': { en: 'All', zh: '全部' },
  'common.noViolations': { en: 'No violations found.', zh: '未发现违规。' },
  'scan.policies': { en: 'Policies (rule/pack IDs, comma-separated; empty = all)', zh: '策略（规则/包 ID，逗号分隔；留空=全部）' },
  'scan.showWaived': { en: 'Show waived', zh: '显示已豁免' },
  'scan.waived': { en: 'waived', zh: '已豁免' },
  'scan.expired': { en: 'expired', zh: '已过期' },
  'report.drop': { en: 'Paste or drop a scan JSON report', zh: '粘贴或拖入扫描 JSON 报告' },
  'studio.template': { en: 'Template', zh: '模板' },
  'studio.compliant': { en: 'Compliant fixture', zh: '合规夹具' },
  'studio.violation': { en: 'Violation fixture', zh: '违规夹具' },
  'studio.rego': { en: 'Rego rule', zh: 'Rego 规则' },
  'studio.pass': { en: 'PASS', zh: '通过' },
  'studio.fail': { en: 'FAIL', zh: '失败' },
  'waivers.add': { en: 'Add waiver', zh: '新增豁免' },
  'waivers.reason': { en: 'Reason', zh: '原因' },
  'waivers.expires': { en: 'Expires', zh: '过期时间' },
  'waivers.owner': { en: 'Owner', zh: '责任人' },
  'waivers.none': { en: 'No waivers defined.', zh: '尚未定义豁免。' },
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
