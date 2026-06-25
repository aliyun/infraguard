import { useEffect, useMemo, useRef, useState } from 'react'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import styles from './styles.module.css'

declare global {
  interface Window {
    Go: new () => { importObject: WebAssembly.Imports; run: (i: WebAssembly.Instance) => void }
    infraguardScan: (content: string, modules: string, lang: string, iac: string) => string
  }
}

// ---- Types matching the policy-dump payload + WASM output ------------------

interface Impl {
  path: string
  content: string
}
interface RuleMeta {
  id: string
  name: Record<string, string>
  severity: string
  iac_types: string[]
  impls: Record<string, Impl>
}
interface PackMeta {
  id: string
  name: Record<string, string>
  rules: string[]
}
interface Payload {
  lib_modules: Record<string, string>
  rules: RuleMeta[]
  packs: PackMeta[]
}
interface SnippetLine {
  line_num: number
  content: string
  highlight: boolean
}
interface Violation {
  severity: string
  id: string
  resource_id: string
  file: string
  line: number
  snippet_lines?: SnippetLine[]
  reason: string
  recommendation: string
}

const SAMPLES: Record<string, string> = {
  ros: `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyBucket:
    Type: ALIYUN::OSS::Bucket
    Properties:
      AccessControl: public-read
`,
  terraform: `resource "alicloud_oss_bucket" "my_bucket" {
  bucket = "my-bucket"
  acl    = "public-read"
}
`,
}

const SEV_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 }

// ---- Syntax highlighting (offline, span class="tok-*") ---------------------

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

function tokenize(src: string, re: RegExp, classes: string[]): string {
  let out = ''
  let last = 0
  re.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(src))) {
    if (m[0] === '') {
      re.lastIndex++
      continue
    }
    out += esc(src.slice(last, m.index))
    let cls = 'tok-p'
    for (let g = 1; g < m.length; g++) {
      if (m[g] != null) {
        cls = classes[g - 1]
        break
      }
    }
    out += `<span class="${cls}">${esc(m[0])}</span>`
    last = m.index + m[0].length
  }
  out += esc(src.slice(last))
  return out
}

function highlight(src: string, lang: string): string {
  if (lang === 'hcl') {
    const re =
      /(#[^\n]*|\/\/[^\n]*)|("(?:[^"\\]|\\.)*")|\b(resource|variable|provider|module|data|output|locals|terraform|true|false|null)\b|([A-Za-z_][\w-]*)(?=\s*=)|\b(\d+(?:\.\d+)?)\b/g
    return tokenize(src, re, ['tok-c', 'tok-s', 'tok-k', 'tok-a', 'tok-n'])
  }
  const re =
    /(#[^\n]*)|((?<=^[ \t]*(?:- )?)[\w.\-/]+(?=\s*:))|("(?:[^"\\]|\\.)*"|'(?:[^']|'')*')|\b(true|false|null)\b|\b(\d+(?:\.\d+)?)\b/gm
  return tokenize(src, re, ['tok-c', 'tok-a', 'tok-s', 'tok-b', 'tok-n'])
}

// Build a context snippet (±2 lines) from the editor content, since the wasm
// engine has no filesystem to read the source back from.
function buildSnippet(content: string, line: number): SnippetLine[] {
  if (!line || line < 1) return []
  const lines = content.split('\n')
  const start = Math.max(1, line - 2)
  const end = Math.min(lines.length, line + 2)
  const out: SnippetLine[] = []
  for (let n = start; n <= end; n++) {
    out.push({ line_num: n, content: lines[n - 1] ?? '', highlight: n === line })
  }
  return out
}

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script')
    s.src = src
    s.onload = () => resolve()
    s.onerror = () => reject(new Error('failed to load ' + src))
    document.head.appendChild(s)
  })
}

export default function Playground() {
  const { i18n, siteConfig } = useDocusaurusContext()
  // Static assets are served from the site root (e.g. /infraguard/playground/...).
  // siteConfig.baseUrl carries the locale segment for non-default locales
  // (/infraguard/zh/), so strip it to avoid requesting a non-existent
  // /infraguard/zh/playground/ path.
  let base = siteConfig.baseUrl
  const loc = i18n.currentLocale
  if (loc !== i18n.defaultLocale && base.endsWith(`/${loc}/`)) {
    base = base.slice(0, base.length - loc.length - 1)
  }
  const wasmUrl = `${base}playground/infraguard.wasm`
  const execUrl = `${base}playground/wasm_exec.js`
  const rulesUrl = `${base}playground/rules.json`
  const zh = i18n.currentLocale.startsWith('zh')
  const t = (en: string, zhs: string) => (zh ? zhs : en)
  const pick = (n: Record<string, string>, fallback: string) =>
    (zh && n.zh) || n.en || Object.values(n)[0] || fallback

  const [status, setStatus] = useState('loading')
  const [iac, setIac] = useState('ros')
  const [content, setContent] = useState(SAMPLES.ros)
  const [selected, setSelected] = useState<string[]>([])
  const [result, setResult] = useState<{ violations: Violation[]; error?: string } | null>(null)
  const [filter, setFilter] = useState('')
  const [loading, setLoading] = useState(false)
  const data = useRef<Payload | null>(null)
  const taRef = useRef<HTMLTextAreaElement>(null)
  const preRef = useRef<HTMLPreElement>(null)
  const [, forceRender] = useState(0)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        await loadScript(execUrl)
        const go = new window.Go()
        const [buf, payload] = await Promise.all([
          fetch(wasmUrl).then((x) => x.arrayBuffer()),
          fetch(rulesUrl).then((x) => x.json()),
        ])
        const res = await WebAssembly.instantiate(buf, go.importObject)
        go.run(res.instance)
        data.current = payload
        if (!cancelled) {
          setStatus('ready')
          forceRender((n) => n + 1)
        }
      } catch (e) {
        if (!cancelled) setStatus('error: ' + (e as Error).message)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [execUrl, wasmUrl, rulesUrl])

  // Picker options for the current IaC: packs first, then individual rules.
  const options = useMemo(() => {
    const d = data.current
    if (!d) return [] as { value: string; label: string; sub: string }[]
    const packs = d.packs.map((p) => ({ value: `pack:${p.id}`, label: `📦 ${pick(p.name, p.id)}`, sub: p.id }))
    const rules = d.rules
      .filter((r) => r.iac_types.includes(iac))
      .map((r) => ({ value: r.id, label: pick(r.name, r.id), sub: r.id }))
    return [...packs, ...rules]
  }, [iac, status, zh])

  function changeIac(v: string) {
    setIac(v)
    setContent(SAMPLES[v] ?? '')
    setResult(null)
    setFilter('')
  }

  function resolveModules(): Record<string, string> {
    const d = data.current
    if (!d) return {}
    const byId = new Map(d.rules.map((r) => [r.id, r]))
    let ids: string[]
    if (selected.length === 0) {
      ids = d.rules.map((r) => r.id)
    } else {
      const set = new Set<string>()
      for (const v of selected) {
        if (v.startsWith('pack:')) {
          d.packs.find((p) => p.id === v.slice(5))?.rules.forEach((id) => set.add(id))
        } else {
          set.add(v)
        }
      }
      ids = [...set]
    }
    const modules: Record<string, string> = {}
    for (const id of ids) {
      const impl = byId.get(id)?.impls?.[iac]
      if (impl) modules[impl.path] = impl.content
    }
    return modules
  }

  function scan() {
    const d = data.current
    if (!d) return
    setLoading(true)
    setFilter('')
    try {
      const payload = JSON.stringify({ lib_modules: d.lib_modules, modules: resolveModules() })
      const res = window.infraguardScan(content, payload, zh ? 'zh' : 'en', iac)
      const parsed = JSON.parse(res) as { violations?: Violation[]; error?: string }
      setResult({ violations: parsed.violations ?? [], error: parsed.error })
    } catch (e) {
      setResult({ violations: [], error: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }

  function sync() {
    if (preRef.current && taRef.current) {
      preRef.current.scrollTop = taRef.current.scrollTop
      preRef.current.scrollLeft = taRef.current.scrollLeft
    }
  }

  const sorted = useMemo(() => {
    const list = [...(result?.violations ?? [])]
    list.sort((a, b) => (SEV_ORDER[a.severity?.toLowerCase()] ?? 9) - (SEV_ORDER[b.severity?.toLowerCase()] ?? 9))
    return list
  }, [result])
  const visible = filter ? sorted.filter((v) => v.severity?.toLowerCase() === filter) : sorted

  const counts = useMemo(() => {
    const c: Record<string, number> = { high: 0, medium: 0, low: 0 }
    for (const v of sorted) c[v.severity?.toLowerCase()] = (c[v.severity?.toLowerCase()] || 0) + 1
    return c
  }, [sorted])

  const scanText = loading
    ? t('Scanning…', '扫描中…')
    : status === 'ready'
      ? t('Scan', '扫描')
      : status === 'loading'
        ? t('Loading…', '加载中…')
        : status

  return (
    <div className={styles.scope}>
      <p className={styles.intro}>
        {t(
          'Run compliance rules against an Alibaba Cloud ROS or Terraform template, right in your browser. For the full experience, run ',
          '在浏览器中对阿里云 ROS 或 Terraform 模板执行合规规则扫描。完整功能请运行 ',
        )}
        <code>infraguard server start</code>
        {t(' to try it out.', ' 来体验。')}
      </p>

      <div className="row">
        <div className="col">
          <div className="toolbar">
            <div className="segmented" role="tablist">
              {['ros', 'terraform'].map((v) => (
                <button
                  key={v}
                  type="button"
                  role="tab"
                  aria-selected={iac === v}
                  className={iac === v ? 'active' : ''}
                  onClick={() => changeIac(v)}
                >
                  {v === 'ros' ? 'ROS' : 'Terraform'}
                </button>
              ))}
            </div>
            <div className="grow">
              <MultiSelect
                options={options}
                selected={selected}
                onChange={setSelected}
                allLabel={t('All policies', '全部策略')}
                searchPlaceholder={t('Search', '搜索')}
                selectedLabel={t('selected', '已选')}
              />
            </div>
            <button onClick={scan} disabled={status !== 'ready' || loading}>
              {scanText}
            </button>
          </div>

          <div className="code-editor">
            <pre className="code-hl" ref={preRef} aria-hidden="true">
              <code dangerouslySetInnerHTML={{ __html: highlight(content, iac === 'terraform' ? 'hcl' : 'yaml') + '\n' }} />
            </pre>
            <textarea
              className="code-input"
              ref={taRef}
              spellCheck={false}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              onScroll={sync}
            />
          </div>
        </div>

        <div className="col results">
          {result?.error && <div className="error">{result.error}</div>}
          {result && !result.error && (
            <>
              <div className="summary-line">
                <button
                  type="button"
                  className={`sevchip ${!filter ? 'active' : ''}`}
                  onClick={() => setFilter('')}
                >
                  <span className="badge muted">{t('All', '全部')}</span> {sorted.length}
                </button>
                {(['high', 'medium', 'low'] as const).map((s) => (
                  <button
                    key={s}
                    type="button"
                    className={`sevchip ${filter === s ? 'active' : ''}`}
                    onClick={() => setFilter(filter === s ? '' : s)}
                  >
                    <span className={`badge ${s}`}>{s}</span> {counts[s] || 0}
                  </button>
                ))}
              </div>
              {visible.length === 0 ? (
                <div className="empty">✓ {t('No violations found.', '未发现违规。')}</div>
              ) : (
                visible.map((v, i) => <ViolationCard key={i} v={v} content={content} lineLabel={t('line', '行')} />)
              )}
            </>
          )}
          {!result && <div className="empty">{t('Run a scan to see results.', '点击扫描查看结果。')}</div>}
        </div>
      </div>
    </div>
  )
}

// ---- Sub-components --------------------------------------------------------

function ViolationCard({ v, content, lineLabel }: { v: Violation; content: string; lineLabel: string }) {
  const sev = (v.severity || '').toLowerCase()
  const sevClass = sev === 'high' || sev === 'medium' || sev === 'low' ? sev : 'muted'
  const snippet = v.snippet_lines && v.snippet_lines.length > 0 ? v.snippet_lines : buildSnippet(content, v.line)
  return (
    <div className="violation">
      <div className="v-head">
        <span className={`badge ${sevClass}`}>{sev}</span>
        <span className="v-title">{v.reason || v.id}</span>
      </div>
      <div className="v-meta">
        <code>{v.id}</code>
        <span className="v-dot">·</span>
        <span>{v.resource_id}</span>
        <span className="v-dot">·</span>
        <span>
          {v.file}:{v.line}
        </span>
      </div>
      {snippet.length > 0 && (
        <pre>
          {snippet.map((l) => (
            <span key={l.line_num} className={l.highlight ? 'hl' : undefined}>
              {String(l.line_num).padStart(4)} {l.content}
              {'\n'}
            </span>
          ))}
        </pre>
      )}
      {v.recommendation && <div className="v-rec">{v.recommendation}</div>}
    </div>
  )
}

function MultiSelect({
  options,
  selected,
  onChange,
  allLabel,
  searchPlaceholder,
  selectedLabel,
}: {
  options: { value: string; label: string; sub?: string }[]
  selected: string[]
  onChange: (v: string[]) => void
  allLabel: string
  searchPlaceholder: string
  selectedLabel: string
}) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])

  const filtered = useMemo(() => {
    const q = query.toLowerCase()
    return q
      ? options.filter(
          (o) =>
            o.value.toLowerCase().includes(q) ||
            o.label.toLowerCase().includes(q) ||
            (o.sub || '').toLowerCase().includes(q),
        )
      : options
  }, [options, query])

  const sel = new Set(selected)
  function toggle(v: string) {
    const next = new Set(sel)
    next.has(v) ? next.delete(v) : next.add(v)
    onChange([...next])
  }

  const triggerText = selected.length === 0 ? allLabel : `${selected.length} ${selectedLabel}`

  return (
    <div className="select" ref={ref} style={{ width: '100%' }}>
      <button type="button" className="select-trigger" onClick={() => setOpen((v) => !v)}>
        <span className={selected.length === 0 ? 'muted' : undefined}>{triggerText}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>
      {open && (
        <div className="select-menu ms-menu">
          <input
            className="ms-search"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={searchPlaceholder}
          />
          <button type="button" className={selected.length === 0 ? 'active' : ''} onClick={() => onChange([])}>
            {allLabel}
          </button>
          {filtered.map((o) => (
            <button
              key={o.value}
              type="button"
              className={sel.has(o.value) ? 'active' : ''}
              onClick={() => toggle(o.value)}
            >
              <span className="ms-check">{sel.has(o.value) ? '✓' : ''}</span>
              <span className="ms-opt">
                <span className="ms-opt-label">{o.label}</span>
                {o.sub && <span className="ms-opt-sub">{o.sub}</span>}
              </span>
            </button>
          ))}
          {filtered.length === 0 && <div className="ms-empty muted">—</div>}
        </div>
      )}
    </div>
  )
}
