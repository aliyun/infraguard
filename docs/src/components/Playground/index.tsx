import { useEffect, useRef, useState } from 'react'
import useBaseUrl from '@docusaurus/useBaseUrl'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import styles from './styles.module.css'

declare global {
  interface Window {
    Go: new () => { importObject: WebAssembly.Imports; run: (i: WebAssembly.Instance) => void }
    infraguardScan: (content: string, modules: string, lang: string) => string
  }
}

const SAMPLE = `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyBucket:
    Type: ALIYUN::OSS::Bucket
    Properties:
      AccessControl: public-read
`

interface Violation {
  severity: string
  id: string
  resource_id: string
  line: number
  reason: string
  recommendation: string
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

// Minimal YAML highlighter matching the InfraGuard server editors.
function highlightYaml(src: string): string {
  const re =
    /(#[^\n]*)|((?<=^[ \t]*(?:- )?)[\w.\-/]+(?=\s*:))|("(?:[^"\\]|\\.)*"|'(?:[^']|'')*')|\b(true|false|null)\b|\b(\d+(?:\.\d+)?)\b/gm
  let out = ''
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(src))) {
    if (m[0] === '') {
      re.lastIndex++
      continue
    }
    out += esc(src.slice(last, m.index))
    const cls = m[1] ? styles.tokC : m[2] ? styles.tokA : m[3] ? styles.tokS : m[4] ? styles.tokK : styles.tokN
    out += `<span class="${cls}">${esc(m[0])}</span>`
    last = m.index + m[0].length
  }
  out += esc(src.slice(last))
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
  const wasmUrl = useBaseUrl('/playground/infraguard.wasm')
  const execUrl = useBaseUrl('/playground/wasm_exec.js')
  const rulesUrl = useBaseUrl('/playground/rules.json')
  const { i18n } = useDocusaurusContext()
  const zh = i18n.currentLocale.startsWith('zh')
  const t = (en: string, zhs: string) => (zh ? zhs : en)

  const [status, setStatus] = useState('loading')
  const [content, setContent] = useState(SAMPLE)
  const [result, setResult] = useState<{ violations: Violation[]; error?: string } | null>(null)
  const rules = useRef('')
  const taRef = useRef<HTMLTextAreaElement>(null)
  const preRef = useRef<HTMLPreElement>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        await loadScript(execUrl)
        const go = new window.Go()
        const [buf, r] = await Promise.all([
          fetch(wasmUrl).then((x) => x.arrayBuffer()),
          fetch(rulesUrl).then((x) => x.text()),
        ])
        const res = await WebAssembly.instantiate(buf, go.importObject)
        go.run(res.instance)
        rules.current = r
        if (!cancelled) setStatus('ready')
      } catch (e) {
        if (!cancelled) setStatus('error: ' + (e as Error).message)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [execUrl, wasmUrl, rulesUrl])

  function scan() {
    try {
      const res = window.infraguardScan(content, rules.current, zh ? 'zh' : 'en')
      setResult(JSON.parse(res))
    } catch (e) {
      setResult({ violations: [], error: (e as Error).message })
    }
  }

  function sync() {
    if (preRef.current && taRef.current) {
      preRef.current.scrollTop = taRef.current.scrollTop
      preRef.current.scrollLeft = taRef.current.scrollLeft
    }
  }

  const sevClass = (s: string) => styles[s] || styles.muted

  const buttonText =
    status === 'ready' ? t('Scan', '扫描') : status === 'loading' ? t('Loading…', '加载中…') : status

  return (
    <div>
      <p className={styles.intro}>
        {t(
          'Scan an Alibaba Cloud ROS template against compliance rules, right in your browser. Covers the quick-start rule set — for the full set use the CLI or ',
          '在浏览器中对阿里云 ROS 模板执行合规规则扫描。当前覆盖快速体验规则集；完整规则集请使用 CLI 或 ',
        )}
        <code>infraguard server</code>
        {t('.', '。')}
      </p>
      <div className={styles.row}>
        <div>
          <div className={styles.toolbar}>
            <span className={styles.ros}>ROS</span>
            <span className={styles.grow} />
            <button className={styles.scan} disabled={status !== 'ready'} onClick={scan}>
              {buttonText}
            </button>
          </div>
          <div className={styles.editorWrap}>
            <pre className={`${styles.code} ${styles.hl}`} ref={preRef} aria-hidden="true">
              <code dangerouslySetInnerHTML={{ __html: highlightYaml(content) + '\n' }} />
            </pre>
            <textarea
              className={`${styles.code} ${styles.input}`}
              ref={taRef}
              spellCheck={false}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              onScroll={sync}
            />
          </div>
        </div>
        <div className={styles.results}>
          {result?.error && <div className={styles.error}>{result.error}</div>}
          {result && !result.error && result.violations.length === 0 && (
            <p className={styles.empty}>✓ {t('No violations found.', '未发现违规。')}</p>
          )}
          {result?.violations?.map((v, i) => (
            <div key={i} className={styles.card}>
              <div className={styles.cardHead}>
                <span className={`${styles.badge} ${sevClass(v.severity)}`}>{v.severity}</span>
                <span className={styles.title}>{v.reason || v.id}</span>
              </div>
              <div className={styles.meta}>
                {v.id} · {v.resource_id} · {t('line', '行')} {v.line}
              </div>
              {v.recommendation && <div className={styles.rec}>{v.recommendation}</div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
