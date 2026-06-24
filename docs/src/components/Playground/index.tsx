import { useEffect, useRef, useState } from 'react'
import useBaseUrl from '@docusaurus/useBaseUrl'

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
  const [status, setStatus] = useState('loading')
  const [content, setContent] = useState(SAMPLE)
  const [result, setResult] = useState<{ violations: Violation[]; error?: string } | null>(null)
  const rules = useRef('')

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
      const res = window.infraguardScan(content, rules.current, 'en')
      setResult(JSON.parse(res))
    } catch (e) {
      setResult({ violations: [], error: (e as Error).message })
    }
  }

  const color: Record<string, string> = { high: '#dc2626', medium: '#d97706', low: '#0891b2' }

  return (
    <div style={{ maxWidth: 980, margin: '0 auto', padding: '1rem' }}>
      <p>
        Runs entirely in your browser via WebAssembly — no template leaves your machine. Covers the{' '}
        <strong>quick-start ROS rules</strong>. For the full rule set use the CLI or <code>infraguard server</code>.
      </p>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 320 }}>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            spellCheck={false}
            style={{ width: '100%', height: 320, fontFamily: 'monospace', fontSize: '.85rem', whiteSpace: 'pre' }}
          />
          <div style={{ marginTop: '.5rem' }}>
            <button
              className="button button--primary"
              disabled={status !== 'ready'}
              onClick={scan}
            >
              {status === 'ready' ? 'Scan' : status}
            </button>
          </div>
        </div>
        <div style={{ flex: 1, minWidth: 320 }}>
          {result?.error && <pre style={{ color: '#dc2626' }}>{result.error}</pre>}
          {result && !result.error && result.violations.length === 0 && <p>✓ No violations found.</p>}
          {result?.violations?.map((v, i) => (
            <div key={i} style={{ border: '1px solid var(--ifm-color-emphasis-300)', borderRadius: 8, padding: '.6rem .8rem', marginBottom: '.5rem' }}>
              <span style={{ background: color[v.severity] || '#6b7280', color: '#fff', borderRadius: 4, padding: '0 .4rem', fontSize: '.72rem', fontWeight: 700, textTransform: 'uppercase' }}>
                {v.severity}
              </span>{' '}
              <strong>{v.reason || v.id}</strong>
              <div style={{ color: 'var(--ifm-color-emphasis-600)', fontSize: '.82rem', marginTop: '.25rem' }}>
                {v.id} · {v.resource_id} · line {v.line}
              </div>
              {v.recommendation && <div style={{ fontSize: '.82rem', marginTop: '.25rem' }}>→ {v.recommendation}</div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
