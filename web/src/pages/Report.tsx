import { useMemo, useState } from 'react'
import type { Summary, Violation } from '../api'
import { useI18n } from '../i18n'
import { SeverityBadge, SummaryLine, ViolationCard } from '../components/ui'

interface ParsedReport {
  summary?: Summary
  violations: Violation[]
}

function parseReport(text: string): ParsedReport {
  const data = JSON.parse(text)
  let violations: Violation[] = []
  if (Array.isArray(data.results)) {
    for (const f of data.results) {
      for (const v of f.violations || []) violations.push({ ...v, file: v.file || f.file })
    }
  } else if (Array.isArray(data.violations)) {
    violations = data.violations
  }
  return { summary: data.summary, violations }
}

export default function Report() {
  const { t } = useI18n()
  const [text, setText] = useState('')
  const [report, setReport] = useState<ParsedReport | null>(null)
  const [error, setError] = useState('')
  const [severity, setSeverity] = useState('')
  const [groupBy, setGroupBy] = useState<'file' | 'rule'>('file')

  function load(raw: string) {
    setText(raw)
    setError('')
    if (!raw.trim()) {
      setReport(null)
      return
    }
    try {
      setReport(parseReport(raw))
    } catch (e) {
      setError((e as Error).message)
      setReport(null)
    }
  }

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    file.text().then(load)
  }

  const grouped = useMemo(() => {
    if (!report) return []
    const filtered = report.violations.filter((v) => !severity || v.severity === severity)
    const map = new Map<string, Violation[]>()
    for (const v of filtered) {
      const key = groupBy === 'file' ? v.file : v.id
      if (!map.has(key)) map.set(key, [])
      map.get(key)!.push(v)
    }
    return [...map.entries()]
  }, [report, severity, groupBy])

  return (
    <div>
      <h1 className="page-title">{t('nav.report')}</h1>
      <p className="page-sub">{t('sub.report')}</p>
      {!report && (
        <div className="panel">
          <label>{t('report.drop')}</label>
          <textarea className="code" value={text} onChange={(e) => load(e.target.value)} placeholder='{"summary": ..., "results": [...]}' />
          <div style={{ marginTop: '.6rem' }}>
            <input type="file" accept=".json,application/json" onChange={onFile} />
          </div>
          {error && <div className="error">{error}</div>}
        </div>
      )}
      {report && (
        <>
          <div className="toolbar">
            {report.summary && <SummaryLine summary={report.summary} />}
            <span className="grow" />
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={{ width: 'auto' }}>
              <option value="">{t('common.all')}</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
            <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as 'file' | 'rule')} style={{ width: 'auto' }}>
              <option value="file">by file</option>
              <option value="rule">by rule</option>
            </select>
            <button className="secondary" onClick={() => { setReport(null); setText('') }}>
              ×
            </button>
          </div>
          {grouped.map(([key, vs]) => (
            <div key={key} style={{ marginBottom: '1rem' }}>
              <h3 style={{ margin: '0 0 .5rem', fontSize: '1rem' }}>
                {key} <span className="muted">({vs.length})</span>
              </h3>
              {vs.map((v, i) => (
                <ViolationCard key={i} v={v} />
              ))}
            </div>
          ))}
          {grouped.length === 0 && (
            <div className="muted">
              <SeverityBadge severity="ok" /> {t('common.noViolations')}
            </div>
          )}
        </>
      )}
    </div>
  )
}
