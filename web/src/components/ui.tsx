import type { Severity, Summary, Violation } from '../api'
import { useI18n } from '../i18n'

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const s = (severity || '').toLowerCase()
  const cls = s === 'high' || s === 'medium' || s === 'low' ? s : 'muted'
  return <span className={`badge ${cls}`}>{s}</span>
}

export function Editor({
  value,
  onChange,
  placeholder,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
}) {
  return (
    <textarea
      className="code"
      spellCheck={false}
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

export function SummaryLine({ summary }: { summary: Summary }) {
  const { t } = useI18n()
  const c = summary.severity_counts || {}
  return (
    <div className="summary-line">
      <strong>{summary.total_violations}</strong>
      <SeverityBadge severity="high" /> {c.high || 0}
      <SeverityBadge severity="medium" /> {c.medium || 0}
      <SeverityBadge severity="low" /> {c.low || 0}
      {summary.waived_count > 0 && (
        <span className="muted">
          · {summary.waived_count} {t('scan.waived')}
        </span>
      )}
      {summary.expired_waiver_count > 0 && (
        <span className="badge medium">
          {summary.expired_waiver_count} {t('scan.expired')}
        </span>
      )}
    </div>
  )
}

export function ViolationCard({ v }: { v: Violation }) {
  return (
    <div className={`violation ${v.waiver?.status === 'active' ? 'waived' : ''}`}>
      <div className="v-head">
        <SeverityBadge severity={v.severity} />
        <span className="v-title">{v.reason || v.id}</span>
        {v.waiver && (
          <span className={`badge ${v.waiver.status === 'expired' ? 'medium' : 'muted'}`}>
            {v.waiver.status === 'expired' ? '⚠ expired' : '⊘ waived'}
          </span>
        )}
      </div>
      <div className="v-meta">
        {v.id} · {v.resource_id} · {v.file}:{v.line}
      </div>
      {v.snippet_lines && v.snippet_lines.length > 0 && (
        <pre>
          {v.snippet_lines.map((l) => (
            <span key={l.line_num} className={l.highlight ? 'hl' : undefined}>
              {String(l.line_num).padStart(4)} {l.content}
              {'\n'}
            </span>
          ))}
        </pre>
      )}
      {v.recommendation && <div className="v-meta">→ {v.recommendation}</div>}
      {v.waiver && (
        <div className="waiver-note">
          {v.waiver.source}: {v.waiver.reason}
          {v.waiver.expires ? ` (expires ${v.waiver.expires})` : ''}
        </div>
      )}
    </div>
  )
}
