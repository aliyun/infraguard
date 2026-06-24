import { useEffect, useState } from 'react'
import { api, type Coverage, type PackSummary, type RuleDetail, type RuleSummary } from '../api'
import { pick, useI18n } from '../i18n'
import { SeverityBadge } from '../components/ui'

export default function Catalog() {
  const { t, lang } = useI18n()
  const [coverage, setCoverage] = useState<Coverage | null>(null)
  const [rules, setRules] = useState<RuleSummary[]>([])
  const [packs, setPacks] = useState<PackSummary[]>([])
  const [q, setQ] = useState('')
  const [severity, setSeverity] = useState('')
  const [iac, setIac] = useState('')
  const [detail, setDetail] = useState<{ kind: string; rule?: RuleDetail; pack?: PackSummary; rules?: RuleSummary[] } | null>(null)

  useEffect(() => {
    api.coverage().then(setCoverage).catch(() => {})
  }, [])

  useEffect(() => {
    const params: Record<string, string> = {}
    if (q) params.q = q
    if (severity) params.severity = severity
    if (iac) params.iac = iac
    const h = setTimeout(() => {
      api.policies(params).then((d) => {
        setRules(d.rules)
        setPacks(d.packs)
      }).catch(() => {})
    }, 200)
    return () => clearTimeout(h)
  }, [q, severity, iac])

  function open(id: string) {
    api.policyDetail(id).then(setDetail).catch(() => {})
  }

  const maxService = coverage?.by_service[0]?.count || 1

  return (
    <div>
      <h1 className="page-title">{t('nav.catalog')}</h1>
      <p className="page-sub">{t('sub.catalog')}</p>

      {coverage && (
        <>
          <div className="stat-grid">
            <div className="stat"><div className="num">{coverage.total_rules}</div><div className="lbl">rules</div></div>
            <div className="stat"><div className="num">{coverage.total_packs}</div><div className="lbl">packs</div></div>
            <div className="stat"><div className="num" style={{ color: 'var(--high)' }}>{coverage.by_severity.high}</div><div className="lbl">high</div></div>
            <div className="stat"><div className="num" style={{ color: 'var(--medium)' }}>{coverage.by_severity.medium}</div><div className="lbl">medium</div></div>
            <div className="stat"><div className="num" style={{ color: 'var(--low)' }}>{coverage.by_severity.low}</div><div className="lbl">low</div></div>
            <div className="stat"><div className="num">{coverage.by_iac.both}</div><div className="lbl">ros+tf</div></div>
          </div>
          <div className="panel" style={{ marginBottom: '1rem' }}>
            <label>Coverage by service</label>
            {coverage.by_service.slice(0, 12).map((s) => (
              <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: '.6rem', marginBottom: '.3rem' }}>
                <span style={{ width: 110, fontSize: '.82rem' }}>{s.key}</span>
                <div className="bar" style={{ flex: 1 }}><span style={{ width: `${(s.count / maxService) * 100}%` }} /></div>
                <span className="muted" style={{ width: 30, textAlign: 'right' }}>{s.count}</span>
              </div>
            ))}
          </div>
        </>
      )}

      <div className="toolbar">
        <input type="text" className="grow" placeholder={t('common.search')} value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={{ width: 'auto' }}>
          <option value="">{t('common.severity')}: {t('common.all')}</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
        <select value={iac} onChange={(e) => setIac(e.target.value)} style={{ width: 'auto' }}>
          <option value="">IaC: {t('common.all')}</option>
          <option value="ros">ROS</option>
          <option value="terraform">Terraform</option>
        </select>
      </div>

      {packs.length > 0 && (
        <table style={{ marginBottom: '1.5rem' }}>
          <thead><tr><th>Pack</th><th>Name</th><th>Rules</th></tr></thead>
          <tbody>
            {packs.map((p) => (
              <tr key={p.id} className="clickable" onClick={() => open(p.id)}>
                <td><code>{p.id.replace('pack:aliyun:', '')}</code></td>
                <td>{pick(p.name, lang)}</td>
                <td>{p.rule_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <table>
        <thead><tr><th>{t('common.rule')}</th><th>Name</th><th>{t('common.severity')}</th><th>Services</th></tr></thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id} className="clickable" onClick={() => open(r.id)}>
              <td><code>{r.id.replace('rule:aliyun:', '')}</code></td>
              <td>{pick(r.name, lang)}</td>
              <td><SeverityBadge severity={r.severity} /></td>
              <td className="muted">{(r.services || []).join(', ')}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {detail && (
        <>
          <div className="drawer-backdrop" onClick={() => setDetail(null)} />
          <div className="drawer">
            <button className="close" onClick={() => setDetail(null)}>×</button>
          {detail.kind === 'rule' && detail.rule && (
            <>
              <h2 style={{ marginTop: 0 }}>{pick(detail.rule.name, lang)}</h2>
              <div className="kv"><b>ID</b> <code>{detail.rule.id}</code></div>
              <div className="kv"><b>{t('common.severity')}</b> <SeverityBadge severity={detail.rule.severity} /></div>
              <div className="kv"><b>IaC</b> {(detail.rule.iac_types || []).join(', ')}</div>
              <div className="kv"><b>Resources</b> {(detail.rule.resource_types || []).join(', ')}</div>
              <p>{pick(detail.rule.description, lang)}</p>
              <p className="hint">{pick(detail.rule.recommendation, lang)}</p>
              {Object.entries(detail.rule.implementations || {}).map(([k, impl]) => (
                <div key={k}>
                  <label>{k}</label>
                  <pre className="code" style={{ whiteSpace: 'pre', overflow: 'auto' }}>{impl.content}</pre>
                </div>
              ))}
            </>
          )}
          {detail.kind === 'pack' && detail.pack && (
            <>
              <h2 style={{ marginTop: 0 }}>{pick(detail.pack.name, lang)}</h2>
              <div className="kv"><b>ID</b> <code>{detail.pack.id}</code></div>
              <p>{pick(detail.pack.description, lang)}</p>
              <table>
                <thead><tr><th>{t('common.rule')}</th><th>{t('common.severity')}</th></tr></thead>
                <tbody>
                  {(detail.rules || []).map((r) => (
                    <tr key={r.id}><td><code>{r.id.replace('rule:aliyun:', '')}</code></td><td><SeverityBadge severity={r.severity} /></td></tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
          </div>
        </>
      )}
    </div>
  )
}
