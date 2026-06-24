import { useEffect, useState } from 'react'
import { api, type Coverage, type PackSummary, type RuleDetail, type RuleSummary } from '../api'
import { pick, useI18n } from '../i18n'
import { ImplTabs, Segmented, Select, SeverityBadge } from '../components/ui'

type Tab = 'overview' | 'packs' | 'rules'
type Detail = { kind: string; rule?: RuleDetail; pack?: PackSummary; rules?: RuleSummary[] }

export default function Catalog() {
  const { t, lang } = useI18n()
  const [tab, setTab] = useState<Tab>('overview')
  const [coverage, setCoverage] = useState<Coverage | null>(null)
  const [rules, setRules] = useState<RuleSummary[]>([])
  const [packs, setPacks] = useState<PackSummary[]>([])
  const [q, setQ] = useState('')
  const [severity, setSeverity] = useState('')
  const [iac, setIac] = useState('')
  const [service, setService] = useState('')
  const [resourceType, setResourceType] = useState('')
  const [detail, setDetail] = useState<Detail | null>(null)
  const [back, setBack] = useState<Detail | null>(null)

  useEffect(() => {
    api.coverage().then(setCoverage).catch(() => {})
  }, [])

  useEffect(() => {
    const params: Record<string, string> = {}
    if (q) params.q = q
    if (severity) params.severity = severity
    if (iac) params.iac = iac
    if (service) params.service = service
    if (resourceType) params.resource_type = resourceType
    const h = setTimeout(() => {
      api.policies(params).then((d) => {
        setRules(d.rules)
        setPacks(d.packs)
      }).catch(() => {})
    }, 200)
    return () => clearTimeout(h)
  }, [q, severity, iac, service, resourceType])

  function open(id: string) {
    setBack(null)
    api.policyDetail(id).then(setDetail).catch(() => {})
  }

  // drill opens a rule from within a pack, remembering the pack for "back".
  function drill(id: string) {
    setBack(detail)
    api.policyDetail(id).then(setDetail).catch(() => {})
  }

  function closeDrawer() {
    setDetail(null)
    setBack(null)
  }

  function goBack() {
    setDetail(back)
    setBack(null)
  }

  const maxService = coverage?.by_service[0]?.count || 1

  const productSelect = (
    <Select
      value={service}
      onChange={setService}
      searchable
      searchPlaceholder={t('common.search')}
      options={[
        { value: '', label: `${t('filter.product')}: ${t('common.all')}` },
        ...(coverage?.by_service || []).map((s) => ({ value: s.key, label: s.key })),
      ]}
    />
  )
  const resTypeSelect = (
    <Select
      value={resourceType}
      onChange={setResourceType}
      searchable
      searchPlaceholder={t('common.search')}
      options={[
        { value: '', label: `${t('filter.resourceType')}: ${t('common.all')}` },
        ...(coverage?.resource_types || []).map((rt) => ({ value: rt, label: rt })),
      ]}
    />
  )

  return (
    <div>
      <h1 className="page-title">{t('nav.catalog')}</h1>
      <p className="page-sub">{t('sub.catalog')}</p>

      <div style={{ marginBottom: '1.25rem' }}>
        <Segmented
          value={tab}
          onChange={(v) => setTab(v as Tab)}
          options={[
            { value: 'overview', label: t('tab.overview') },
            { value: 'packs', label: t('tab.packs') },
            { value: 'rules', label: t('tab.rules') },
          ]}
        />
      </div>

      {tab === 'overview' && coverage && (
        <>
          <div className="stat-grid">
            <div className="stat clickable-stat" onClick={() => setTab('rules')}><div className="num">{coverage.total_rules}</div><div className="lbl">{t('tab.rules')}</div></div>
            <div className="stat clickable-stat" onClick={() => setTab('packs')}><div className="num">{coverage.total_packs}</div><div className="lbl">{t('tab.packs')}</div></div>
            <div className="stat"><div className="num" style={{ color: 'var(--high)' }}>{coverage.by_severity.high}</div><div className="lbl">HIGH</div></div>
            <div className="stat"><div className="num" style={{ color: 'var(--medium)' }}>{coverage.by_severity.medium}</div><div className="lbl">MEDIUM</div></div>
            <div className="stat"><div className="num" style={{ color: 'var(--low)' }}>{coverage.by_severity.low}</div><div className="lbl">LOW</div></div>
            <div className="stat"><div className="num">{coverage.by_iac.both}</div><div className="lbl">ROS+Terraform</div></div>
          </div>
          <div className="panel">
            <label>{t('catalog.coverage')}</label>
            {coverage.by_service.slice(0, 14).map((s) => (
              <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: '.6rem', marginBottom: '.35rem' }}>
                <span style={{ width: 120, fontSize: '.82rem' }}>{s.key}</span>
                <div className="bar" style={{ flex: 1 }}><span style={{ width: `${(s.count / maxService) * 100}%` }} /></div>
                <span className="muted" style={{ width: 30, textAlign: 'right' }}>{s.count}</span>
              </div>
            ))}
          </div>
        </>
      )}

      {tab === 'packs' && (
        <>
          <div className="toolbar">
            <input type="text" className="grow" placeholder={t('common.search')} value={q} onChange={(e) => setQ(e.target.value)} />
            {productSelect}
            {resTypeSelect}
          </div>
          <table>
            <thead><tr><th>{t('tab.packs')}</th><th>Name</th><th>{t('tab.rules')}</th></tr></thead>
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
        </>
      )}

      {tab === 'rules' && (
        <>
          <div className="toolbar">
            <input type="text" className="grow" placeholder={t('common.search')} value={q} onChange={(e) => setQ(e.target.value)} />
            {productSelect}
            {resTypeSelect}
            <Select
              value={severity}
              onChange={setSeverity}
              options={[
                { value: '', label: `${t('common.severity')}: ${t('common.all')}` },
                { value: 'high', label: 'HIGH' },
                { value: 'medium', label: 'MEDIUM' },
                { value: 'low', label: 'LOW' },
              ]}
            />
            <Select
              value={iac}
              onChange={setIac}
              options={[
                { value: '', label: `IaC: ${t('common.all')}` },
                { value: 'ros', label: 'ROS' },
                { value: 'terraform', label: 'Terraform' },
              ]}
            />
          </div>
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
        </>
      )}

      {detail && (
        <>
          <div className="drawer-backdrop" onClick={closeDrawer} />
          <div className="drawer">
            <button className="close" onClick={closeDrawer}>×</button>
            {back && (
              <button className="secondary drawer-back" onClick={goBack}>← {t('common.back')}</button>
            )}
            {detail.kind === 'rule' && detail.rule && (
              <>
                <h2 style={{ marginTop: 0 }}>{pick(detail.rule.name, lang)}</h2>
                <div className="kv"><b>ID</b> <code>{detail.rule.id}</code></div>
                <div className="kv"><b>{t('common.severity')}</b> <SeverityBadge severity={detail.rule.severity} /></div>
                <div className="kv"><b>IaC</b> {(detail.rule.iac_types || []).join(', ')}</div>
                <div className="kv"><b>{t('detail.resources')}</b></div>
                <div className="kv-vals">
                  {(detail.rule.resource_types || []).map((rt) => (
                    <div key={rt}><code>{rt}</code></div>
                  ))}
                </div>
                <p>{pick(detail.rule.description, lang)}</p>
                <p className="hint">{pick(detail.rule.recommendation, lang)}</p>
                <ImplTabs impls={detail.rule.implementations || {}} />
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
                      <tr key={r.id} className="clickable" onClick={() => drill(r.id)}>
                        <td><code>{r.id.replace('rule:aliyun:', '')}</code></td>
                        <td><SeverityBadge severity={r.severity} /></td>
                      </tr>
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
