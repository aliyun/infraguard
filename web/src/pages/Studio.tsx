import { useState } from 'react'
import { api, type Violation } from '../api'
import { useI18n } from '../i18n'
import { Editor, ViolationCard } from '../components/ui'

const SAMPLE_REGO = `package infraguard.rules.aliyun.my_rule

import rego.v1
import data.infraguard.helpers

rule_meta := {
\t"id": "my-rule",
\t"severity": "medium",
\t"name": {"en": "My rule", "zh": "我的规则"},
\t"reason": {"en": "Bucket must be tagged", "zh": "桶必须打标签"},
\t"recommendation": {"en": "Add tags", "zh": "添加标签"},
\t"resource_types": ["ALIYUN::OSS::Bucket"]
}

deny contains result if {
\tsome name, resource in helpers.resources_by_types(rule_meta.resource_types)
\tnot helpers.has_tags(resource)
\tresult := {
\t\t"id": rule_meta.id,
\t\t"resource_id": name,
\t\t"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
\t}
}
`

const SAMPLE_TEMPLATE = `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  B:
    Type: ALIYUN::OSS::Bucket
    Properties: {}
`

const SAMPLE_COMPLIANT = `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  B:
    Type: ALIYUN::OSS::Bucket
    Properties:
      Tags:
        - Key: owner
          Value: team
`

export default function Studio() {
  const { t, lang } = useI18n()
  const [rego, setRego] = useState(SAMPLE_REGO)
  const [iac, setIac] = useState('ros')
  const [mode, setMode] = useState<'eval' | 'test'>('eval')
  const [template, setTemplate] = useState(SAMPLE_TEMPLATE)
  const [compliant, setCompliant] = useState(SAMPLE_COMPLIANT)
  const [violation, setViolation] = useState(SAMPLE_TEMPLATE)
  const [evalRes, setEvalRes] = useState<Violation[] | null>(null)
  const [testRes, setTestRes] = useState<Awaited<ReturnType<typeof api.ruleTest>> | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function run() {
    setLoading(true)
    setError('')
    setEvalRes(null)
    setTestRes(null)
    try {
      if (mode === 'eval') {
        const r = await api.ruleEval({ rego, content: template, iac, lang })
        setEvalRes(r.violations)
      } else {
        const r = await api.ruleTest({ rego, iac, compliant, violation })
        setTestRes(r)
      }
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  function caseBadge(c?: { pass: boolean; violations: number; error?: string }) {
    if (!c) return null
    return (
      <span className={`badge ${c.pass ? 'ok' : 'high'}`}>
        {c.pass ? t('studio.pass') : t('studio.fail')} ({c.violations}){c.error ? ' ' + c.error : ''}
      </span>
    )
  }

  return (
    <div>
      <h1 className="page-title">{t('nav.studio')}</h1>
      <p className="page-sub">{t('sub.studio')}</p>
      <div className="row">
        <div className="col">
          <div className="toolbar">
            <label style={{ margin: 0 }}>{t('studio.rego')}</label>
            <span className="grow" />
            <select value={iac} onChange={(e) => setIac(e.target.value)} style={{ width: 'auto' }}>
              <option value="ros">ROS</option>
              <option value="terraform">Terraform</option>
            </select>
          </div>
          <Editor value={rego} onChange={setRego} />
        </div>
        <div className="col">
          <div className="toolbar">
            <select value={mode} onChange={(e) => setMode(e.target.value as 'eval' | 'test')} style={{ width: 'auto' }}>
              <option value="eval">{t('common.run')} · {t('studio.template')}</option>
              <option value="test">{t('common.test')} · fixtures</option>
            </select>
            <button onClick={run} disabled={loading}>
              {loading ? t('common.loading') : mode === 'eval' ? t('common.run') : t('common.test')}
            </button>
          </div>

          {mode === 'eval' ? (
            <>
              <label>{t('studio.template')}</label>
              <Editor value={template} onChange={setTemplate} />
            </>
          ) : (
            <>
              <label>{t('studio.compliant')}</label>
              <Editor value={compliant} onChange={setCompliant} />
              <label style={{ marginTop: '.6rem' }}>{t('studio.violation')}</label>
              <Editor value={violation} onChange={setViolation} />
            </>
          )}

          {error && <div className="error">{error}</div>}

          {evalRes && (
            <div style={{ marginTop: '.75rem' }}>
              {evalRes.length === 0 ? <div className="muted">{t('common.noViolations')}</div> : evalRes.map((v, i) => <ViolationCard key={i} v={v} />)}
            </div>
          )}

          {testRes && (
            <div className="panel" style={{ marginTop: '.75rem' }}>
              <div className="kv"><b>{t('studio.compliant')}</b> {caseBadge(testRes.compliant)}</div>
              <div className="kv"><b>{t('studio.violation')}</b> {caseBadge(testRes.violation)}</div>
              <div className="kv"><b>Result</b> <span className={`badge ${testRes.pass ? 'ok' : 'high'}`}>{testRes.pass ? t('studio.pass') : t('studio.fail')}</span></div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
