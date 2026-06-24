import { useState } from 'react'
import { api, type ScanResult } from '../api'
import { useI18n } from '../i18n'
import { Editor, SummaryLine, ViolationCard } from '../components/ui'

const SAMPLE = `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyBucket:
    Type: ALIYUN::OSS::Bucket
    Properties:
      AccessControl: public-read
`

export default function Playground() {
  const { t, lang } = useI18n()
  const [content, setContent] = useState(SAMPLE)
  const [iac, setIac] = useState('ros')
  const [policies, setPolicies] = useState('')
  const [showWaived, setShowWaived] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function scan() {
    setLoading(true)
    setError('')
    try {
      const policyList = policies.split(',').map((s) => s.trim()).filter(Boolean)
      const res = await api.scan({ content, iac, policies: policyList, lang })
      setResult(res)
    } catch (e) {
      setError((e as Error).message)
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  const visible = result?.violations.filter((v) => showWaived || v.waiver?.status !== 'active') ?? []

  return (
    <div>
      <h1 className="page-title">{t('nav.playground')}</h1>
      <div className="row">
        <div className="col">
          <div className="toolbar">
            <select value={iac} onChange={(e) => setIac(e.target.value)} style={{ width: 'auto' }}>
              <option value="ros">ROS</option>
              <option value="terraform">Terraform</option>
            </select>
            <button onClick={scan} disabled={loading}>
              {loading ? t('common.loading') : t('common.scan')}
            </button>
          </div>
          <Editor value={content} onChange={setContent} />
          <div style={{ marginTop: '.6rem' }}>
            <label>{t('scan.policies')}</label>
            <input
              type="text"
              value={policies}
              onChange={(e) => setPolicies(e.target.value)}
              placeholder="oss-bucket-public-read-prohibited, pack:aliyun:..."
            />
          </div>
        </div>
        <div className="col">
          {error && <div className="error">{error}</div>}
          {result && (
            <>
              <SummaryLine summary={result.summary} />
              <label className="checkbox" style={{ marginBottom: '.6rem' }}>
                <input type="checkbox" checked={showWaived} onChange={(e) => setShowWaived(e.target.checked)} />
                {t('scan.showWaived')}
              </label>
              {visible.length === 0 ? (
                <div className="muted">{t('common.noViolations')}</div>
              ) : (
                visible.map((v, i) => <ViolationCard key={i} v={v} />)
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
