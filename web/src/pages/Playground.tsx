import { useState } from 'react'
import { api, type ScanResult } from '../api'
import { useI18n } from '../i18n'
import { Editor, Segmented, SummaryLine, ViolationCard } from '../components/ui'

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

export default function Playground() {
  const { t, lang } = useI18n()
  const [iac, setIac] = useState('ros')
  const [content, setContent] = useState(SAMPLES.ros)
  const [policies, setPolicies] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  function changeIac(v: string) {
    setIac(v)
    setContent(SAMPLES[v] ?? '')
    setResult(null)
  }

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

  return (
    <div>
      <h1 className="page-title">{t('nav.playground')}</h1>
      <p className="page-sub">{t('sub.playground')}</p>
      <div className="row">
        <div className="col">
          <div className="toolbar">
            <Segmented
              value={iac}
              onChange={changeIac}
              options={[
                { value: 'ros', label: 'ROS' },
                { value: 'terraform', label: 'Terraform' },
              ]}
            />
            <span className="grow" />
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
              <div style={{ marginTop: '.75rem' }}>
                {result.violations.length === 0 ? (
                  <div className="muted">{t('common.noViolations')}</div>
                ) : (
                  result.violations.map((v, i) => <ViolationCard key={i} v={v} />)
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
