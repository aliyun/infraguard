import { useEffect, useMemo, useState } from 'react'
import { api, type ScanResult } from '../api'
import { pick, useI18n } from '../i18n'
import { Editor, MultiSelect, Segmented, SummaryLine, ViolationCard } from '../components/ui'

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

function shortId(id: string): string {
  return id.includes(':') ? id.split(':').pop() || id : id
}

export default function Playground() {
  const { t, lang } = useI18n()
  const [iac, setIac] = useState('ros')
  const [content, setContent] = useState(SAMPLES.ros)
  const [selected, setSelected] = useState<string[]>([])
  const [options, setOptions] = useState<{ value: string; label: string }[]>([])
  const [result, setResult] = useState<ScanResult | null>(null)
  const [filter, setFilter] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    api
      .policies({})
      .then((d) => {
        const packs = d.packs.map((p) => ({ value: p.id, label: `📦 ${pick(p.name, lang) || p.id}` }))
        const rules = d.rules.map((r) => ({ value: shortId(r.id), label: shortId(r.id) }))
        setOptions([...packs, ...rules])
      })
      .catch(() => {})
  }, [lang])

  function changeIac(v: string) {
    setIac(v)
    setContent(SAMPLES[v] ?? '')
    setResult(null)
  }

  async function scan() {
    setLoading(true)
    setError('')
    setFilter('')
    try {
      const res = await api.scan({ content, iac, policies: selected, lang })
      setResult(res)
    } catch (e) {
      setError((e as Error).message)
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  const sorted = useMemo(() => {
    const list = [...(result?.violations ?? [])]
    list.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
    return list
  }, [result])
  const visible = filter ? sorted.filter((v) => v.severity === filter) : sorted

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
            <MultiSelect
              options={options}
              selected={selected}
              onChange={setSelected}
              allLabel={t('scan.allPolicies')}
              searchPlaceholder={t('common.search')}
              width="100%"
            />
          </div>
        </div>
        <div className="col">
          {error && <div className="error">{error}</div>}
          {result && (
            <>
              <SummaryLine summary={result.summary} filter={filter} onFilter={setFilter} />
              <div style={{ marginTop: '.85rem' }}>
                {visible.length === 0 ? (
                  <div className="muted">{t('common.noViolations')}</div>
                ) : (
                  visible.map((v, i) => <ViolationCard key={i} v={v} />)
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
