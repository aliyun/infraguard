import { useEffect, useState } from 'react'
import { api, type Waiver, type WaiverIssue } from '../api'
import { useI18n } from '../i18n'

export default function Waivers() {
  const { t } = useI18n()
  const [path, setPath] = useState('')
  const [waivers, setWaivers] = useState<Waiver[]>([])
  const [issues, setIssues] = useState<WaiverIssue[]>([])
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    api.waivers().then((d) => {
      setPath(d.path)
      setWaivers(d.waivers)
      setIssues(d.issues)
    }).catch((e) => setError((e as Error).message))
  }, [])

  function update(i: number, patch: Partial<Waiver>) {
    setWaivers((ws) => ws.map((w, idx) => (idx === i ? { ...w, ...patch } : w)))
    setSaved(false)
  }
  function remove(i: number) {
    setWaivers((ws) => ws.filter((_, idx) => idx !== i))
    setSaved(false)
  }
  function add() {
    setWaivers((ws) => [...ws, { rule: '', resource: '', reason: '', expires: '', owner: '' }])
    setSaved(false)
  }

  async function save() {
    setError('')
    try {
      const cleaned = waivers.map((w) => ({
        rule: w.rule,
        resource: w.resource || undefined,
        reason: w.reason,
        expires: w.expires || undefined,
        owner: w.owner || undefined,
      }))
      const d = await api.saveWaivers(cleaned)
      setIssues(d.issues)
      setPath(d.path)
      setSaved(true)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  function issuesFor(i: number) {
    return issues.filter((iss) => iss.index === i)
  }

  return (
    <div>
      <h1 className="page-title">{t('nav.waivers')}</h1>
      <p className="page-sub">{t('sub.waivers')}</p>
      <div className="toolbar">
        <code className="grow muted">{path}</code>
        <button className="secondary" onClick={add}>＋ {t('waivers.add')}</button>
        <button onClick={save}>{t('common.save')}</button>
      </div>
      {error && <div className="error">{error}</div>}
      {saved && <div className="hint" style={{ color: 'var(--ok)' }}>✓ saved</div>}

      {waivers.length === 0 ? (
        <div className="muted">{t('waivers.none')}</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t('common.rule')}</th>
              <th>{t('common.resource')}</th>
              <th>{t('waivers.reason')}</th>
              <th>{t('waivers.expires')}</th>
              <th>{t('waivers.owner')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {waivers.map((w, i) => {
              const errs = issuesFor(i)
              return (
                <tr key={i}>
                  <td><input type="text" value={w.rule} onChange={(e) => update(i, { rule: e.target.value })} /></td>
                  <td><input type="text" value={w.resource || ''} onChange={(e) => update(i, { resource: e.target.value })} placeholder="*" /></td>
                  <td>
                    <input type="text" value={w.reason} onChange={(e) => update(i, { reason: e.target.value })} />
                    {errs.map((iss, k) => (
                      <div key={k} className="hint" style={{ color: iss.severity === 'error' ? 'var(--high)' : 'var(--medium)' }}>
                        {iss.code}{iss.detail ? `: ${iss.detail}` : ''}
                      </div>
                    ))}
                  </td>
                  <td><input type="text" value={w.expires || ''} onChange={(e) => update(i, { expires: e.target.value })} placeholder="YYYY-MM-DD" /></td>
                  <td><input type="text" value={w.owner || ''} onChange={(e) => update(i, { owner: e.target.value })} /></td>
                  <td><button className="secondary" onClick={() => remove(i)}>×</button></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}
