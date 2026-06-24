import { useEffect, useMemo, useRef, useState } from 'react'
import type { Severity, Summary, Violation } from '../api'
import { useI18n } from '../i18n'
import { highlight, type Language } from '../highlight'

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const s = (severity || '').toLowerCase()
  const cls = s === 'high' || s === 'medium' || s === 'low' ? s : 'muted'
  return <span className={`badge ${cls}`}>{s}</span>
}

// Editor is a syntax-highlighted, editable code editor (transparent textarea
// over a highlighted <pre>, fully offline).
export function Editor({
  value,
  onChange,
  placeholder,
  language = 'plain',
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  language?: Language
}) {
  const taRef = useRef<HTMLTextAreaElement>(null)
  const preRef = useRef<HTMLPreElement>(null)
  function sync() {
    if (preRef.current && taRef.current) {
      preRef.current.scrollTop = taRef.current.scrollTop
      preRef.current.scrollLeft = taRef.current.scrollLeft
    }
  }
  return (
    <div className="code-editor">
      <pre className="code code-hl" ref={preRef} aria-hidden="true">
        <code dangerouslySetInnerHTML={{ __html: highlight(value, language) + '\n' }} />
      </pre>
      <textarea
        ref={taRef}
        className="code code-input"
        spellCheck={false}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        onScroll={sync}
      />
    </div>
  )
}

// CodeBlock is a read-only highlighted code view with a copy button.
export function CodeBlock({ code, language = 'plain' }: { code: string; language?: Language }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard?.writeText(code).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <div className="codeblock">
      <button type="button" className="copy-btn secondary" onClick={copy}>
        {copied ? t('common.copied') : t('common.copy')}
      </button>
      <pre className="code">
        <code dangerouslySetInnerHTML={{ __html: highlight(code, language) }} />
      </pre>
    </div>
  )
}

interface Option<T extends string> {
  value: T
  label: string
}

// Segmented is a compact toggle for a small set of mutually exclusive options.
export function Segmented<T extends string>({
  value,
  onChange,
  options,
}: {
  value: T
  onChange: (v: T) => void
  options: Option<T>[]
}) {
  return (
    <div className="segmented" role="tablist">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="tab"
          aria-selected={value === o.value}
          className={value === o.value ? 'active' : ''}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

// Select is a custom dropdown styled consistently with the rest of the UI.
export function Select<T extends string>({
  value,
  onChange,
  options,
  width,
  searchable,
  searchPlaceholder,
}: {
  value: T
  onChange: (v: T) => void
  options: Option<T>[]
  width?: number | string
  searchable?: boolean
  searchPlaceholder?: string
}) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])
  const current = options.find((o) => o.value === value)
  const shown = useMemo(() => {
    if (!searchable || !query) return options
    const q = query.toLowerCase()
    return options.filter((o) => o.value.toLowerCase().includes(q) || o.label.toLowerCase().includes(q))
  }, [options, query, searchable])
  return (
    <div className="select" ref={ref} style={{ width }}>
      <button type="button" className="select-trigger" onClick={() => setOpen((v) => !v)}>
        <span>{current?.label ?? value}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>
      {open && (
        <div className="select-menu ms-menu" role="listbox">
          {searchable && (
            <input
              className="ms-search"
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={searchPlaceholder}
            />
          )}
          {shown.map((o) => (
            <button
              key={o.value}
              type="button"
              role="option"
              aria-selected={o.value === value}
              className={o.value === value ? 'active' : ''}
              onClick={() => {
                onChange(o.value)
                setOpen(false)
                setQuery('')
              }}
            >
              {o.label}
            </button>
          ))}
          {shown.length === 0 && <div className="ms-empty muted">—</div>}
        </div>
      )}
    </div>
  )
}

// FileButton is a styled trigger for choosing a local file (returns its text).
export function FileButton({ label, accept, onText }: { label: string; accept?: string; onText: (text: string) => void }) {
  const ref = useRef<HTMLInputElement>(null)
  return (
    <>
      <button type="button" className="secondary" onClick={() => ref.current?.click()}>
        {label}
      </button>
      <input
        ref={ref}
        type="file"
        accept={accept}
        style={{ display: 'none' }}
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f) f.text().then(onText)
          e.target.value = ''
        }}
      />
    </>
  )
}

const IAC_LABEL: Record<string, string> = { ros: 'ROS', terraform: 'Terraform' }

// ImplTabs renders a rule's per-IaC implementations as tabs (or a single label).
export function ImplTabs({ impls }: { impls: Record<string, { content: string }> }) {
  const keys = Object.keys(impls)
  const [tab, setTab] = useState(keys[0] || '')
  useEffect(() => {
    if (!keys.includes(tab)) setTab(keys[0] || '')
  }, [impls]) // eslint-disable-line react-hooks/exhaustive-deps
  if (keys.length === 0) return null
  return (
    <div style={{ marginTop: '.6rem' }}>
      {keys.length > 1 ? (
        <div style={{ marginBottom: '.5rem' }}>
          <Segmented value={tab} onChange={setTab} options={keys.map((k) => ({ value: k, label: IAC_LABEL[k] || k }))} />
        </div>
      ) : (
        <label>{IAC_LABEL[keys[0]] || keys[0]}</label>
      )}
      <CodeBlock code={impls[tab]?.content || ''} language="rego" />
    </div>
  )
}

// MultiSelect is a searchable, multi-value dropdown with an "All" option
// (empty selection means all).
export function MultiSelect({
  options,
  selected,
  onChange,
  allLabel,
  searchPlaceholder,
  width,
}: {
  options: { value: string; label: string; sub?: string; group?: string }[]
  selected: string[]
  onChange: (v: string[]) => void
  allLabel: string
  searchPlaceholder?: string
  width?: number | string
}) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])

  const filtered = useMemo(() => {
    const q = query.toLowerCase()
    return q
      ? options.filter(
          (o) =>
            o.value.toLowerCase().includes(q) ||
            o.label.toLowerCase().includes(q) ||
            (o.sub || '').toLowerCase().includes(q),
        )
      : options
  }, [options, query])

  const sel = new Set(selected)
  function toggle(v: string) {
    const next = new Set(sel)
    next.has(v) ? next.delete(v) : next.add(v)
    onChange([...next])
  }

  const triggerText = selected.length === 0 ? allLabel : `${selected.length} ${t('common.selected')}`

  return (
    <div className="select" ref={ref} style={{ width }}>
      <button type="button" className="select-trigger" onClick={() => setOpen((v) => !v)}>
        <span className={selected.length === 0 ? 'muted' : undefined}>{triggerText}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>
      {open && (
        <div className="select-menu ms-menu">
          <input
            className="ms-search"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={searchPlaceholder}
          />
          <button type="button" className={selected.length === 0 ? 'active' : ''} onClick={() => onChange([])}>
            {allLabel}
          </button>
          {filtered.map((o) => (
            <button
              key={o.value}
              type="button"
              className={sel.has(o.value) ? 'active' : ''}
              onClick={() => toggle(o.value)}
            >
              <span className="ms-check">{sel.has(o.value) ? '✓' : ''}</span>
              <span className="ms-opt">
                <span className="ms-opt-label">{o.label}</span>
                {o.sub && <span className="ms-opt-sub">{o.sub}</span>}
              </span>
            </button>
          ))}
          {filtered.length === 0 && <div className="ms-empty muted">—</div>}
        </div>
      )}
    </div>
  )
}

// SummaryLine shows severity counts as clickable filter chips. The total acts as
// an "All" reset. filter is the active severity ('' = all).
export function SummaryLine({
  summary,
  filter,
  onFilter,
}: {
  summary: Summary
  filter?: string
  onFilter?: (s: string) => void
}) {
  const { t } = useI18n()
  const c = summary.severity_counts || {}
  const clickable = !!onFilter
  const chip = (sev: string, count: number) => (
    <button
      type="button"
      className={`sevchip ${filter === sev ? 'active' : ''}`}
      disabled={!clickable}
      onClick={() => onFilter?.(filter === sev ? '' : sev)}
    >
      <SeverityBadge severity={sev} /> {count}
    </button>
  )
  return (
    <div className="summary-line">
      <button
        type="button"
        className={`sevchip ${!filter ? 'active' : ''}`}
        disabled={!clickable}
        onClick={() => onFilter?.('')}
      >
        <span className="badge muted">{t('common.all')}</span> {summary.total_violations}
      </button>
      {chip('high', c.high || 0)}
      {chip('medium', c.medium || 0)}
      {chip('low', c.low || 0)}
    </div>
  )
}

export function ViolationCard({ v }: { v: Violation }) {
  return (
    <div className="violation">
      <div className="v-head">
        <SeverityBadge severity={v.severity} />
        <span className="v-title">{v.reason || v.id}</span>
      </div>
      <div className="v-meta">
        <code>{v.id}</code>
        <span className="v-dot">·</span>
        <span>{v.resource_id}</span>
        <span className="v-dot">·</span>
        <span>{v.file}:{v.line}</span>
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
      {v.recommendation && <div className="v-rec">{v.recommendation}</div>}
    </div>
  )
}
