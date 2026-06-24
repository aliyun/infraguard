import { useEffect, useMemo, useRef, useState } from 'react'
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
}: {
  value: T
  onChange: (v: T) => void
  options: Option<T>[]
  width?: number | string
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])
  const current = options.find((o) => o.value === value)
  return (
    <div className="select" ref={ref} style={{ width }}>
      <button type="button" className="select-trigger" onClick={() => setOpen((v) => !v)}>
        <span>{current?.label ?? value}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>
      {open && (
        <div className="select-menu" role="listbox">
          {options.map((o) => (
            <button
              key={o.value}
              type="button"
              role="option"
              aria-selected={o.value === value}
              className={o.value === value ? 'active' : ''}
              onClick={() => {
                onChange(o.value)
                setOpen(false)
              }}
            >
              {o.label}
            </button>
          ))}
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
  options: { value: string; label: string; group?: string }[]
  selected: string[]
  onChange: (v: string[]) => void
  allLabel: string
  searchPlaceholder?: string
  width?: number | string
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

  const filtered = useMemo(() => {
    const q = query.toLowerCase()
    return q ? options.filter((o) => o.value.toLowerCase().includes(q) || o.label.toLowerCase().includes(q)) : options
  }, [options, query])

  const sel = new Set(selected)
  function toggle(v: string) {
    const next = new Set(sel)
    next.has(v) ? next.delete(v) : next.add(v)
    onChange([...next])
  }

  const triggerText = selected.length === 0 ? allLabel : `${selected.length} selected`

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
              {o.label}
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
        className={`sevchip total ${!filter ? 'active' : ''}`}
        disabled={!clickable}
        onClick={() => onFilter?.('')}
      >
        <strong>{summary.total_violations}</strong> {t('common.all')}
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
