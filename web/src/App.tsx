import { Link, NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { useI18n, LANGS, type Lang } from './i18n'
import { api } from './api'
import { Select } from './components/ui'
import Playground from './pages/Playground'
import Catalog from './pages/Catalog'
import Studio from './pages/Studio'

const navItems = [
  { to: '/playground', key: 'nav.playground' },
  { to: '/catalog', key: 'nav.catalog' },
  { to: '/studio', key: 'nav.studio' },
]

export default function App() {
  const { t, lang, setLang } = useI18n()
  const [version, setVersion] = useState('')
  const [theme, setTheme] = useState<string>(() => localStorage.getItem('ig_theme') || '')

  useEffect(() => {
    api.meta().then((m) => setVersion(m.version)).catch(() => {})
  }, [])

  useEffect(() => {
    if (theme) document.documentElement.dataset.theme = theme
    else delete document.documentElement.dataset.theme
  }, [theme])

  const isDark =
    theme === 'dark' ||
    (!theme && typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches)

  function toggleTheme() {
    const next = isDark ? 'light' : 'dark'
    localStorage.setItem('ig_theme', next)
    setTheme(next)
  }

  return (
    <div className="app">
      <header className="topbar">
        <Link to="/playground" className="brand">
          <img className="brand-logo" src="logo.svg" alt="" width={26} height={26} />
          <span className="brand-name">InfraGuard</span>
        </Link>
        <div className="topbar-actions">
          <Select
            value={lang}
            onChange={(v) => setLang(v as Lang)}
            options={LANGS}
            width={120}
            searchable
          />
          <button className="icon-btn" onClick={toggleTheme} title="Toggle theme" aria-label="Toggle theme">
            {isDark ? '☀' : '☾'}
          </button>
          {version && <span className="version">v{version}</span>}
        </div>
      </header>
      <div className="body">
        <aside className="sidebar">
          <nav>
            {navItems.map((n) => (
              <NavLink key={n.to} to={n.to} className={({ isActive }) => (isActive ? 'active' : '')}>
                {t(n.key)}
              </NavLink>
            ))}
          </nav>
        </aside>
        <main className="content">
          <Routes>
            <Route path="/" element={<Navigate to="/playground" replace />} />
            <Route path="/playground" element={<Playground />} />
            <Route path="/catalog" element={<Catalog />} />
            <Route path="/studio" element={<Studio />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}
