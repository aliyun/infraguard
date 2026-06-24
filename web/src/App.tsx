import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { useI18n } from './i18n'
import { api } from './api'
import Playground from './pages/Playground'
import Report from './pages/Report'
import Catalog from './pages/Catalog'
import Studio from './pages/Studio'
import Waivers from './pages/Waivers'

const navItems = [
  { to: '/playground', key: 'nav.playground' },
  { to: '/report', key: 'nav.report' },
  { to: '/catalog', key: 'nav.catalog' },
  { to: '/studio', key: 'nav.studio' },
  { to: '/waivers', key: 'nav.waivers' },
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

  function toggleTheme() {
    const isDark = theme === 'dark' || (!theme && window.matchMedia('(prefers-color-scheme: dark)').matches)
    const next = isDark ? 'light' : 'dark'
    localStorage.setItem('ig_theme', next)
    setTheme(next)
  }

  const isDark = theme === 'dark' || (!theme && typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches)

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">IG</span>
          <span className="brand-name">InfraGuard</span>
        </div>
        <nav>
          {navItems.map((n) => (
            <NavLink key={n.to} to={n.to} className={({ isActive }) => (isActive ? 'active' : '')}>
              {t(n.key)}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <select value={lang} onChange={(e) => setLang(e.target.value as 'en' | 'zh')}>
            <option value="en">English</option>
            <option value="zh">中文</option>
          </select>
          <button className="icon-btn" onClick={toggleTheme} title="Toggle theme" aria-label="Toggle theme">
            {isDark ? '☀' : '☾'}
          </button>
        </div>
        {version && (
          <div className="version" style={{ padding: '.4rem .5rem 0' }}>
            v{version}
          </div>
        )}
      </aside>
      <main className="content">
        <Routes>
          <Route path="/" element={<Navigate to="/playground" replace />} />
          <Route path="/playground" element={<Playground />} />
          <Route path="/report" element={<Report />} />
          <Route path="/catalog" element={<Catalog />} />
          <Route path="/studio" element={<Studio />} />
          <Route path="/waivers" element={<Waivers />} />
        </Routes>
      </main>
    </div>
  )
}
