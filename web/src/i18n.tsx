import { createContext, useContext, useState, type ReactNode } from 'react'

export type Lang = 'en' | 'zh' | 'es' | 'fr' | 'de' | 'ja' | 'pt'

export const LANGS: { value: Lang; label: string }[] = [
  { value: 'en', label: 'English' },
  { value: 'zh', label: '中文' },
  { value: 'es', label: 'Español' },
  { value: 'fr', label: 'Français' },
  { value: 'de', label: 'Deutsch' },
  { value: 'ja', label: '日本語' },
  { value: 'pt', label: 'Português' },
]

const dict: Record<string, Record<Lang, string>> = {
  'nav.playground': { en: 'Playground', zh: '扫描', es: 'Escaneo', fr: 'Analyse', de: 'Scan', ja: 'スキャン', pt: 'Verificação' },
  'nav.catalog': { en: 'Policies', zh: '策略', es: 'Políticas', fr: 'Politiques', de: 'Richtlinien', ja: 'ポリシー', pt: 'Políticas' },
  'nav.studio': { en: 'Rule Studio', zh: '规则工作台', es: 'Estudio de reglas', fr: 'Studio de règles', de: 'Regel-Studio', ja: 'ルールスタジオ', pt: 'Estúdio de regras' },
  'sub.playground': {
    en: 'Scan a template against compliance rules in real time.',
    zh: '对模板实时执行合规规则扫描。',
    es: 'Analiza una plantilla con reglas de cumplimiento en tiempo real.',
    fr: 'Analysez un modèle selon les règles de conformité en temps réel.',
    de: 'Prüfen Sie eine Vorlage in Echtzeit gegen Compliance-Regeln.',
    ja: 'テンプレートをコンプライアンスルールに対してリアルタイムでスキャンします。',
    pt: 'Verifique um modelo com regras de conformidade em tempo real.',
  },
  'sub.catalog': {
    en: 'Browse built-in rules and packs, and coverage.',
    zh: '浏览内置规则、合规包与覆盖情况。',
    es: 'Explora las reglas y paquetes integrados, y la cobertura.',
    fr: 'Parcourez les règles et packs intégrés, ainsi que la couverture.',
    de: 'Durchsuchen Sie integrierte Regeln, Pakete und die Abdeckung.',
    ja: '組み込みのルールとパック、カバレッジを閲覧します。',
    pt: 'Explore as regras e pacotes integrados e a cobertura.',
  },
  'sub.studio': {
    en: 'Write a Rego rule and evaluate or test it instantly.',
    zh: '编写 Rego 规则并即时评估或测试。',
    es: 'Escribe una regla Rego y evalúala o pruébala al instante.',
    fr: 'Écrivez une règle Rego et évaluez-la ou testez-la instantanément.',
    de: 'Schreiben Sie eine Rego-Regel und werten Sie sie sofort aus oder testen Sie sie.',
    ja: 'Rego ルールを記述し、即座に評価またはテストします。',
    pt: 'Escreva uma regra Rego e avalie ou teste-a instantaneamente.',
  },
  'common.scan': { en: 'Scan', zh: '扫描', es: 'Analizar', fr: 'Analyser', de: 'Scannen', ja: 'スキャン', pt: 'Verificar' },
  'common.run': { en: 'Run', zh: '运行', es: 'Ejecutar', fr: 'Exécuter', de: 'Ausführen', ja: '実行', pt: 'Executar' },
  'common.test': { en: 'Test', zh: '测试', es: 'Probar', fr: 'Tester', de: 'Testen', ja: 'テスト', pt: 'Testar' },
  'common.loading': { en: 'Loading…', zh: '加载中…', es: 'Cargando…', fr: 'Chargement…', de: 'Laden…', ja: '読み込み中…', pt: 'Carregando…' },
  'common.search': { en: 'Search', zh: '搜索', es: 'Buscar', fr: 'Rechercher', de: 'Suchen', ja: '検索', pt: 'Pesquisar' },
  'common.severity': { en: 'Severity', zh: '严重级别', es: 'Gravedad', fr: 'Gravité', de: 'Schweregrad', ja: '重大度', pt: 'Gravidade' },
  'common.resource': { en: 'Resource', zh: '资源', es: 'Recurso', fr: 'Ressource', de: 'Ressource', ja: 'リソース', pt: 'Recurso' },
  'common.rule': { en: 'Rule', zh: '规则', es: 'Regla', fr: 'Règle', de: 'Regel', ja: 'ルール', pt: 'Regra' },
  'common.name': { en: 'Name', zh: '名称', es: 'Nombre', fr: 'Nom', de: 'Name', ja: '名前', pt: 'Nome' },
  'common.result': { en: 'Result', zh: '结果', es: 'Resultado', fr: 'Résultat', de: 'Ergebnis', ja: '結果', pt: 'Resultado' },
  'common.all': { en: 'All', zh: '全部', es: 'Todas', fr: 'Tout', de: 'Alle', ja: 'すべて', pt: 'Todas' },
  'common.chooseFile': { en: 'Choose file', zh: '选择文件', es: 'Elegir archivo', fr: 'Choisir un fichier', de: 'Datei wählen', ja: 'ファイルを選択', pt: 'Escolher arquivo' },
  'common.back': { en: 'Back', zh: '返回', es: 'Volver', fr: 'Retour', de: 'Zurück', ja: '戻る', pt: 'Voltar' },
  'common.copy': { en: 'Copy', zh: '复制', es: 'Copiar', fr: 'Copier', de: 'Kopieren', ja: 'コピー', pt: 'Copiar' },
  'common.copied': { en: 'Copied', zh: '已复制', es: 'Copiado', fr: 'Copié', de: 'Kopiert', ja: 'コピーしました', pt: 'Copiado' },
  'common.selected': { en: 'selected', zh: '项已选', es: 'seleccionadas', fr: 'sélectionnées', de: 'ausgewählt', ja: '件選択', pt: 'selecionadas' },
  'common.noViolations': { en: 'No violations found.', zh: '未发现违规。', es: 'No se encontraron infracciones.', fr: 'Aucune violation trouvée.', de: 'Keine Verstöße gefunden.', ja: '違反は見つかりませんでした。', pt: 'Nenhuma violação encontrada.' },
  'detail.resources': { en: 'Resources', zh: '资源类型', es: 'Recursos', fr: 'Ressources', de: 'Ressourcen', ja: 'リソース', pt: 'Recursos' },
  'detail.description': { en: 'Description', zh: '描述', es: 'Descripción', fr: 'Description', de: 'Beschreibung', ja: '説明', pt: 'Descrição' },
  'filter.product': { en: 'Product', zh: '产品', es: 'Producto', fr: 'Produit', de: 'Produkt', ja: '製品', pt: 'Produto' },
  'filter.resourceType': { en: 'Resource type', zh: '资源类型', es: 'Tipo de recurso', fr: 'Type de ressource', de: 'Ressourcentyp', ja: 'リソースタイプ', pt: 'Tipo de recurso' },
  'tab.overview': { en: 'Overview', zh: '总览', es: 'Resumen', fr: 'Aperçu', de: 'Übersicht', ja: '概要', pt: 'Visão geral' },
  'tab.packs': { en: 'Packs', zh: '合规包', es: 'Paquetes', fr: 'Packs', de: 'Pakete', ja: 'パック', pt: 'Pacotes' },
  'tab.rules': { en: 'Rules', zh: '规则', es: 'Reglas', fr: 'Règles', de: 'Regeln', ja: 'ルール', pt: 'Regras' },
  'catalog.coverage': { en: 'Coverage by service', zh: '按服务覆盖', es: 'Cobertura por servicio', fr: 'Couverture par service', de: 'Abdeckung nach Dienst', ja: 'サービス別カバレッジ', pt: 'Cobertura por serviço' },
  'scan.policies': { en: 'Policies', zh: '策略', es: 'Políticas', fr: 'Politiques', de: 'Richtlinien', ja: 'ポリシー', pt: 'Políticas' },
  'scan.allPolicies': { en: 'All policies', zh: '全部策略', es: 'Todas las políticas', fr: 'Toutes les politiques', de: 'Alle Richtlinien', ja: 'すべてのポリシー', pt: 'Todas as políticas' },
  'studio.template': { en: 'Template', zh: '模板', es: 'Plantilla', fr: 'Modèle', de: 'Vorlage', ja: 'テンプレート', pt: 'Modelo' },
  'studio.compliant': { en: 'Compliant fixture', zh: '合规夹具', es: 'Caso conforme', fr: 'Exemple conforme', de: 'Konformes Beispiel', ja: '準拠サンプル', pt: 'Exemplo conforme' },
  'studio.violation': { en: 'Violation fixture', zh: '违规夹具', es: 'Caso con infracción', fr: 'Exemple en violation', de: 'Verstoß-Beispiel', ja: '違反サンプル', pt: 'Exemplo com violação' },
  'studio.rego': { en: 'Rego rule', zh: 'Rego 规则', es: 'Regla Rego', fr: 'Règle Rego', de: 'Rego-Regel', ja: 'Rego ルール', pt: 'Regra Rego' },
  'studio.pass': { en: 'PASS', zh: '通过', es: 'CORRECTO', fr: 'RÉUSSI', de: 'BESTANDEN', ja: '合格', pt: 'APROVADO' },
  'studio.fail': { en: 'FAIL', zh: '失败', es: 'FALLO', fr: 'ÉCHEC', de: 'FEHLER', ja: '不合格', pt: 'FALHA' },
}

interface I18nCtx {
  lang: Lang
  setLang: (l: Lang) => void
  t: (key: string) => string
}

const Ctx = createContext<I18nCtx>({ lang: 'en', setLang: () => {}, t: (k) => k })

function isLang(v: string): v is Lang {
  return LANGS.some((l) => l.value === v)
}

function detectLang(): Lang {
  const saved = localStorage.getItem('ig_lang')
  if (saved && isLang(saved)) return saved
  const nav = (typeof navigator !== 'undefined' ? navigator.language || '' : '').toLowerCase().split('-')[0]
  if (isLang(nav)) return nav
  return 'en'
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(detectLang)
  const setLang = (l: Lang) => {
    localStorage.setItem('ig_lang', l)
    setLangState(l)
  }
  const t = (key: string) => dict[key]?.[lang] ?? dict[key]?.en ?? key
  return <Ctx.Provider value={{ lang, setLang, t }}>{children}</Ctx.Provider>
}

export function useI18n() {
  return useContext(Ctx)
}

// pick returns the value for the current language from an i18n map, falling back to en.
export function pick(m: Record<string, string> | undefined, lang: string): string {
  if (!m) return ''
  return m[lang] || m['en'] || Object.values(m)[0] || ''
}
