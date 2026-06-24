// Tiny dependency-free syntax highlighter for Rego, YAML (ROS) and HCL (Terraform).
// Produces HTML with <span class="tok-*"> wrappers; runs fully offline.

export type Language = 'rego' | 'yaml' | 'hcl' | 'plain'

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

interface Rule {
  re: string // no capturing groups; use (?:...)
  cls: string
}

const RULES: Record<Language, Rule[]> = {
  rego: [
    { re: '#[^\\n]*', cls: 'c' },
    { re: '"(?:[^"\\\\]|\\\\.)*"', cls: 's' },
    { re: '\\b(?:package|import|as|default|some|every|in|if|contains|not|with|else)\\b', cls: 'k' },
    { re: '\\b(?:true|false|null)\\b', cls: 'b' },
    { re: '\\b\\d+(?:\\.\\d+)?\\b', cls: 'n' },
  ],
  yaml: [
    { re: '#[^\\n]*', cls: 'c' },
    { re: '(?<=^[ \\t]*(?:- )?)[\\w.\\-/]+(?=\\s*:)', cls: 'a' },
    { re: "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^']|'')*'", cls: 's' },
    { re: '\\b(?:true|false|null|yes|no)\\b', cls: 'b' },
    { re: '\\b\\d+(?:\\.\\d+)?\\b', cls: 'n' },
  ],
  hcl: [
    { re: '#[^\\n]*|//[^\\n]*', cls: 'c' },
    { re: '"(?:[^"\\\\]|\\\\.)*"', cls: 's' },
    { re: '\\b(?:resource|data|variable|output|module|provider|terraform|locals|for|in|if)\\b', cls: 'k' },
    { re: '\\b(?:true|false|null)\\b', cls: 'b' },
    { re: '\\b\\d+(?:\\.\\d+)?\\b', cls: 'n' },
  ],
  plain: [],
}

const compiled: Partial<Record<Language, RegExp>> = {}

function regexFor(lang: Language): RegExp | null {
  if (RULES[lang].length === 0) return null
  if (!compiled[lang]) {
    const src = RULES[lang].map((r) => `(${r.re})`).join('|')
    compiled[lang] = new RegExp(src, 'gm')
  }
  return compiled[lang]!
}

export function highlight(code: string, lang: Language): string {
  const re = regexFor(lang)
  if (!re) return esc(code)
  const rules = RULES[lang]
  let out = ''
  let last = 0
  re.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(code))) {
    if (m[0] === '') {
      re.lastIndex++
      continue
    }
    out += esc(code.slice(last, m.index))
    let gi = -1
    for (let i = 1; i < m.length; i++) {
      if (m[i] !== undefined) {
        gi = i - 1
        break
      }
    }
    out += `<span class="tok-${rules[gi]?.cls ?? 'p'}">${esc(m[0])}</span>`
    last = m.index + m[0].length
  }
  out += esc(code.slice(last))
  return out
}
