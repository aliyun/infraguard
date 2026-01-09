/**
 * Prism.js language definition for Rego (Open Policy Agent language)
 * Based on Rego syntax specification
 */

// Prism type from prismjs package (used by Docusaurus)
type PrismType = {
  languages: {
    [key: string]: any;
  };
};

export function registerRegoLanguage(Prism: PrismType) {
  Prism.languages.rego = {
    'comment': {
      pattern: /#.*/,
      greedy: true,
    },
    'string': {
      pattern: /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/,
      greedy: true,
    },
    'keyword': {
      pattern: /\b(?:package|import|as|default|else|some|not|if|contains|with)\b/,
      greedy: true,
    },
    'boolean': {
      pattern: /\b(?:true|false)\b/,
    },
    'operator': {
      pattern: /:=|==|!=|>=|<=|>|<|\+|-|\*|\/|%|\.|\?/,
    },
    'function': {
      pattern: /\b[a-z_][a-z0-9_]*(?=\s*\()/i,
    },
    'variable': {
      pattern: /\b[a-z_][a-z0-9_]*\b/i,
    },
    'number': {
      pattern: /\b\d+(?:\.\d+)?\b/,
    },
    'punctuation': {
      pattern: /[{}[\];(),.:]/,
    },
  };
}

