---
title: infraguard lsp
---

# infraguard lsp

Startet den ROS Language Server Protocol (LSP)-Server für Editor-Integration.

## Synopsis

```bash
infraguard lsp [flags]
```

## Beschreibung

Der Befehl `lsp` startet einen Language Server Protocol (LSP)-Server, der über Standard-Ein-/Ausgabe (stdio) kommuniziert. Er bietet intelligente Bearbeitungsunterstützung für ROS-Vorlagen in Editoren wie VS Code, einschließlich:

- **Auto-Vervollständigung** — Ressourcentypen, Eigenschaften, intrinsische Funktionen, Ref/GetAtt-Ziele
- **Echtzeit-Diagnose** — Formatversion, Ressourcentypen, erforderliche Eigenschaften, Typfehler
- **Hover-Dokumentation** — Beschreibungen, Typinformationen, Einschränkungen für Ressourcen und Eigenschaften
- **Gehe zu Definition** — Springe von Referenzen zu Parameter- und Ressourcendefinitionen

Der LSP-Server unterstützt sowohl YAML- als auch JSON-Vorlagenformate.

## Flags

| Flag | Typ | Beschreibung |
|------|-----|--------------|
| `--stdio` | bool | Stdio-Transport verwenden (Standard, für Editor-Kompatibilität akzeptiert) |

## Beispiele

### LSP-Server starten

```bash
infraguard lsp
```

### Mit explizitem stdio-Flag starten

```bash
infraguard lsp --stdio
```

## Editor-Integration

Der LSP-Server wird typischerweise automatisch von Editor-Erweiterungen gestartet. Für VS Code installieren Sie die [InfraGuard-Erweiterung](https://marketplace.visualstudio.com/items?itemName=AlibabaCloudROS.infraguard), die die LSP-Lebenszyklusverwaltung übernimmt.

Weitere Details finden Sie unter [Editor-Integration](../user-guide/editor-integration).

## Exit-Codes

- `0`: Server wurde normal beendet
