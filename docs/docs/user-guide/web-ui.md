---
title: Web UI
---

# Web UI

InfraGuard ships a local web UI for people who prefer a graphical workflow over
the CLI. It is served by the binary itself — no install, no backend, fully
offline.

```bash
infraguard server start --open
```

This starts a background server bound to `127.0.0.1`, prints the URL, and opens it
in your browser. Manage it with `infraguard server status` and
`infraguard server stop` (see the [server CLI reference](../cli/server)).

## Pages

### Scan

Paste an Alibaba Cloud ROS or Terraform template, pick the policies to apply (or
leave it as "all"), and scan. Results appear as severity-ranked cards with the
rule, resource, source line, and remediation. Click a severity chip to filter.

### Policies

Browse the built-in rules and packs:

- **Overview** — totals, severity breakdown, and coverage by service.
- **Packs** / **Rules** — searchable, filterable by product and resource type.

Click any rule to see its metadata and Rego implementation (ROS / Terraform).

### Rule Studio

Write a Rego rule and evaluate it against a template, or test it against
compliant/violation fixtures — the same engine the CLI uses, in the browser.

## Browser playground

For a zero-install taste of InfraGuard, the documentation site also hosts a
[Playground](/playground) that scans ROS templates entirely in your browser. It
covers the quick-start rule set; use `infraguard server` for the full catalog and
Terraform support.
