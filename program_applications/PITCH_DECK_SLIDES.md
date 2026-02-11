---
title: ProofLayer
subtitle: The Security Layer for AI Coding Agents
author: Pre-Seed | 2025
---

# The Problem

- **62%** of AI-generated code has vulnerabilities
- **10,000+** new security findings/month (10x spike)
- **85%** of orgs use AI coding assistants

Existing tools scan AFTER commit.

**Nobody protects the agent WHILE it writes.**

::: notes
Snyk and Semgrep were built for human developers. They scan after commit. When an AI agent writes 500 lines in 30 seconds, that model breaks. The vulnerable code is already in your repo — or in production.
:::

# The Window Is Open

**2 Years Ago**

- No MCP protocol
- No agent coding
- No attack vector

**Today**

- MCP = standard (97M downloads)
- Cursor: $500M ARR
- OpenAI, Google, Microsoft adopting

**2 Years From Now**

- Snyk bolts on AI features
- Window closes

::: notes
MCP is 6 months old. Cursor went from zero to $500M ARR in 12 months. If we wait, incumbents add agent features. The window is now.
:::

# Security Inside the Agent

```
┌────────────────────────────────┐
│  AI Agent (Claude, Cursor...)  │
│              ↓                 │
│     ┌─────────────────┐        │
│     │   ProofLayer    │        │
│     │  • Prompt Shield│        │
│     │  • Code Scanner │        │
│     │  • Package Check│        │
│     └─────────────────┘        │
│              ↓                 │
│       Clean, Safe Code         │
└────────────────────────────────┘
```

**One command:** `npx agent-security-scanner-mcp`

::: notes
MCP server — the protocol agents use to call tools. One install, the agent gains three security capabilities. Works with Claude Code, Cursor, Windsurf, Cline.
:::

# Three Capabilities

**1. PROMPT INJECTION FIREWALL**

Block attacks before execution

**2. CODE SCANNER + AUTO-FIX**

359 rules | OWASP Top 10 | Fixes applied automatically

**3. PACKAGE HALLUCINATION DETECTION**

4.3M verified packages | 7 ecosystems

::: notes
Prompt firewall, code scanning with auto-fix, and package hallucination detection. We don't just warn — we fix.
:::

# Package Hallucination

> Agent suggests: `npm install data-validator-utils`
>
> Reality: Package doesn't exist
>
> Attack: Adversary registers it as malware
>
> Result: Agent auto-installs malicious code

**Our testing: 45% hallucination rate** (Rust, Claude Sonnet)

*"When we show this to security teams, the room goes silent."*

::: notes
This closes meetings. 45% of Rust packages Claude suggested don't exist. Attackers register these names as malware. The agent auto-installs it. Nobody had this on their threat model.
:::

# Built. Shipped. Live.

- 359 security rules
- 4.3M packages verified
- 7 ecosystems
- Works with Claude Code, Cursor, Windsurf, Cline
- 2.7 MB | MIT Licensed

`npm install agent-security-scanner-mcp`

**Pre-revenue → Enterprise design partners**

::: notes
Not a deck — a demo. Live on npm today. Pre-revenue, focused on distribution and enterprise pilots.
:::

# Market: $30B → $322B

**Agentic AI Security Market**

- $30.27B (2025)
- $322B (2033)
- 34.4% CAGR

**Comparables**

- Snyk: $8.5B (human code)
- Cursor: $500M ARR (AI coding)
- Semgrep: $204M raised

**We're building Snyk for AI agents.**

::: notes
Snyk: $8.5B for human code. Cursor: $500M ARR for AI coding. We're at the intersection.
:::

# Business Model

| Tier | Price | Features |
|------|-------|----------|
| Free | $0 | CLI + local, community rules |
| Team | $500-2K/mo | Dashboard, audit logs, CI/CD |
| Enterprise | Custom | SSO, SLA, compliance, support |

**+ Usage-based CI/CD pricing**

**+ Rule marketplace (future)**

::: notes
Open-source drives adoption. Team tier adds dashboards and CI/CD. Enterprise gets SSO and SLAs. Same playbook as GitLab, Snyk, HashiCorp.
:::

# Why We Win

|                   | Snyk | Semgrep | Lakera | ProofLayer |
|-------------------|:----:|:-------:|:------:|:----------:|
| MCP-native        |  ✗   |    ✗    |   ✗    |     ✓      |
| Scans IN workflow |  ✗   |    ✗    |   ✗    |     ✓      |
| Package halluc.   |  ✗   |    ✗    |   ✗    |     ✓      |
| Prompt injection  |  ✗   |    ✗    |   ✓    |     ✓      |
| Auto-fix          |  ✗   |    ✗    |   ✗    |     ✓      |

**They retrofit. We're native.**

::: notes
Snyk/Semgrep scan after commit — built for humans. Lakera protects chatbots, not code. We're MCP-native. They'll retrofit. We're native.
:::

# Team

**DIVYA CHITIMALLA — CEO/CTO**

Google Safe Browsing (1B+ users) → NVIDIA Garak → Garak Security

**ANIT KUMAR SAHU — Chief Scientist**

CMU PhD → Amazon Alexa AI → Oracle Health AI

**DHEERAJ REDDY — Product Lead**

Staff Engineer → Albertsons AI Infrastructure

::: notes
Divya: Google phishing detection for 1B users, commercialized NVIDIA Garak. Anit: adversarial ML papers at CMU/Amazon, now agent guardrails at Oracle. Dheeraj: production AI infrastructure, knows what ships.
:::

# Raising $400K

**MONTH 1: Distribution**

- MCP registry listing
- 2-3 tool partnerships
- 10K+ installations

**MONTH 2: Enterprise MVP**

- Team dashboard + CI/CD
- 3 enterprise LOIs

**MONTH 3: Expand**

- 359 → 500+ rules
- Runtime scanning
- First paid pilots

::: notes
$400K pre-seed. Month 1: distribution via MCP registry. Month 2: enterprise dashboard and LOIs. Month 3: expand coverage and close pilots. Product is built — funding buys speed.
:::

# The Security Layer for AI Agents

**41%** of code is AI-generated.

**62%** has vulnerabilities.

**Nobody** protects the agent.

**We do.**

divya@prooflayer.dev

::: notes
Every company adopting AI coding agents will need this. We're building it now. The window is 12 months. We're already live. Let's talk.
:::
