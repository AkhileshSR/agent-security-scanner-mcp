# ProofLayer Pre-Seed Pitch Deck

**Format:** Google Slides
**Duration:** 10-12 minutes
**Slides:** 13

---

## Slide 1: Title

### On Slide
```
ProofLayer

The Security Layer for AI Coding Agents

[Logo placeholder]

Pre-Seed | 2025
```

### Speaker Notes
"AI agents are writing 41% of all code globally. 62% of that code contains security vulnerabilities. We built the first security layer that runs inside the agent's workflow — protecting code as it's written, not after it ships."

---

## Slide 2: Problem

### On Slide
```
The Problem

62% of AI-generated code has vulnerabilities
10,000+ new security findings/month (10x spike)
85% of orgs use AI coding assistants

Existing tools scan AFTER commit.
Nobody protects the agent WHILE it writes.
```

### Visual Suggestion
Timeline: `Agent writes → Committed → Snyk scans → Too late`
Red gap between "writes" and "scans"

### Speaker Notes
"Snyk and Semgrep were built for human developers. They scan after commit. When an AI agent writes 500 lines in 30 seconds, that model breaks. The vulnerable code is already in your repo — or in production."

---

## Slide 3: Why Now

### On Slide
```
The Window Is Open

2 YEARS AGO          TODAY                   2 YEARS FROM NOW
✗ No MCP protocol    ✓ MCP = standard        ⚠ Snyk bolts on AI
✗ No agent coding    ✓ Cursor: $500M ARR     ⚠ Window closes
✗ No attack vector   ✓ 97M MCP downloads

The integration layer is being defined NOW.
```

### Speaker Notes
"MCP is 6 months old. Cursor went from zero to $500M ARR in 12 months. If we wait, incumbents add agent features. The window is now."

---

## Slide 4: Solution

### On Slide
```
Security Inside the Agent

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

One command: npx agent-security-scanner-mcp
```

### Speaker Notes
"MCP server — the protocol agents use to call tools. One install, the agent gains three security capabilities. Works with Claude Code, Cursor, Windsurf, Cline."

---

## Slide 5: Product

### On Slide
```
Three Capabilities

1. PROMPT INJECTION FIREWALL
   Block attacks before execution

2. CODE SCANNER + AUTO-FIX
   359 rules | OWASP Top 10 | Fixes applied automatically

3. PACKAGE HALLUCINATION DETECTION
   4.3M verified packages | 7 ecosystems
   Stop supply-chain attacks before install
```

### Visual Suggestion
Screenshot of ProofLayer catching a vuln in Claude Code

### Speaker Notes
"Prompt firewall, code scanning with auto-fix, and package hallucination detection. We don't just warn — we fix."

---

## Slide 6: The "Oh Shit" Moment

### On Slide
```
Package Hallucination

Agent suggests: npm install data-validator-utils
Reality: Package doesn't exist
Attack: Adversary registers it as malware
Result: Agent auto-installs malicious code

Our testing: 45% hallucination rate (Rust, Claude Sonnet)

"When we show this to security teams, the room goes silent."
```

### Visual Suggestion
Flow: Fake package → npm registry → malware installed

### Speaker Notes
"This closes meetings. 45% of Rust packages Claude suggested don't exist. Attackers register these names as malware. The agent auto-installs it. Nobody had this on their threat model."

---

## Slide 7: Traction

### On Slide
```
Built. Shipped. Live.

✓ 359 security rules
✓ 4.3M packages verified
✓ 7 ecosystems
✓ Works with Claude Code, Cursor, Windsurf, Cline
✓ 2.7 MB | MIT Licensed

npm install agent-security-scanner-mcp

Pre-revenue → Enterprise design partners
```

### Speaker Notes
"Not a deck — a demo. Live on npm today. Pre-revenue, focused on distribution and enterprise pilots."

---

## Slide 8: Market

### On Slide
```
$30B → $322B

Agentic AI Security Market
$30.27B (2025) → $322B (2033)
34.4% CAGR

COMPS
Snyk: $8.5B (human code)
Cursor: $500M ARR (AI coding)
Semgrep: $204M raised

We're building Snyk for AI agents.
```

### Speaker Notes
"Snyk: $8.5B for human code. Cursor: $500M ARR for AI coding. We're at the intersection."

---

## Slide 9: Business Model

### On Slide
```
Open Source → Enterprise

FREE              TEAM              ENTERPRISE
$0                $500-2K/mo        Custom
───────────────────────────────────────────
CLI + local       Dashboard         SSO + SLA
Community rules   Audit logs        Compliance
                  CI/CD             Dedicated support

+ Usage-based CI/CD pricing
+ Rule marketplace (future)
```

### Speaker Notes
"Open-source drives adoption. Team tier adds dashboards and CI/CD. Enterprise gets SSO and SLAs. Same playbook as GitLab, Snyk, HashiCorp."

---

## Slide 10: Competition

### On Slide
```
Why We Win

                 Snyk    Semgrep   Lakera   ProofLayer
MCP-native        ✗        ✗         ✗         ✓
Scans IN workflow ✗        ✗         ✗         ✓
Package halluc.   ✗        ✗         ✗         ✓
Prompt injection  ✗        ✗         ✓         ✓
Auto-fix          ✗        ✗         ✗         ✓

They retrofit. We're native.
```

### Speaker Notes
"Snyk/Semgrep scan after commit — built for humans. Lakera protects chatbots, not code. We're MCP-native. They'll retrofit. We're native."

---

## Slide 11: Team

### On Slide
```
We've Done This Before

DIVYA CHITIMALLA — CEO/CTO
Google Safe Browsing (1B+ users) → NVIDIA Garak → Garak Security
Phishing detection. AI red-teaming. Now agent security.

ANIT KUMAR SAHU — Chief Scientist
CMU PhD → Amazon Alexa AI → Oracle Health AI
Adversarial ML research (KDD). Production guardrails.

DHEERAJ REDDY — Product Lead
Staff Engineer → Albertsons AI Infrastructure
Agent workflows. 35% → 90% accuracy improvements.
```

### Speaker Notes
"Divya: Google phishing detection for 1B users, commercialized NVIDIA Garak. Anit: adversarial ML papers at CMU/Amazon, now agent guardrails at Oracle. Dheeraj: production AI infrastructure, knows what ships. Attack + Defense + Production = ProofLayer."

---

## Slide 12: The Ask

### On Slide
```
Raising $400K

MONTH 1: Distribution
• MCP registry listing
• 2-3 tool partnerships
• 10K+ installations

MONTH 2: Enterprise MVP
• Team dashboard + CI/CD
• 3 enterprise LOIs

MONTH 3: Expand
• 359 → 500+ rules
• Runtime scanning
• First paid pilots
```

### Speaker Notes
"$400K pre-seed. Month 1: distribution via MCP registry. Month 2: enterprise dashboard and LOIs. Month 3: expand coverage and close pilots. Product is built — funding buys speed."

---

## Slide 13: Close

### On Slide
```
The Security Layer for AI Agents

41% of code is AI-generated.
62% has vulnerabilities.
Nobody protects the agent.

We do.

divya@prooflayer.dev
```

### Visual Suggestion
QR code to npm package

### Speaker Notes
"Every company adopting AI coding agents will need this. We're building it now. The window is 12 months. We're already live. Let's talk."

---

## Appendix: Key Stats

| Metric | Value |
|--------|-------|
| AI-generated code with vulnerabilities | 62% |
| New security findings/month from AI code | 10,000+ |
| Orgs using AI coding assistants | 85% |
| Global code that is AI-generated | 41% |
| Agentic AI Security market (2025) | $30.27B |
| Projected market (2033) | $322B |
| CAGR | 34.4% |
| MCP monthly SDK downloads | 97M |
| Cursor ARR | $500M |
| Snyk valuation | $8.5B |
| Semgrep raised | $204M |
| Our security rules | 359 |
| Our package database | 4.3M |

---

## Design Notes for Google Slides

**Color Palette:**
- Primary: Deep blue (#1a365d) — trust, security
- Accent: Electric green (#22c55e) — "safe" signals
- Alert: Red (#ef4444) — vulnerabilities
- Background: White or very light gray

**Typography:**
- Headlines: Bold sans-serif (Inter, Poppins)
- Body: Clean sans-serif
- Code: Monospace (JetBrains Mono, Fira Code)

**Visual Style:**
- Minimal text, maximum whitespace
- One key point per slide
- Use icons for capabilities (shield, code, package)
- Dark terminal screenshots for product demos

**Slide Dimensions:**
- 16:9 widescreen format
