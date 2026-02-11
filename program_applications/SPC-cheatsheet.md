# SPC Interview Cheat Sheet — Divya

## Interviewers
- **Jonathan Brebner** — Partner, Chief Storyteller (SF) — cares about narrative
- **Dylan Itzikowitz** — NYC, early-stage investing — cares about ambition/ability

---

## SECTION 1: TEAM (~5 min)

### Your Intro (2 sentences)
"4.5 years at Google leading phishing detection on Chrome protecting 1B users. Then commercialized NVIDIA's Garak into enterprise AI security. Now building ProofLayer — the security layer for AI agents."

### How We Met (30 sec)
"Anit and I are IIT Kharagpur labmates. He published adversarial attacks while I built defenses. When AI agents exploded in 2024, we both realized: nobody is securing agent-written code. Dheeraj brought production AI infrastructure experience. We'd all seen the problem from different angles."

### Handoff Phrases
- "Anit can speak to this from the research side..."
- "This is something Dheeraj drove — Dheeraj?"

---

## SECTION 2: IDEATION (~5 min)

### 60-Second Pitch
"62% of AI-generated code has vulnerabilities. 41% of all code is now AI-generated. Snyk/Semgrep were built for humans — scan after commit. Nobody protects the agent itself.

We built the first MCP-native security layer. Runs inside the agent. Prompt injection firewall, code scanning with auto-fix, 4.3M package verification. Works with Claude Code, Cursor, Windsurf. We're building Snyk for AI agents."

### The "Oh Shit" Moment
"Package hallucination. AI agents invent dependency names. Attackers register them as malware. The agent auto-installs it. When we show this, the room goes silent."

### Who's Bleeding?
1. Enterprise security teams — mandated AI tools, no audit capability
2. DevOps — unexplained vuln spikes traced to AI code
3. AI tool vendors (Cursor, Windsurf) — need security story for enterprise sales

### Why Now?
- **Not 2 years ago:** MCP didn't exist, agents weren't writing production code
- **Not 2 years later:** Protocol layer being defined NOW, first-mover owns trust layer, window closes in 12 months

---

## SECTION 3: NEXT STEPS (~5 min)

### 90-Day Plan ($400K)
| Month | Milestone | Target |
|-------|-----------|--------|
| 1 | MCP registry + tool vendor partnerships | 10K installs |
| 2 | Enterprise MVP (dashboard, CI/CD) | 3 LOIs |
| 3 | 500+ rules, runtime scanning | Close deals |

### Why SPC Specifically
1. **Network** — warm intros to CISOs, not cold outreach
2. **GTM mentorship** — open-source to enterprise revenue playbook

### If Funded Tomorrow, Monday =?
"Tuesday: MCP registry application. Wednesday: reach out to 5 enterprise design partners. End of week: sprint plan for enterprise dashboard."

---

## QUICK STATS (memorize)

| Stat | Number |
|------|--------|
| AI code with vulns | **62%** |
| Global code AI-generated | **41%** |
| Orgs using AI coding | **85%** |
| Market 2025 | **$30B** |
| Market 2033 | **$322B** |
| Cursor ARR | **$500M** |
| Snyk valuation | **$8.5B** |
| Our rules | **275+** |
| Our packages | **4.3M** |

---

## HARDEST QUESTIONS

**"Won't OpenAI/Anthropic build this?"**
"They'll build basic guardrails, not security scanning. Anthropic doesn't build antivirus. This is middleware — always built by specialists. Plus we're tool-agnostic."

**"How different from existing AppSec?"**
"1) MCP-native — inside agent workflow. 2) Agent-specific threats — prompt injection, hallucinated packages. 3) Auto-fix, not just detection."

**"Scariest customer question?"**
"Zero-day handling. Currently rule-based. That's why runtime behavioral monitoring is Milestone 3 — pattern-matching to anomaly detection."

**"Why beat well-funded incumbents?"**
"Snyk assumes human commits code, runs scan. We're MCP-native — tool the agent calls. Same reason Datadog beat monitoring incumbents — cloud-native vs porting legacy."

---

## DO / DON'T

**DO:** Be concise | Concrete examples | Show you've built (npm scanner) | Be authentic about uncertainty

**DON'T:** Recite LinkedIn | Oversell traction | Dominate conversation | Get defensive

---

## YOUR UNIQUE EDGES
1. **Google Safe Browsing** — same pattern as agent security (intercept malicious inputs at scale)
2. **NVIDIA Garak OSS -> Commercial** — exact open-source to enterprise playbook
3. **Akamai Bot Detection** — distinguishing adversarial from legitimate at infra layer

---

## FINAL REMINDER
They fund **founders, not perfect plans**. Show velocity (live npm, shipped v2.0.7 today), curiosity (killed 3 approaches), and conviction.
