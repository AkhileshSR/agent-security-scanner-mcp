# Y Combinator Application - ProofLayer

---

## Founders

**Who writes code, or does other technical work on your product? Was any of it done by a non-founder? Please explain.**

Divya Chitimalla (CEO/CTO) wrote 100% of the current product - the MCP server, 359 security rules, package hallucination detection system, and npm package. No non-founder work. The Chief Scientist contributes to adversarial ML research and guardrail design. All technical work is founder-built.

---

**Are you looking for a cofounder?**

No

---

**Founder Video**

[To be recorded - 1 minute introducing founders]

---

## Company

**Company name:**

ProofLayer

---

**Describe what your company does in 50 characters or less:**

Security layer for AI coding agents

---

**Company URL, if any:**

https://[TBD]

---

**Demo:**

[Attach demo video showing MCP server in action with Claude Code/Cursor]

---

**Please provide a link to the product, if any:**

https://www.npmjs.com/package/agent-security-scanner-mcp

---

**If login credentials are required for the link above, enter them here:**

N/A - open source, no login required

---

**What is your company going to make? Please describe your product and what it does or will do.**

We built the first MCP-native security layer for AI coding agents.

AI agents (Claude Code, Cursor, Copilot, Windsurf) are writing 41% of all code globally, but 62% of AI-generated code contains vulnerabilities. Existing security tools (Snyk, Semgrep) scan code *after* it's committed - nobody protects the agent *while* it writes.

Our MCP server plugs directly into AI coding tools and provides three capabilities:

1. **Prompt injection firewall** - Scans instructions for malicious payloads before the agent executes them
2. **Code vulnerability scanning with auto-fix** - 359 rules covering SQL injection, XSS, hardcoded secrets, command injection (OWASP Top 10) with automatic remediation suggestions
3. **Package hallucination detection** - Verifies every dependency against 4.3M real packages across 7 ecosystems (npm, PyPI, crates.io, RubyGems, Go, Dart, CPAN)

Live on npm today: `npm install agent-security-scanner-mcp`

Works with Claude Code, Cursor, Windsurf, Cline - every major AI coding client.

---

**Where do you live now, and where would the company be based after YC?**

[City], USA / San Francisco, USA

---

**Explain your decision regarding location.**

San Francisco for proximity to AI/security talent, enterprise customers, and the YC network. The AI coding tool ecosystem (Anthropic, Cursor, etc.) is concentrated in SF/Bay Area.

---

## Progress

**How far along are you?**

Live product on npm with real users:
- 359 security rules covering 12 programming languages
- 4.3M verified packages across 7 ecosystems
- 6 MCP tools integrated
- Works with every major AI coding client (Claude Code, Cursor, Windsurf, Cline)
- 2.7 MB lightweight package, MIT licensed

Pre-revenue. Focused on open-source distribution and reaching out to enterprise design partners.

---

**How long have each of you been working on this? How much of that has been full-time? Please explain.**

3 months building the product. Part-time (nights/weekends) while holding day jobs. The product is fully functional and deployed - funding enables us to go full-time and pursue enterprise pilots.

---

**What tech stack are you using, or planning to use, to build this product? Include AI models and AI coding tools you use.**

**Current stack:**
- TypeScript/Node.js - MCP server and VS Code extension
- Python - Security analyzer engine
- YAML - Security rule definitions (Semgrep-compatible format)
- Regex + optional Tree-sitter AST - Pattern matching

**AI tools used:**
- Claude Code - Primary development tool
- Used our own product to scan code as we built it (dogfooding)

**Planned additions:**
- LLM-based rule generation for custom enterprise policies
- Streaming guardrails for real-time agent output scanning

---

**Optional: attach a coding agent session you're particularly proud of.**

[Attach transcript of Claude Code session building the package hallucination detector]

---

**Are people using your product?**

Yes

---

**Do you have revenue?**

No

---

**If you are applying with the same idea as a previous batch, did anything change?**

N/A - First application

---

**If you have already participated or committed to participate in an incubator, "accelerator" or "pre-accelerator" program, please tell us about it.**

N/A

---

## Idea

**Why did you pick this idea to work on? Do you have domain expertise in this area? How do you know people need what you're making?**

**Why this idea:**
We discovered the problem firsthand. While using Claude Code to build a Rust application, 45% of the packages it suggested didn't exist. We ran 273 package hallucination tests and 512+ XSS vulnerability tests on Claude Sonnet 4.5. The results were alarming: 45% Rust package hallucination rate, 34% XSS success rate. Nobody was protecting developers from this.

**Domain expertise:**
- Divya: Founding CTO at Redbolt AI ($2M funded), top OSS contributor to NVIDIA Garak (AI red-teaming), Google Safe Browsing (phishing detection at billions of URLs), Akamai bot detection, Google Chronicle
- Chief Scientist: Oracle Health AI (agent guardrails), Amazon AGI (adversarial ML at scale, KDD 2022), Bosch (black-box adversarial attacks, KDD 2021), GE Healthcare (LLM hallucination detection)

**How we know people need this:**
- 62% of AI-generated code has vulnerabilities (Cloud Security Alliance)
- 10,000+ new security findings per month from AI code - 10x spike in 6 months (Apiiro)
- Posted our research on LinkedIn - security teams reached out asking for the tool
- Developers don't want more warnings, they want auto-fix. We built that.

---

**Who are your competitors? What do you understand about your business that they don't?**

**Competitors:**

| Company | What They Do | Their Gap |
|---------|--------------|-----------|
| Snyk ($8.5B) | Static code scanning | Scans after commit, no agent integration, no prompt injection |
| Semgrep ($204M) | Rule-based SAST | CLI-focused, not MCP-native, no package hallucination |
| Lakera ($30M) | LLM app firewall | Protects chatbots, not coding agents, no code context |
| SonarQube | Code quality | No LLM understanding, no agent workflow |

**What we understand that they don't:**

1. **The agent IS the developer now.** Security must run inside the agent's workflow (MCP), not as a separate tool humans remember to invoke.

2. **Package hallucination is a new attack vector.** AI agents invent dependencies that don't exist - supply chain attacks waiting to happen. Nobody else detects this.

3. **Detection without remediation is noise.** Developers ignore warnings. We built auto-fix for every rule - the agent finds the vuln, shows the fix, applies it.

4. **MCP is the distribution layer.** One integration works across Claude Code, Cursor, Windsurf, Cline. Competitors would need to build separate integrations for each.

---

**How do or will you make money? How much could you make?**

**Revenue model:**

| Tier | Price | Features |
|------|-------|----------|
| Free (Open Source) | $0 | CLI, local scanning, community rules |
| Team | $500-2K/mo | Team dashboard, audit logs, custom policies |
| Enterprise | Custom | SSO, SLA, dedicated onboarding, compliance reports |

**Additional revenue:**
- Usage-based pricing for CI/CD pipeline integration
- Rule marketplace (custom rules for specific frameworks/industries)

**Market size:**
- Agentic AI Security Market: $30.27B (2025) → $322B by 2033 (CAGR 34.4%)
- Comparable: Snyk valued at $8.5B for human code security
- Cursor alone: $500M ARR for AI coding

**Our target:**
- Year 1: $100K ARR (3-5 enterprise pilots)
- Year 2: $1M ARR (expand to 20-30 customers)
- Year 3: $10M ARR (platform + marketplace)

---

**Which category best applies to your company?**

B2B / Developer Tools / Security

---

**If you had any other ideas you considered applying with, please list them.**

1. **Runtime agent behavior monitoring** - Track what AI agents actually do (file writes, API calls, shell commands) and flag anomalies. Decided to focus on code security first - clearer value prop, faster validation.

2. **Agent-to-agent security** - Protect multi-agent systems where Agent A's output becomes Agent B's input (state pollution attacks). Still interested - this is our Chief Scientist's research focus. May add later.

3. **AI code review as a service** - Human-in-the-loop review for high-stakes AI-generated code. Too services-heavy, doesn't scale. Killed it.

---

## Equity

**Have you formed ANY legal entity yet?**

[Yes/No - to be filled]

---

**Have you taken any investment yet?**

No

---

**Are you currently fundraising?**

Yes

---

## Curious

**What convinced you to apply to Y Combinator? Did someone encourage you to apply? Have you been to any YC events?**

Three reasons:

1. **YC understands developer tools.** Companies like Snyk, GitLab, and countless dev tools came through YC. Agent security is the next wave of dev tooling.

2. **Network access.** We need enterprise design partners fast. YC's network reaches security buyers at scale-ups and enterprises who are actively deploying AI coding tools.

3. **Credibility signal.** Cold outreach to security teams without backing = low response rate. "YC-backed" opens doors.

[Note if encouraged by specific person or attended events]

---

**How did you hear about Y Combinator?**

[To be filled - e.g., "YC alumni recommendation", "Hacker News", etc.]

---

## Summary

> "Snyk is valued at $8.5B for scanning human code. We're building the Snyk for AI agents - and we're already live on npm."
