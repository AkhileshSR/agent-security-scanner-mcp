SPC Founder Fellowship Interview Prep — FILLED
ProofLayer Team — 15-Minute Partner Interview

Interview Format
Duration: 15 minutes with 2 General Partners
Structure: ~5 minutes per section (Team → Ideation → Next Steps)
Style: Conversational but efficient — every answer matters


Section 1: Team Dynamic (~5 min)
Key Questions They'll Ask
How do you divide responsibilities?
What makes your team special?
Why are you three the right people for this problem?


All Three Co-Founders — 2-Sentence Role Descriptions (NOT LinkedIn Headlines)
Divya Chitimalla (CEO/CTO)

I'm the person who spent 4.5 years at Google leading the phishing detection engine on Chrome that protects a billion users — and then commercialized NVIDIA's open-source Garak red-teaming framework into an enterprise AI security platform. I build security products that scale from open-source adoption to enterprise revenue, and I've done it twice now — first at Garak Security (backed by Open Core Ventures) and now at ProofLayer.

Anit Kumar Sahu (Chief Scientist)

I'm the researcher who literally wrote the papers on federated learning and adversarial attacks at CMU, Bosch, and Amazon — and then shipped those ideas into production ML systems at Amazon Alexa and Oracle Health AI. Now I'm applying everything I know about breaking and defending AI systems to build the security layer that protects AI agents writing code.
Dheeraj Reddy (Product Lead)

I'm a Staff Data Engineer who builds AI infrastructure at scale — from real-time data pipelines to GPT-4 powered agent workflows where I improved accuracy from 35% to 90%. I bridge the gap between what researchers dream up and what actually ships to production, and that's exactly what ProofLayer needs as we go from open-source tool to enterprise product.


Divya's Unique Experiences (Edge in AI Agent Security)
✅ Experience 1 — Google Safe Browsing / Phishing Detection: Led phishing detection on Chrome for 4.5 years, protecting 1B+ users in real-time. This is exactly the same pattern as agent security — intercepting malicious inputs before they reach the target, at scale, with sub-millisecond latency requirements. The difference is the "user" is now an AI agent, and the "phishing page" is a prompt injection.

✅ Experience 2 — NVIDIA Garak OSS → Commercial: Top contributor to NVIDIA's Garak (the most widely used LLM vulnerability scanner — used by Fortune 500 companies). Then founded Garak Security to commercialize it as an enterprise platform. This gives us the exact playbook: open-source adoption → enterprise conversion. We're running the same play with ProofLayer's MCP security server.

✅ Experience 3 — Akamai Bot Detection: Built bot detection systems at Akamai — distinguishing adversarial automated traffic from legitimate users at internet scale. Agent security is fundamentally the same problem: distinguishing legitimate agent behavior from adversarial manipulation, in real-time, at the infrastructure layer.


30-Second "How We Met / Decided to Work Together" Story
"Anit and I are both IIT Kharagpur and were labmates at Electronics lab — we've known each other since undergrad, but our paths kept intersecting at the AI-security boundary. Anit was publishing adversarial attack research at Bosch and Amazon while I was building defenses at Google and Akamai. When AI coding agents exploded in 2024-2025, we both independently realized: nobody is securing the code these agents write. Dheeraj brought the missing piece — he'd been building AI agent infrastructure at scale and had firsthand experience with how these systems fail in production. We'd all seen the problem from different angles — attack research, defense engineering, and production infrastructure — and ProofLayer was the obvious intersection."


Product Lead — Dheeraj Reddy 
✅ How you bridge technical depth and customer needs:

"I've spent 8+ years building data infrastructure and AI systems — I know what engineers actually need versus what sounds good in a demo. At Albertsons, I architect real-time AI pipelines that serve millions of users. My research on GPT-4 agent accuracy (improving from 35% to 90% with structured instructions and error handling) taught me that the gap between 'AI can do it' and 'AI does it reliably' is exactly where product decisions live. I translate our security research into features developers will actually adopt."

✅ Product decision that shaped ProofLayer's direction:

"Early on, we debated whether to build a standalone security dashboard or an MCP-native tool. I pushed hard for MCP-native because of a principle I've lived by in data engineering: security that requires a context switch doesn't get used. By making ProofLayer a capability the agent calls — not a separate tool the developer opens — we made adoption frictionless. That's why we can plug into Cursor, Claude Code, Windsurf with a single npx command. That decision is our entire distribution strategy."

✅ Speaking to the vision as crisply as the CEO:

"We're building the trust layer between AI agents and the code they ship. Today that's an MCP security server. Tomorrow it's the infrastructure that lets enterprises say 'this code was verified by ProofLayer before it hit production.' Every company adopting AI coding agents will need this — and we're building it now, while the protocol layer is still being defined."


Chief Scientist — Anit Kumar Sahu
✅ Relevant ML/Security Research & Production Experience:

Domain
Where
What
Relevance
Adversarial Attacks
Bosch (2019-2020)
Led black-box adversarial attacks on neural networks. Published at KDD 2021 on efficient attacks with minimal query budgets
Directly maps to agent systems where query constraints matter — attackers have limited interactions
Federated Learning & Privacy
Amazon Alexa AI (2020-2024)
Tech lead productionizing federated learning and self-learning ASR models. Published ILASR system at KDD 2022 — incremental learning with security guarantees
Privacy-preserving ML at scale is the foundation for securing distributed agent systems
LLM Guardrails
GE Healthcare (2024-2025)
Hallucination detection and mitigation in LLMs for medical report generation
Adversarial robustness for generative models in domains where errors have real consequences
Agent Security
Oracle Health AI (Current)
Building output guardrails for streaming agent responses in high-stakes physician-patient interactions
Building the exact type of guardrails ProofLayer provides, but for healthcare — proving the approach works in production


✅ Non-Obvious Technical Insight on AI Agent Vulnerabilities:

"Most red-teaming focuses on single-agent vulnerabilities — prompt injection, jailbreaking — but the real attack surface emerges from agent-to-agent interactions. I call it state pollution: Agent A's malicious output becomes Agent B's trusted input, bypassing both agents' individual guardrails.

In my healthcare routing work at Oracle, a query classification agent routes to specialized agents for scheduling, prescriptions, or medical advice. I've observed that attackers can manipulate the router's classification to force sensitive medical queries to the wrong agent — causing information leakage, capability confusion, or cascading hallucinated responses.

The attack surface grows combinatorially — N agents create N² potential interaction vulnerabilities. And it gets worse with multi-turn attacks where an adversary establishes benign context in turn one, references it to bypass guardrails in turn two, and exploits the agent's memory in turn three.

This is why ProofLayer needs to be at the infrastructure level, not the application level. You can't secure agent interactions by securing individual agents."

✅ Why Existing Security Tools Don't Solve This:

"Current tools focus on single-agent vulnerabilities through static analysis. From shipping models at Amazon and Oracle, I've seen three gaps they can't close:

Streaming outputs — agents generate responses incrementally; guardrails designed for complete responses fail on partial streams
Latency constraints — security checks add overhead, forcing trade-offs that create exploitable gaps (we measure every millisecond in healthcare)
Decentralized agent architectures — multi-agent systems can't be secured by tools assuming centralized control

What's needed is graph-based security testing that models agent interactions, streaming guardrails for partial outputs, and cross-agent state tracking to detect information leakage through handoffs. That's what we're building."


CEO/CTO — Divya Chitimalla
✅ 60-Second Market Vision:

"AI coding agents are writing production code at scale — Cursor, Claude Code, Copilot, Devin — and none of them have a security layer. Every line an agent writes can contain SQL injection, hardcoded secrets, or dependencies that don't even exist. We're building the security infrastructure for agentic software development.

Today, we're an MCP server that plugs into every major AI coding tool with 275+ security rules, prompt injection detection, and hallucinated package verification across 4.3 million packages. Tomorrow, we're the runtime security layer that sits between every AI agent and the code it ships.

The market isn't 'SAST tools' — it's 'who secures the 80% of code that humans won't review because an agent wrote it.'"

✅ "Why now? Why not 2 years ago or 2 years from now?"

Not 2 years ago:

MCP protocol didn't exist — no standard way to plug into AI tools
AI agents weren't writing production code autonomously
Package hallucination wasn't a known attack vector
There was no "agentic" workflow to secure

Not 2 years from now:

The integration surface is being defined right now — MCP is ~6 months old and becoming the standard (97M monthly SDK downloads, adopted by OpenAI, Google, Microsoft)
First-mover in this category owns the trust layer
Every month without agent security = millions of lines of unscanned AI-generated code shipping to production
Waiting means competing against incumbents (Snyk at $8.5B, Semgrep at $204M raised) who will bolt on "AI agent" features

The window: AI agents are shipping code today with zero security middleware. The protocol layer (MCP) just matured enough to build on. In 12 months, this category will be crowded."

✅ Funding Strategy and Milestones:

Current traction (pre-funding):

Live on npm, 7 ecosystems, 275+ rules, 6 MCP tools
Works with every major AI coding client (Claude Code, Cursor, Windsurf, Cline)
2.7 MB lightweight package, MIT licensed

Seed milestones with $400K:

Distribution — MCP registry listing, default integration partnerships with AI coding tools
Enterprise features — Policy engine, team dashboards, custom rule management, SSO
Coverage expansion — Runtime scanning (not just static), real-time agent behavior monitoring
Community growth — Open-source contributor base, rule marketplace

Revenue model:

Free open-source core (current) → paid cloud/enterprise tier
Per-seat licensing for teams with compliance requirements
Usage-based for CI/CD pipeline integration

Key metric: Number of agent-generated code scans per month (proxy for how deeply embedded we are in the agentic workflow)


Team Chemistry Signals
✅ Who answers what (pre-agreed):

Topic
Lead Speaker
Support
Team story / how we met
Divya (sets context)
Anit adds color
Market vision / why now
Divya
Dheeraj on product specifics
Technical depth / vulnerabilities
Anit
Divya on real-world context
Product decisions / customer signal
Dheeraj
Divya on strategy
Competitive landscape
Dheeraj
Anit on technical differentiation
90-day plan / milestones
Divya (opens)
Dheeraj (specifics) → Anit (research)


✅ Smooth handoff phrases:

"Anit can speak to this better from the research side..."
"This is actually something Dheeraj drove — Dheeraj?"
"Building on what Divya said about the market..."


Section 2: Ideation (~5 min)
60-Second Pitch: What Is ProofLayer and Why Does It Matter?
"62% of AI-generated code contains security vulnerabilities. 10,000 new security findings per month from AI code — a 10x spike in 6 months. 85% of organizations now use AI coding assistants, and 41% of all code globally is AI-generated.

The existing security tools? Snyk and Semgrep were built for human developers. They scan code after it's committed. Lakera protects chatbots, not code.

Nobody is protecting the agent itself. Nobody is stopping the prompt injection before it happens. Nobody is catching the hallucinated package before it's installed.

We built the first MCP-native security layer. It runs inside the agent workflow — prompt injection firewall, code scanning with auto-fix, and package verification across 4.3M packages. We're already deployed on Claude Code, Cursor, and Windsurf. The market is $30B today, $322B by 2033. We're building the Snyk for AI agents."


Stat/Anecdote That Makes the Problem Urgent
"In our testing, we found that AI coding agents hallucinate package names at a measurable rate. Attackers are already registering these hallucinated names on npm and PyPI as malware. It's like domain squatting, but for code dependencies — and the AI agent does the installation automatically. One compromised package in a CI/CD pipeline can exfiltrate every secret in the build environment."


"Who Is Bleeding From This Problem Today?"
"Three audiences:

Enterprise security teams who've mandated AI coding assistants but have no way to audit what the agents produce — they're flying blind
DevOps/platform teams who are seeing unexplained vulnerabilities spike in their SAST scans and can trace them back to AI-generated code
AI coding tool vendors (Cursor, Windsurf, Cline) who need a security story for enterprise sales but don't want to build it themselves — we're their security layer"


Ideas/Approaches Tried and Killed

✅ Killed Idea 2: Three verticals (chat/voice/code) simultaneously

"We explored securing AI agents across chat, voice, and code simultaneously. Killed the breadth approach — we're going deep on code agents first because that's where the money is (Cursor alone is $500M ARR) and where the consequences of failure are most concrete (vulnerabilities ship to production). We'll expand once we own the code security category."

✅ Killed Idea 3: Building our own scanning engine from scratch

"We considered writing a proprietary scanning engine. Killed it in favor of building on Semgrep-aligned rules and tree-sitter AST parsing — this lets us be compatible with existing rule ecosystems while adding the agent-native layer (prompt injection, package hallucination) that nobody else has. Build what's new, leverage what exists."


"Here's What Surprised Us When Talking to Customers"
"We expected enterprises to care most about code vulnerability detection — they already know about SQL injection and XSS. What actually gets the most urgent reaction is package hallucination. When we show a security team that their AI agent invented a dependency name and that an attacker could register it as malware, the room goes silent. Nobody had that on their threat model. It's the 'oh shit' moment that turns a meeting into a deployment conversation."


Current Customer/Design Partner Status
"We're in pre-revenue open-source adoption phase. The npm package is live and works with every major AI coding client. We're pursuing design partnerships with enterprises that have mandated AI coding assistants and need a security compliance story. Our immediate focus is getting listed on the MCP registry for maximum distribution."


Competitive & Strategic Questions — Prepared Answers
✅ "Won't OpenAI/Anthropic just build this into their APIs?"

"They might build basic safety guardrails — they already have some. But security scanning, package verification, and policy enforcement are not their core competency. They're building the best models, not the best security tools. Anthropic doesn't build antivirus; Google doesn't build firewalls. This is a middleware layer, and middleware has always been built by specialists. Plus, we're tool-agnostic — we work across all agents, which is what enterprises need."

✅ "Isn't this market too early? Who's actually buying?"

"85% of organizations already use AI coding assistants. Cursor went from $1M to $500M ARR in 12 months. This isn't 'early market' — this is 'explosive adoption without security.' Enterprise security teams are already asking 'how do we audit AI-generated code?' They have budget and urgency. What they don't have is a tool that fits into the agentic workflow."

✅ "How is this different from existing AppSec or WAF tools?"

"Three ways. First, we're MCP-native — we run inside the agent's workflow, not as a separate step. Second, we handle agent-specific threats that traditional tools don't even detect: prompt injection, package hallucination, agent manipulation. Third, we provide auto-fix, not just detection — which is critical when you're scanning thousands of lines of agent-generated code per hour."

✅ "Why three verticals (chat/voice/code) vs. going deep on one?"

"We're not doing three verticals. We killed that approach. We're going deep on code agents only — that's where the largest market ($500M ARR for Cursor alone), the most concrete consequences (code ships to production), and the clearest buyer (enterprise security teams) exist. We'll expand once we own this category."


How We Validate Ideas
"Three-layer validation:

Build fast, measure adoption — the open-source MCP scanner is live on npm. We track installs, which tools people use it with, and which security rules fire most. That's real signal, not hypothetical.
Customer conversations — we talk to enterprise security teams and DevOps leads to understand what they're actually worried about (spoiler: package hallucination is scarier to them than prompt injection).
Threat landscape monitoring — we track new attack vectors as they're discovered. When someone publishes a new prompt injection technique or a malicious hallucinated package is found, we build a rule for it within days."


Section 3: Next Steps (~5 min)
90-Day Plan with $400K and SPC Support
✅ Milestone 1 (Month 1): Distribution & Integration

Get listed on the official MCP registry
Partner with 2-3 AI coding tool vendors for default/recommended integration
Target: 10,000+ active installations
Why first: Distribution determines everything — a security tool nobody uses protects nothing

✅ Milestone 2 (Month 2): Enterprise MVP

Launch team dashboard with scan history and policy controls
Add CI/CD pipeline integration (GitHub Actions, GitLab CI)
Target: 3 enterprise design partners with signed LOIs
Why second: Enterprise signal validates the revenue model

✅ Milestone 3 (Month 3): Coverage Expansion

Expand rule library from 275+ to 500+ rules
Add runtime scanning (not just static analysis)
Launch package hallucination detection for 2 additional ecosystems
Target: measurable reduction in time-to-close for design partner deals


Key Assumptions That Could Kill the Business
✅ Assumption 1: Developers will adopt security middleware for AI agents

Test: Track conversion from npm install to active weekly usage. If <5% of installs become active users in 90 days, the friction is too high.
What would change our mind: If developers consistently disable security scanning because it slows their workflow. Then we'd need to move to async/background scanning.

✅ Assumption 2: MCP will remain the dominant protocol for agent tools

Test: Monitor protocol adoption metrics (currently 97M monthly SDK downloads). Track whether major vendors (OpenAI, Google, Microsoft) continue investing.
What would change our mind: If a competing protocol gains >30% market share, we'd need to become protocol-agnostic faster.

✅ Assumption 3: Enterprises will pay for agent security as a separate product (not just expect it from their existing SAST vendor)

Test: LOIs and willingness-to-pay signals from design partners. If 3 out of 5 say "we'd just wait for Snyk to add this," we have a positioning problem.
What would change our mind: If incumbents ship competitive agent-native features within 6 months, we'd need to accelerate or pivot to OEM/embed strategy.


Why SPC Specifically
"Three things we need beyond capital:

Deeply tech community who can be early users / user feedback  — SPC's network includes founders building in adjacent spaces (developer tools, security, infrastructure). We need warm intros to enterprise CISOs and design partners, not cold outreach.

Go-to-market mentorship — We're three deeply technical founders. Our biggest growth area is translating open-source adoption into enterprise revenue. SPC's experience with open-source → commercial transitions is exactly what we need.



Why Not Now (Without Funding)
"We've built everything so far — the npm package, 275+ rules, 4.3M package verification, MCP integration with every major AI coding client. But we're hitting a ceiling:

Time — Enterprise conversations require availability we don't have as full-time employees
Speed — Competitors (Inkog, agent-audit, Enkrypt) are emerging. First-mover advantage is measured in months, not years
Enterprise requirements — SOC 2 compliance, team features, and SLAs require dedicated engineering time

The plan is already in motion. Funding accelerates it from '12-month timeline' to '90-day timeline.'"


SPC Evaluation Framework — Signal Mapping
"Velocity" Signals (We've Done This Before)
✅ Bias for building:

Live npm package with 275+ rules, 6 MCP tools, 4.3M packages indexed
Works with every major AI coding client (Claude Code, Cursor, Windsurf, Cline)
Divya: Founded and built Garak Security (commercial enterprise AI security platform), previously shipped Google Safe Browsing phishing detection to 1B+ users
Anit: Published 10+ peer-reviewed papers, productionized federated learning at Amazon scale
Dheeraj: Built production AI infrastructure at Albertsons, published agent accuracy research

✅ Leadership experience:

Divya: Founding CTO at Garak Security (backed by Open Core Ventures), previously founding CTO at Redbolt AI ($2M funded)
Anit: Tech lead at Amazon Alexa AI, team lead at Bosch Research
Dheeraj: Staff-level engineer leading data architecture at Albertsons

✅ Domain expertise:

Divya: PhD (UC Davis), 4.5 years at Google on Chrome security, Akamai bot detection, NVIDIA Garak contributor
Anit: PhD (CMU), published adversarial attack research (KDD), federated learning (MLSys, IEEE), currently building agent guardrails at Oracle Health AI
Dheeraj: 8+ years data engineering, agent accuracy research, real-time AI infrastructure
"Acceleration" Signals (Upside Potential)
✅ Risk tolerance:

Divya left Google to start Sinewave AI, then Garak Security — serial founder who keeps jumping into frontier problems
Anit is leaving a senior research scientist role at Oracle to go full-time on ProofLayer — walking away from big-company stability
All three are betting on a category that doesn't officially exist yet

✅ Curiosity:

We killed three approaches (dashboard, multi-vertical, custom engine) based on customer signal, not ego
We monitor the threat landscape daily and ship rules within days of new attack discoveries

✅ Emotional intelligence:

Clear role division with zero overlap anxiety
Each founder can articulate what the others bring better than themselves
Practiced smooth handoffs — no talking over each other

✅ Ambition:

This is a 10-year commitment. The agent security market is $30B today, $322B by 2033
We're not building a feature — we're building the category-defining security infrastructure for agentic AI
Snyk built an $8.5B company securing human code. We're building the equivalent for AI-generated code.


Quick Reminders
Do
Be concise — you have ~5 min per section
Use concrete examples over abstract claims
Show you've built things (the npm scanner is gold)
Be authentic about uncertainty — they fund founders, not perfect plans
Ask a thoughtful question if time permits
Don't
Recite LinkedIn bios chronologically
Oversell traction you don't have
Let one person dominate the conversation
Get defensive about hard questions
Forget to show curiosity about SPC itself


Mock Interview — Rehearsed Answers
"Tell us about your team in 90 seconds — not your resumes, but why you work."

Divya: "We're three people who've been independently fighting AI security problems and finally built the thing together. I spent 4.5 years at Google protecting a billion Chrome users from phishing, then commercialized NVIDIA's Garak red-teaming framework. Anit literally wrote the papers on adversarial attacks and federated learning at CMU, Amazon, and Bosch — and now he's building agent guardrails at Oracle Health. Dheeraj builds production AI infrastructure at scale and has published on making AI agents actually reliable. We work because we each see the agent security problem from a different angle — attack research, defense engineering, and production systems — and ProofLayer is where all three converge."

"What's the scariest question a customer could ask you right now?"

"How do you handle zero-day vulnerabilities in real-time? Our current approach is rule-based — we catch known patterns. If an attacker discovers a fundamentally new class of agent manipulation, our rules won't catch it until we update. That's why runtime behavioral monitoring is Milestone 3 in our 90-day plan — we need to move from pattern-matching to anomaly detection."

"Walk us through an idea you killed and why."

"We initially planned to cover chat agents, voice agents, and code agents simultaneously. We killed it within two weeks of customer conversations. Enterprise security teams told us: 'We don't care about chatbot security — we care that our AI coding agent just introduced 47 SQL injection vulnerabilities into production.' Code agents have the clearest buyer, the largest market, and the most concrete consequences. We went all-in on code."

"If we funded you tomorrow, what's the first thing you'd do on Monday?"

"Tuesday, we apply for MCP registry listing. Wednesday, we start reaching out to the 5 enterprise design partners we've already identified. By end of week one, we have a sprint plan for the enterprise dashboard MVP."

"Why will you win against a well-funded incumbent?"

"Because incumbents have to retrofit agent security onto architectures built for human developers. Snyk's entire product assumes a human commits code to a repo and runs a scan. We're built MCP-native — our tool is a capability the agent calls, not a separate step. That architectural difference is our moat. It's the same reason Datadog beat the monitoring incumbents — they were cloud-native while everyone else was trying to port legacy tools to the cloud."


Pre-Interview Checklist (Day Of)
Test video/audio setup 15 min early
Have ProofLayer demo ready to share screen if asked
Keep the website open for quick reference
Mute notifications
Have water nearby
Designate who speaks first:
Section 1 (Team): Divya opens, tags Anit and Dheeraj
Section 2 (Ideation): Divya pitches, Anit goes deep on tech, Dheeraj on product
Section 3 (Next Steps): Divya opens with 90-day plan, Dheeraj on milestones, Anit on research agenda


Key Stats to Memorize
Stat
Number
AI-generated code with vulnerabilities
62%
New security findings/month from AI code
10,000+ (10x spike)
Orgs using AI coding assistants
85%
Global code that is AI-generated
41%
Agentic AI Security market (2025)
$30.27B
Projected market (2033)
$322B (34.4% CAGR)
MCP monthly SDK downloads
97M
Cursor ARR
$500M
Snyk valuation
$8.5B
Semgrep raised
$204M
Lakera raised
$30M
Our rules
275+
Our package database
4.3M packages
Our auto-fix templates
105



