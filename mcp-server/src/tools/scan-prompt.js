// src/tools/scan-prompt.js
import { z } from "zod";
import { readFileSync, existsSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { createHash } from "crypto";

// Handle both ESM and CJS bundling
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

// Risk thresholds for action determination
const RISK_THRESHOLDS = {
  CRITICAL: 85,
  HIGH: 65,
  MEDIUM: 40,
  LOW: 20
};

// Category weights for risk calculation
const CATEGORY_WEIGHTS = {
  "exfiltration": 1.0,
  "malicious-injection": 1.0,
  "system-manipulation": 1.0,
  "social-engineering": 0.8,
  "obfuscation": 0.7,
  "agent-manipulation": 0.9,
  "prompt-injection": 0.9,
  "prompt-injection-content": 1.0,
  "prompt-injection-jailbreak": 1.0,
  "prompt-injection-extraction": 0.9,
  "prompt-injection-delimiter": 0.8,
  "prompt-injection-encoded": 0.9,
  "prompt-injection-context": 0.8,
  "prompt-injection-privilege": 0.85,
  "prompt-injection-multi-turn": 0.7,
  "prompt-injection-output": 0.9,
  "unknown": 0.5
};

// Confidence multipliers
const CONFIDENCE_MULTIPLIERS = {
  "HIGH": 1.0,
  "MEDIUM": 0.7,
  "LOW": 0.4
};

// Load agent attack rules from YAML
function loadAgentAttackRules() {
  try {
    const rulesPath = join(__dirname, '..', '..', 'rules', 'agent-attacks.security.yaml');
    if (!existsSync(rulesPath)) {
      console.error("Agent attack rules file not found");
      return [];
    }

    const yaml = readFileSync(rulesPath, 'utf-8');
    const rules = [];

    // Simple YAML parsing for rules
    const ruleBlocks = yaml.split(/^  - id:/m).slice(1);

    for (const block of ruleBlocks) {
      const lines = ('  - id:' + block).split('\n');
      const rule = {
        id: '',
        severity: 'WARNING',
        message: '',
        patterns: [],
        metadata: {}
      };

      let inPatterns = false;
      let inMetadata = false;

      for (const line of lines) {
        if (line.match(/^\s+- id:\s*/)) {
          rule.id = line.replace(/^\s+- id:\s*/, '').trim();
        } else if (line.match(/^\s+severity:\s*/)) {
          rule.severity = line.replace(/^\s+severity:\s*/, '').trim();
        } else if (line.match(/^\s+message:\s*/)) {
          rule.message = line.replace(/^\s+message:\s*["']?/, '').replace(/["']$/, '').trim();
        } else if (line.match(/^\s+patterns:\s*$/)) {
          inPatterns = true;
          inMetadata = false;
        } else if (line.match(/^\s+metadata:\s*$/)) {
          inPatterns = false;
          inMetadata = true;
        } else if (inPatterns && line.match(/^\s+- /)) {
          let pattern = line.replace(/^\s+- /, '').trim();
          pattern = pattern.replace(/^["']|["']$/g, '');
          // Strip Python-style inline flags - JS doesn't support them
          pattern = pattern.replace(/^\(\?i\)/, '');
          // Unescape double backslashes from YAML (\\s -> \s)
          pattern = pattern.replace(/\\\\/g, '\\');
          if (pattern) rule.patterns.push(pattern);
        } else if (inMetadata && line.match(/^\s+\w+:/)) {
          const match = line.match(/^\s+(\w+):\s*["']?([^"'\n]+)["']?/);
          if (match) {
            rule.metadata[match[1]] = match[2].trim();
          }
        } else if (line.match(/^\s+languages:/)) {
          inPatterns = false;
          inMetadata = false;
        }
      }

      if (rule.id && rule.patterns.length > 0) {
        rules.push(rule);
      }
    }

    return rules;
  } catch (error) {
    console.error("Error loading agent attack rules:", error.message);
    return [];
  }
}

// Also load prompt injection rules
function loadPromptInjectionRules() {
  try {
    const rulesPath = join(__dirname, '..', '..', 'rules', 'prompt-injection.security.yaml');
    if (!existsSync(rulesPath)) {
      return [];
    }

    const yaml = readFileSync(rulesPath, 'utf-8');
    const rules = [];

    const ruleBlocks = yaml.split(/^  - id:/m).slice(1);

    for (const block of ruleBlocks) {
      const lines = ('  - id:' + block).split('\n');
      const rule = {
        id: '',
        severity: 'WARNING',
        message: '',
        patterns: [],
        metadata: {}
      };

      let inPatterns = false;
      let inMetadata = false;

      for (const line of lines) {
        if (line.match(/^\s+- id:\s*/)) {
          rule.id = line.replace(/^\s+- id:\s*/, '').trim();
        } else if (line.match(/^\s+severity:\s*/)) {
          rule.severity = line.replace(/^\s+severity:\s*/, '').trim();
        } else if (line.match(/^\s+message:\s*/)) {
          rule.message = line.replace(/^\s+message:\s*["']?/, '').replace(/["']$/, '').trim();
        } else if (line.match(/^\s+patterns:\s*$/)) {
          inPatterns = true;
          inMetadata = false;
        } else if (line.match(/^\s+metadata:\s*$/)) {
          inPatterns = false;
          inMetadata = true;
        } else if (inPatterns && line.match(/^\s+- /)) {
          let pattern = line.replace(/^\s+- /, '').trim();
          pattern = pattern.replace(/^["']|["']$/g, '');
          // Strip Python-style inline flags - JS doesn't support them
          pattern = pattern.replace(/^\(\?i\)/, '');
          // Unescape double backslashes from YAML (\\s -> \s)
          pattern = pattern.replace(/\\\\/g, '\\');
          if (pattern) rule.patterns.push(pattern);
        } else if (inMetadata && line.match(/^\s+\w+:/)) {
          const match = line.match(/^\s+(\w+):\s*["']?([^"'\n]+)["']?/);
          if (match) {
            rule.metadata[match[1]] = match[2].trim();
          }
        }
      }

      // Only include generic rules (content patterns, not code patterns)
      if (rule.id && rule.patterns.length > 0 && rule.id.startsWith('generic.prompt')) {
        rules.push(rule);
      }
    }

    return rules;
  } catch (error) {
    console.error("Error loading prompt injection rules:", error.message);
    return [];
  }
}

// Calculate risk score from findings
function calculateRiskScore(findings, context) {
  if (findings.length === 0) return 0;

  let totalScore = 0;

  for (const finding of findings) {
    const riskScore = parseInt(finding.risk_score) || 50;
    const category = finding.category || 'unknown';
    const confidence = finding.confidence || 'MEDIUM';

    const categoryWeight = CATEGORY_WEIGHTS[category] || 0.5;
    const confidenceMultiplier = CONFIDENCE_MULTIPLIERS[confidence] || 0.7;

    totalScore += (riskScore / 100) * categoryWeight * confidenceMultiplier * 100;
  }

  // Average the scores but boost for multiple findings
  let avgScore = totalScore / findings.length;

  // Enhanced compound boosting
  if (findings.length > 1) {
    // Cross-category boost: if findings span multiple categories, boost by 0.15
    const uniqueCategories = new Set(findings.map(f => f.category || 'unknown'));
    if (uniqueCategories.size > 1) {
      avgScore = avgScore * (1 + 0.15);
    }

    // Mixed-severity boost: if both ERROR and WARNING present, 1.1x
    const hasError = findings.some(f => f.severity === 'ERROR');
    const hasWarning = findings.some(f => f.severity === 'WARNING');
    if (hasError && hasWarning) {
      avgScore = avgScore * 1.1;
    }

    // Per-finding boost (smaller than before)
    avgScore = avgScore * (1 + (findings.length - 1) * 0.05);
  }

  avgScore = Math.min(100, avgScore);

  // Apply sensitivity adjustment (wider spread for meaningful impact)
  if (context?.sensitivity_level === 'high') {
    avgScore = Math.min(100, avgScore * 1.5);
  } else if (context?.sensitivity_level === 'low') {
    avgScore = avgScore * 0.5;
  }

  return Math.round(avgScore);
}

// Determine action based on risk score, findings, and context
function determineAction(riskScore, findings, context) {
  // Adjust thresholds based on sensitivity level
  let blockThreshold = RISK_THRESHOLDS.HIGH;
  let warnThreshold = RISK_THRESHOLDS.MEDIUM;
  let logThreshold = RISK_THRESHOLDS.LOW;

  if (context?.sensitivity_level === 'high') {
    blockThreshold = 50;
    warnThreshold = 30;
    logThreshold = 15;
  } else if (context?.sensitivity_level === 'low') {
    blockThreshold = 75;
    warnThreshold = 50;
    logThreshold = 30;
  }

  // Check for any BLOCK action findings
  const hasBlockFinding = findings.some(f => f.action === 'BLOCK');
  if (hasBlockFinding || riskScore >= RISK_THRESHOLDS.CRITICAL) {
    return 'BLOCK';
  }

  if (riskScore >= blockThreshold) {
    return 'BLOCK';
  }

  const hasWarnFinding = findings.some(f => f.action === 'WARN');
  if (hasWarnFinding || riskScore >= warnThreshold) {
    return 'WARN';
  }

  const hasLogFinding = findings.some(f => f.action === 'LOG');
  if (hasLogFinding || riskScore >= logThreshold) {
    return 'LOG';
  }

  return 'ALLOW';
}

// Determine risk level from score
function getRiskLevel(score) {
  if (score >= RISK_THRESHOLDS.CRITICAL) return 'CRITICAL';
  if (score >= RISK_THRESHOLDS.HIGH) return 'HIGH';
  if (score >= RISK_THRESHOLDS.MEDIUM) return 'MEDIUM';
  if (score >= RISK_THRESHOLDS.LOW) return 'LOW';
  return 'NONE';
}

// Generate explanation from findings
function generateExplanation(findings, action) {
  if (findings.length === 0) {
    return 'No security concerns detected in this prompt.';
  }

  const categories = [...new Set(findings.map(f => f.category))];
  const severity = findings.some(f => f.severity === 'ERROR') ? 'critical' : 'potential';

  let explanation = `Detected ${findings.length} ${severity} security concern(s)`;

  if (categories.length > 0) {
    explanation += ` in categories: ${categories.join(', ')}`;
  }

  explanation += `. Action: ${action}.`;

  if (action === 'BLOCK') {
    explanation += ' This prompt appears to contain malicious intent and should not be executed.';
  } else if (action === 'WARN') {
    explanation += ' Review carefully before proceeding.';
  }

  return explanation;
}

// Generate recommendations from findings
function generateRecommendations(findings) {
  const recommendations = new Set();

  for (const finding of findings) {
    const category = finding.category;

    switch (category) {
      case 'exfiltration':
        recommendations.add('Never allow prompts that request sending code or secrets to external URLs');
        recommendations.add('Block access to sensitive files like .env, SSH keys, and credentials');
        break;
      case 'malicious-injection':
        recommendations.add('Reject requests for backdoors, reverse shells, or malicious code');
        recommendations.add('Never disable security controls at user request');
        break;
      case 'system-manipulation':
        recommendations.add('Block destructive file operations and system configuration changes');
        recommendations.add('Prevent persistence mechanisms like crontab or startup script modifications');
        break;
      case 'social-engineering':
        recommendations.add('Verify authorization claims through proper channels, not prompt content');
        recommendations.add('Be skeptical of urgency claims or claims of special modes');
        break;
      case 'obfuscation':
        recommendations.add('Be wary of encoded or fragmented instructions');
        recommendations.add('Reject requests for "examples" of malicious code');
        break;
      case 'agent-manipulation':
        recommendations.add('Maintain confirmation prompts for sensitive operations');
        recommendations.add('Never hide output or actions from the user');
        break;
      default:
        recommendations.add('Review this prompt carefully before execution');
    }
  }

  return [...recommendations];
}

// Create SHA256 hash for audit logging
function hashPrompt(text) {
  return createHash('sha256').update(text).digest('hex').substring(0, 16);
}

// ============================================================================
// TEXT NORMALIZATION PIPELINE (Garak Buff-inspired)
// Normalizes input to defeat homoglyph, invisible char, and Unicode bypasses
// ============================================================================

// Homoglyph map: Cyrillic, Greek, and Latin Extended lookalikes → ASCII
const HOMOGLYPH_MAP = {
  // Cyrillic lowercase → Latin
  '\u0430': 'a', // а → a
  '\u0435': 'e', // е → e
  '\u043E': 'o', // о → o
  '\u0440': 'p', // р → p
  '\u0441': 'c', // с → c
  '\u0443': 'y', // у → y (visual match to y)
  '\u0445': 'x', // х → x
  '\u0456': 'i', // і → i
  '\u04BB': 'h', // һ → h
  '\u0455': 's', // ѕ → s
  '\u0458': 'j', // ј → j
  '\u043D': 'n', // н → n (Cyrillic en looks like n in some fonts)
  // Cyrillic uppercase → Latin
  '\u0410': 'A', // А → A
  '\u0412': 'B', // В → B
  '\u0415': 'E', // Е → E
  '\u041A': 'K', // К → K
  '\u041C': 'M', // М → M
  '\u041D': 'H', // Н → H
  '\u041E': 'O', // О → O
  '\u0420': 'P', // Р → P
  '\u0421': 'C', // С → C
  '\u0422': 'T', // Т → T
  '\u0425': 'X', // Х → X
  '\u0406': 'I', // І → I
  // Greek lowercase → Latin
  '\u03B1': 'a', // α → a
  '\u03B5': 'e', // ε → e
  '\u03BF': 'o', // ο → o
  '\u03C1': 'p', // ρ → p
  '\u03BA': 'k', // κ → k
  '\u03BD': 'v', // ν → v
  // Greek uppercase → Latin
  '\u0391': 'A', // Α → A
  '\u0392': 'B', // Β → B
  '\u0395': 'E', // Ε → E
  '\u0397': 'H', // Η → H
  '\u0399': 'I', // Ι → I
  '\u039A': 'K', // Κ → K
  '\u039C': 'M', // Μ → M
  '\u039D': 'N', // Ν → N
  '\u039F': 'O', // Ο → O
  '\u03A1': 'P', // Ρ → P
  '\u03A4': 'T', // Τ → T
  '\u03A7': 'X', // Χ → X
  '\u03A5': 'Y', // Υ → Y
  '\u0396': 'Z', // Ζ → Z
};

// Invisible/zero-width characters to strip (regex)
// Includes: soft hyphen, combining grapheme joiner, Arabic letter mark,
// hangul fillers, Mongolian vowel separator, zero-width chars,
// directional markers, word joiners, BOM, halfwidth hangul filler
const INVISIBLE_CHAR_REGEX = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\u3164\uFEFF\uFFA0]/gu;

// Zalgo combining diacritical marks to strip
const ZALGO_REGEX = /[\u0300-\u036F\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]/g;

// Unicode tag characters (U+E0000-U+E007F) - used in invisible ASCII tag attacks
// These are encoded as surrogate pairs in JS, so we use a broader regex
const TAG_CHAR_REGEX = /[\uE0000-\uE007F]/gu;

function normalizeText(text) {
  // Step 1: NFKC normalization
  // Decomposes then recomposes in compatibility form
  // Handles: fullwidth chars (ｉｇｎｏｒｅ → ignore), ligatures (ﬁ → fi),
  //          superscripts, subscripts, circle-enclosed chars
  let normalized = text.normalize('NFKC');

  // Step 2: Strip invisible Unicode characters
  normalized = normalized.replace(INVISIBLE_CHAR_REGEX, '');

  // Step 3: Strip Unicode tag characters
  normalized = normalized.replace(TAG_CHAR_REGEX, '');

  // Step 4: Strip Zalgo combining diacritical marks
  normalized = normalized.replace(ZALGO_REGEX, '');

  // Step 5: Homoglyph canonicalization
  // Replace each character through the map; unmapped chars pass through
  normalized = normalized.split('').map(ch => HOMOGLYPH_MAP[ch] || ch).join('');

  // Step 6: Normalize Unicode whitespace to ASCII space
  // Includes: NBSP, en/em space, thin space, hair space, ideographic space, etc.
  normalized = normalized.replace(/[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/g, ' ');

  return normalized;
}

// Extract content from all code block delimiter formats
// Inspired by Garak latentinjection probes: attacks hide in document structures
function extractCodeBlockContent(text) {
  const extracted = [];
  let match;

  // 1. Triple-backtick blocks (existing) — ```code```
  const backtickRegex = /```[\s\S]*?```/g;
  for (const block of (text.match(backtickRegex) || [])) {
    extracted.push(block.replace(/^```\w*\n?/, '').replace(/\n?```$/, ''));
  }

  // 2. Triple-tilde blocks — ~~~code~~~
  const tildeRegex = /~~~[\s\S]*?~~~/g;
  for (const block of (text.match(tildeRegex) || [])) {
    extracted.push(block.replace(/^~~~\w*\n?/, '').replace(/\n?~~~$/, ''));
  }

  // 3. HTML <code> tags — <code>content</code>
  const codeTagRegex = /<code[^>]*>([\s\S]*?)<\/code>/gi;
  while ((match = codeTagRegex.exec(text)) !== null) {
    extracted.push(match[1]);
  }

  // 4. HTML <pre> tags — <pre>content</pre>
  const preTagRegex = /<pre[^>]*>([\s\S]*?)<\/pre>/gi;
  while ((match = preTagRegex.exec(text)) !== null) {
    extracted.push(match[1]);
  }

  // 5. HTML comments — <!-- content -->
  const htmlCommentRegex = /<!--([\s\S]*?)-->/g;
  while ((match = htmlCommentRegex.exec(text)) !== null) {
    extracted.push(match[1]);
  }

  // 6. CDATA sections — <![CDATA[ content ]]>
  const cdataRegex = /<!\[CDATA\[([\s\S]*?)\]\]>/g;
  while ((match = cdataRegex.exec(text)) !== null) {
    extracted.push(match[1]);
  }

  return extracted;
}

// Collapse string concatenation to defeat fragmentation attacks
// Inspired by PromptFoo's "token smuggling" and "payload splitting" attack classes
function collapseConcatenations(text) {
  let collapsed = text;

  // Join JS/Python string concatenation: "foo" + "bar" → foobar
  // Handles double quotes, single quotes, backticks
  // The pattern: closing-quote, optional whitespace, +, optional whitespace, opening-quote
  collapsed = collapsed.replace(/["'`]\s*\+\s*["'`]/g, '');

  // Join multiline concatenation (newlines between concat operators)
  collapsed = collapsed.replace(/["'`]\s*\n\s*\+\s*["'`]/g, '');
  collapsed = collapsed.replace(/["'`]\s*\+\s*\n\s*["'`]/g, '');

  // Strip C-style inline comments used as fragment separators: ign/**/ore → ignore
  collapsed = collapsed.replace(/\/\*.*?\*\//g, '');

  return collapsed;
}

// Rescan decoded content against all rules
// Used by the decode cascade for each encoding type
function rescanDecoded(decodedText, allRules, findings, encodingLabel) {
  const normalized = normalizeText(decodedText);
  for (const rule of allRules) {
    for (const pattern of rule.patterns) {
      try {
        const regex = new RegExp(pattern, 'i');
        const match = normalized.match(regex);
        if (match) {
          findings.push({
            rule_id: rule.id + '.' + encodingLabel + '-decoded',
            category: rule.metadata.category || 'obfuscation',
            severity: rule.severity,
            message: rule.message + ` (detected in ${encodingLabel}-decoded content)`,
            matched_text: match[0].substring(0, 100),
            confidence: rule.metadata.confidence || 'MEDIUM',
            risk_score: rule.metadata.risk_score || '50',
            action: rule.metadata.action || 'WARN'
          });
          break; // One match per rule
        }
      } catch (e) {
        // Skip invalid regex
      }
    }
  }
}

// Helper: check if decoded string is mostly printable ASCII
function isPrintable(str, threshold) {
  if (!str || str.length === 0) return false;
  const printable = str.split('').filter(c => {
    const code = c.charCodeAt(0);
    return code >= 32 && code <= 126;
  }).length;
  return printable / str.length > threshold;
}

// Multi-encoding decode cascade
// Inspired by Garak's 12+ encoding probes (InjectBase64, InjectHex, InjectROT13, etc.)
// and PromptFoo's static encoding strategies
function tryDecodeAndRescan(expandedText, allRules, findings) {
  // --- 1. Base64 (improved: lower length threshold 40→20, lower printability 0.7→0.55) ---
  const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
  for (const b64str of (expandedText.match(base64Regex) || [])) {
    try {
      const decoded = Buffer.from(b64str, 'base64').toString('utf-8');
      if (decoded.length > 0 && isPrintable(decoded, 0.55)) {
        rescanDecoded(decoded, allRules, findings, 'base64');

        // --- 1b. Nested base64: decode again if inner content is also base64 ---
        const nestedB64 = decoded.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || [];
        for (const nested of nestedB64) {
          try {
            const twice = Buffer.from(nested, 'base64').toString('utf-8');
            if (twice.length > 4 && isPrintable(twice, 0.55)) {
              rescanDecoded(twice, allRules, findings, 'base64-nested');
            }
          } catch (e) { /* skip */ }
        }
      }
    } catch (e) { /* skip invalid base64 */ }
  }

  // --- 2. Hex encoding: sequences of hex pairs (optionally space-separated) ---
  // Matches: "69676e6f7265" or "69 67 6e 6f 72 65"
  const hexRegex = /(?:[0-9a-fA-F]{2}[\s]?){8,}/g;
  for (const hexStr of (expandedText.match(hexRegex) || [])) {
    try {
      const clean = hexStr.replace(/\s/g, '');
      if (clean.length % 2 !== 0) continue;
      if (clean.length < 16) continue; // At least 8 bytes
      const decoded = Buffer.from(clean, 'hex').toString('utf-8');
      if (decoded.length > 4 && isPrintable(decoded, 0.7)) {
        rescanDecoded(decoded, allRules, findings, 'hex');
      }
    } catch (e) { /* skip */ }
  }

  // --- 3. URL encoding: %XX sequences (at least 3 encoded chars) ---
  if (expandedText.includes('%') && /(%[0-9a-fA-F]{2}){3,}/.test(expandedText)) {
    try {
      const decoded = decodeURIComponent(expandedText);
      if (decoded !== expandedText) {
        rescanDecoded(decoded, allRules, findings, 'url-encoded');
      }
    } catch (e) { /* skip malformed URL encoding */ }
  }

  // --- 4. ROT13: only when indicators present (user-approved decision) ---
  // This avoids false positives from ROT13-decoding normal text
  const rot13Indicators = /\b(rot13|rot-13|caesar|cipher|decode\s+this|decipher)\b/i;
  if (rot13Indicators.test(expandedText)) {
    const rot13Decoded = expandedText.replace(/[a-zA-Z]/g, ch => {
      const base = ch <= 'Z' ? 65 : 97;
      return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
    });
    if (rot13Decoded !== expandedText) {
      rescanDecoded(rot13Decoded, allRules, findings, 'rot13');
    }
  }
}

// Frame-setting patterns: conversational priming for later exploitation
// Inspired by PromptFoo's Crescendo strategy (Microsoft research)
const FRAME_SETTING_PATTERNS = [
  /remember\s+(this|that)\s+for\s+later/i,
  /in\s+my\s+next\s+message/i,
  /when\s+i\s+(say|ask|tell)\s+you/i,
  /from\s+now\s+on\s*,?\s+(you|your)\s+(will|must|should|are)/i,
  /starting\s+now\s*,?\s+you/i,
  /keep\s+this\s+in\s+mind/i,
  /for\s+the\s+(rest|remainder)\s+of\s+(this|our)\s+conversation/i,
  /act\s+as\s+(if|though)\s+you\s+(are|have)/i,
  /let'?s\s+play\s+a\s+(game|role)/i,
  /pretend\s+that\s+you\s+(are|have)/i,
  /in\s+all\s+(future|subsequent)\s+(messages?|responses?)/i,
  /always\s+respond\s+(by|with|as)/i,
];

// Improved multi-turn escalation detection
// Fixes: removes "current turn must have findings" requirement,
// adds cross-turn concatenation, frame-setting detection, full accumulation
function detectMultiTurnEscalation(previousMessages, currentText, allRules) {
  const escalationFindings = [];

  if (!previousMessages || !Array.isArray(previousMessages) || previousMessages.length === 0) {
    return escalationFindings;
  }

  // Step 1: Scan ALL previous messages, accumulate total matches (no early break)
  let totalPrevMatches = 0;
  let frameSettingCount = 0;
  const prevMatchedRuleIds = new Set();

  for (const prevMsg of previousMessages) {
    const normalizedPrev = normalizeText(prevMsg);

    // Check frame-setting patterns
    for (const fp of FRAME_SETTING_PATTERNS) {
      if (fp.test(normalizedPrev)) {
        frameSettingCount++;
        break; // One frame-setting match per message is enough
      }
    }

    // Check all rules against this previous message
    for (const rule of allRules) {
      if (prevMatchedRuleIds.has(rule.id)) continue; // Already matched this rule
      for (const pattern of rule.patterns) {
        try {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(normalizedPrev)) {
            totalPrevMatches++;
            prevMatchedRuleIds.add(rule.id);
            break; // One match per rule per message
          }
        } catch (e) { /* skip invalid regex */ }
      }
    }
  }

  // Step 2: Cross-turn concatenation scan
  // Join ALL messages into a single string and scan for patterns that span boundaries
  // This catches: prev="ignore all" + current="previous instructions"
  const crossTurnText = normalizeText([...previousMessages, currentText].join(' '));

  for (const rule of allRules) {
    for (const pattern of rule.patterns) {
      try {
        const regex = new RegExp(pattern, 'i');
        const match = crossTurnText.match(regex);
        if (match) {
          // Only flag if this match does NOT appear in any single message alone
          const matchInCurrent = regex.test(normalizeText(currentText));
          const matchInAnyPrev = previousMessages.some(pm => regex.test(normalizeText(pm)));
          if (!matchInCurrent && !matchInAnyPrev) {
            // Pattern only matches when messages are joined — it spans boundaries
            escalationFindings.push({
              rule_id: rule.id + '.cross-turn',
              category: rule.metadata.category || 'prompt-injection-multi-turn',
              severity: 'WARNING',
              message: `Cross-turn prompt injection: attack pattern spans message boundaries`,
              matched_text: match[0].substring(0, 100),
              confidence: 'MEDIUM',
              risk_score: '75',
              action: 'WARN'
            });
            break;
          }
        }
      } catch (e) { /* skip */ }
    }
  }

  // Step 3: Frame-setting detection — flag even without current findings
  if (frameSettingCount > 0) {
    escalationFindings.push({
      rule_id: 'multi-turn.frame-setting',
      category: 'prompt-injection-multi-turn',
      severity: 'WARNING',
      message: `Frame-setting language detected in ${frameSettingCount} previous message(s). Possible Crescendo-style gradual escalation attack.`,
      matched_text: 'frame-setting phrases in conversation history',
      confidence: 'LOW',
      risk_score: '55',
      action: 'LOG'
    });
  }

  // Step 4: Escalation detection — REMOVED requirement that current turn has findings
  // KEY FIX: An attacker's final "trigger" message may be benign ("yes, do it")
  if (totalPrevMatches > 0) {
    escalationFindings.push({
      rule_id: 'multi-turn.escalation',
      category: 'social-engineering',
      severity: 'WARNING',
      message: `Multi-turn escalation: suspicious patterns in ${totalPrevMatches} previous rule(s). Current message may be a benign trigger.`,
      matched_text: 'escalation across conversation turns',
      confidence: totalPrevMatches >= 3 ? 'HIGH' : 'MEDIUM',
      risk_score: String(Math.min(85, 50 + totalPrevMatches * 5)),
      action: totalPrevMatches >= 3 ? 'WARN' : 'LOG'
    });
  }

  return escalationFindings;
}

// Export schema for tool registration
export const scanAgentPromptSchema = {
  prompt_text: z.string().describe("The prompt or instruction text to analyze"),
  context: z.object({
    previous_messages: z.array(z.string()).optional().describe("Previous conversation messages for multi-turn detection"),
    sensitivity_level: z.enum(["high", "medium", "low"]).optional().describe("Sensitivity level - high means more strict, low means more permissive")
  }).optional().describe("Optional context for better analysis"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level: 'minimal' (action only), 'compact' (default), 'full' (all details)")
};

// Export handler function
export async function scanAgentPrompt({ prompt_text, context, verbosity }) {
  const findings = [];

  // Normalize prompt text (Garak Buff-inspired preprocessing)
  const normalizedPrompt = normalizeText(prompt_text);

  // Detect invisible Unicode characters in original text (obfuscation indicator)
  const invisibleMatches = prompt_text.match(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uE0000-\uE007F]/gu);
  if (invisibleMatches && invisibleMatches.length > 0) {
    findings.push({
      rule_id: 'runtime.invisible-unicode-detected',
      category: 'obfuscation',
      severity: 'WARNING',
      message: `Invisible Unicode characters detected (${invisibleMatches.length} chars). These may hide malicious instructions from human review.`,
      matched_text: `${invisibleMatches.length} invisible character(s) found`,
      confidence: 'HIGH',
      risk_score: '70',
      action: 'WARN'
    });
  }

  // Load rules
  const agentRules = loadAgentAttackRules();
  const promptRules = loadPromptInjectionRules();
  const allRules = [...agentRules, ...promptRules];

  // Extract content from all code block formats and append to scan text
  let expandedText = normalizedPrompt;
  for (const inner of extractCodeBlockContent(normalizedPrompt)) {
    expandedText += '\n' + inner;
  }

  // Collapse string concatenations to defeat fragmentation (Bypass #2)
  const collapsedText = collapseConcatenations(expandedText);
  if (collapsedText !== expandedText) {
    expandedText += '\n' + collapsedText;
  }

  // Scan expanded text against all rules
  for (const rule of allRules) {
    for (const pattern of rule.patterns) {
      try {
        const regex = new RegExp(pattern, 'i');
        const match = expandedText.match(regex);

        if (match) {
          findings.push({
            rule_id: rule.id,
            category: rule.metadata.category || 'unknown',
            severity: rule.severity,
            message: rule.message,
            matched_text: match[0].substring(0, 100),
            confidence: rule.metadata.confidence || 'MEDIUM',
            risk_score: rule.metadata.risk_score || '50',
            action: rule.metadata.action || 'WARN'
          });
          break; // Only one match per rule
        }
      } catch (e) {
        // Skip invalid regex
      }
    }
  }

  // Multi-encoding decode cascade (replaces base64-only block)
  tryDecodeAndRescan(expandedText, allRules, findings);

  // Improved multi-turn escalation detection (Bypass #4 fix)
  if (context?.previous_messages && Array.isArray(context.previous_messages)) {
    const multiTurnFindings = detectMultiTurnEscalation(
      context.previous_messages,
      normalizedPrompt,
      allRules
    );
    findings.push(...multiTurnFindings);
  }

  // Calculate risk score
  const riskScore = calculateRiskScore(findings, context);
  const action = determineAction(riskScore, findings, context);
  const riskLevel = getRiskLevel(riskScore);
  const explanation = generateExplanation(findings, action);
  const recommendations = generateRecommendations(findings);

  // Create audit info
  const audit = {
    timestamp: new Date().toISOString(),
    prompt_hash: hashPrompt(prompt_text),
    prompt_length: prompt_text.length,
    rules_checked: allRules.length,
    context_provided: !!context
  };

  // Determine verbosity (default: compact)
  const level = verbosity || 'compact';

  let result;
  switch (level) {
    case 'minimal':
      result = {
        action,
        risk_level: riskLevel,
        findings_count: findings.length,
        message: findings.length > 0
          ? `${action}: ${findings.length} concern(s) detected. Use verbosity='compact' for details.`
          : "ALLOW: No security concerns detected."
      };
      break;
    case 'full':
      result = {
        action,
        risk_score: riskScore,
        risk_level: riskLevel,
        findings_count: findings.length,
        findings: findings.map(f => ({
          rule_id: f.rule_id,
          category: f.category,
          severity: f.severity,
          message: f.message,
          matched_text: f.matched_text,
          confidence: f.confidence
        })),
        explanation,
        recommendations,
        audit
      };
      break;
    case 'compact':
    default:
      result = {
        action,
        risk_score: riskScore,
        risk_level: riskLevel,
        findings_count: findings.length,
        findings: findings.map(f => ({
          rule_id: f.rule_id,
          severity: f.severity,
          message: f.message
        })),
        recommendations
      };
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify(result, null, 2)
    }]
  };
}
