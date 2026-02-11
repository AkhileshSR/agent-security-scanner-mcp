# Next Steps: Adding More Semgrep Rules

## Current State
- **165 security rules** across 6 languages
- **105 auto-fix templates** with 100% coverage
- **Languages:** JavaScript, TypeScript, Python, Java, Go, Dockerfile

---

## Phase 1: Rule Sources

| Source | URL | Rules Available |
|--------|-----|-----------------|
| **Semgrep Registry** | https://semgrep.dev/explore | 3,000+ rules |
| **Semgrep GitHub** | https://github.com/semgrep/semgrep-rules | Official rules |
| **OWASP** | https://owasp.org/www-project-web-security-testing-guide/ | Security patterns |
| **CodeQL** | https://github.com/github/codeql | Query patterns |
| **Snyk** | https://snyk.io/vuln/ | Vulnerability DB |

---

## Phase 2: Priority Rules to Add

### High Priority (Critical Vulnerabilities)

| Category | Missing Rules | Impact |
|----------|---------------|--------|
| **C/C++** | Buffer overflow, format string, use-after-free | Memory safety |
| **Rust** | Unsafe blocks, FFI issues | Memory safety |
| **PHP** | SQL injection, file inclusion, RCE | Web security |
| **Ruby** | Mass assignment, SSTI, command injection | Rails security |
| **Kotlin** | Android-specific vulnerabilities | Mobile security |
| **Swift** | iOS-specific vulnerabilities | Mobile security |

### Medium Priority (Expand Existing)

| Language | Rules to Add |
|----------|--------------|
| **JavaScript** | Prototype pollution (more patterns), ReDoS, WebSocket security |
| **Python** | Django ORM injection, async vulnerabilities, type confusion |
| **Java** | Spring-specific, Hibernate injection, reflection abuse |
| **Go** | Context cancellation, goroutine leaks, unsafe pointer |

### Low Priority (Nice to Have)

- Infrastructure as Code (Terraform, CloudFormation)
- Kubernetes manifests
- GitHub Actions workflows
- Shell scripts (bash, zsh)

---

## Phase 3: Implementation Process

### Step 1: Create New Language File
```bash
# Example: Adding PHP rules
touch mcp-server/rules/php.security.yaml
```

### Step 2: Rule Template
```yaml
rules:
  - id: php.lang.security.audit.sql-injection
    languages: [php]
    severity: ERROR
    message: "SQL Injection detected. Use prepared statements."
    patterns:
      - "\\$.*->query\\s*\\(\\s*[\"'].*\\$"
      - "mysql_query\\s*\\(\\s*[\"'].*\\$"
      - "mysqli_query\\s*\\(.*[\"'].*\\$"
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021 - Injection"
      confidence: HIGH
      references:
        - https://semgrep.dev/r/php.lang.security.injection.sql-injection
```

### Step 3: Add Fix Template
```javascript
// In index.js FIX_TEMPLATES
"php-sql-injection": {
  description: "Use prepared statements with PDO",
  fix: (line) => line.replace(
    /\$.*->query\s*\(\s*["'](.+?)\s*\.\s*\$/,
    '$stmt = $pdo->prepare("$1 ?"); $stmt->execute(['
  )
}
```

### Step 4: Update Analyzer
```python
# In analyzer.py - add language detection
'php': 'php',
```

### Step 5: Test
```bash
# Create test file
echo '<?php $db->query("SELECT * FROM users WHERE id=" . $id); ?>' > test.php

# Run scanner
python3 analyzer.py test.php
```

---

## Phase 4: Suggested New Rules by Category

### 1. PHP Security (25 rules)
```
- php.lang.security.audit.sql-injection
- php.lang.security.audit.command-injection
- php.lang.security.audit.file-inclusion
- php.lang.security.audit.xss-echo
- php.lang.security.audit.deserialization
- php.lang.security.audit.xxe
- php.lang.security.audit.ssrf
- php.lang.security.audit.path-traversal
- php.lang.security.audit.eval-usage
- php.lang.security.audit.preg-injection
- php.lang.security.audit.open-redirect
- php.lang.security.audit.hardcoded-credentials
- php.lang.security.audit.weak-crypto
- php.lang.security.audit.insecure-random
- php.lang.security.audit.session-fixation
- php.wordpress.security.sql-injection
- php.wordpress.security.xss
- php.laravel.security.mass-assignment
- php.laravel.security.sql-injection
- php.symfony.security.csrf-disabled
```

### 2. Ruby/Rails Security (20 rules)
```
- ruby.rails.security.mass-assignment
- ruby.rails.security.sql-injection
- ruby.rails.security.xss-raw
- ruby.rails.security.command-injection
- ruby.rails.security.open-redirect
- ruby.rails.security.csrf-disabled
- ruby.rails.security.session-secret
- ruby.rails.security.deserialization
- ruby.lang.security.eval-usage
- ruby.lang.security.system-call
```

### 3. Kotlin/Android Security (15 rules)
```
- kotlin.android.security.webview-javascript
- kotlin.android.security.insecure-storage
- kotlin.android.security.hardcoded-secrets
- kotlin.android.security.intent-injection
- kotlin.android.security.sql-injection
- kotlin.android.security.path-traversal
- kotlin.android.security.weak-crypto
- kotlin.android.security.insecure-random
- kotlin.android.security.ssl-pinning
- kotlin.android.security.exported-components
```

### 4. Swift/iOS Security (15 rules)
```
- swift.ios.security.insecure-storage
- swift.ios.security.hardcoded-secrets
- swift.ios.security.weak-crypto
- swift.ios.security.insecure-random
- swift.ios.security.ssl-pinning-bypass
- swift.ios.security.jailbreak-detection
- swift.ios.security.webview-javascript
- swift.ios.security.keychain-accessibility
- swift.ios.security.clipboard-sensitive
- swift.ios.security.url-scheme-hijacking
```

### 5. C/C++ Security (20 rules)
```
- c.lang.security.buffer-overflow
- c.lang.security.format-string
- c.lang.security.use-after-free
- c.lang.security.double-free
- c.lang.security.null-dereference
- c.lang.security.integer-overflow
- c.lang.security.strcpy-usage
- c.lang.security.gets-usage
- c.lang.security.sprintf-usage
- c.lang.security.memory-leak
- cpp.lang.security.new-delete-mismatch
- cpp.lang.security.unchecked-return
- cpp.lang.security.uninitialized-variable
```

### 6. Infrastructure as Code (20 rules)
```
- terraform.aws.security.s3-public-access
- terraform.aws.security.security-group-open
- terraform.aws.security.rds-public
- terraform.aws.security.iam-admin-policy
- terraform.aws.security.kms-key-rotation
- terraform.aws.security.cloudtrail-disabled
- terraform.aws.security.vpc-flow-logs
- terraform.azure.security.storage-public
- terraform.gcp.security.compute-public-ip
- cloudformation.aws.security.s3-encryption
- kubernetes.security.privileged-container
- kubernetes.security.host-network
- kubernetes.security.run-as-root
- kubernetes.security.secrets-in-env
- kubernetes.security.resource-limits
- kubernetes.security.readonly-filesystem
```

### 7. Shell Script Security (10 rules)
```
- bash.security.eval-usage
- bash.security.command-injection
- bash.security.hardcoded-credentials
- bash.security.curl-insecure
- bash.security.wget-insecure
- bash.security.unquoted-variables
- bash.security.world-writable-files
- bash.security.sudo-nopasswd
```

---

## Phase 5: Testing Strategy

```bash
# 1. Create test files with known vulnerabilities
mkdir -p test-files
# Add vulnerable code samples for each language

# 2. Run batch tests
for file in test-files/*; do
  echo "Testing: $file"
  python3 mcp-server/analyzer.py "$file"
done

# 3. Verify fix templates
node -e "
  const fixes = require('./mcp-server/index.js');
  // Test each fix template
"

# 4. Integration test with MCP
npx agent-security-scanner-mcp &
# Test via Claude Desktop/Code
```

---

## Phase 6: Timeline

| Week | Tasks | Rules Added |
|------|-------|-------------|
| 1 | Add PHP rules | +25 |
| 2 | Add Ruby/Rails rules | +20 |
| 3 | Add Kotlin/Android rules | +15 |
| 4 | Add Swift/iOS rules | +15 |
| 5 | Add C/C++ rules | +20 |
| 6 | Add IaC rules (Terraform, K8s) | +20 |
| 7 | Add Shell script rules | +10 |
| 8 | Expand existing language rules | +30 |
| 9-10 | Testing & documentation | - |

**Target: 165 → 320+ rules**

---

## Phase 7: Release Plan

### Version Roadmap

| Version | Features | Rules |
|---------|----------|-------|
| v1.0.x | Current (JS, Python, Java, Go, Dockerfile) | 165 |
| v1.1.0 | + PHP, Ruby | 210 |
| v1.2.0 | + Kotlin, Swift (Mobile) | 240 |
| v1.3.0 | + C/C++ | 260 |
| v1.4.0 | + Terraform, Kubernetes | 280 |
| v1.5.0 | + Shell, expanded rules | 320 |
| v2.0.0 | AST-based analysis, performance optimizations | 320+ |

---

## Checklist for Adding a New Language

- [ ] Create `rules/{language}.security.yaml`
- [ ] Add language detection in `analyzer.py`
- [ ] Add fix templates in `index.js`
- [ ] Create test file with vulnerable samples
- [ ] Run tests and verify detection
- [ ] Update README with new language
- [ ] Bump version and publish to npm

---

## Resources

- [Semgrep Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax/)
- [CWE Database](https://cwe.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
