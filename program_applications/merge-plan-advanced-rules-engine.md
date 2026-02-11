# Merge Plan: feature/advanced-rules-engine → main

## Branch Analysis

**Feature Branch:** `origin/feature/advanced-rules-engine`
**Main Branch:** `origin/main` (v2.0.7)
**Feature Branch Version:** v2.0.4

### Scope of Changes
- **1812 files changed** (+92,124 / -5,516 lines)
- **27 commits** ahead of main

### Key Features in Branch

| Feature | Files | Impact |
|---------|-------|--------|
| AST Engine | `ast_parser.py`, `generic_ast.py`, `pattern_matcher.py` | Core analysis upgrade |
| Taint Analysis | `taint_analyzer.py` | Dataflow tracking |
| Regex Fallback | `regex_fallback.py` | Graceful degradation |
| Semgrep Rules | 1799 rule files | 359 → 1000+ rules |
| Benchmarks | `benchmarks/` | Performance testing |

---

## Step-by-Step Merge Plan

### Phase 1: Prep (5 min)

```bash
# 1. Ensure clean working directory
cd /Users/divyachitimalla/agent-security-layer/mcp-server
git stash  # if needed

# 2. Fetch latest from both branches
git fetch origin main
git fetch origin feature/advanced-rules-engine

# 3. Create backup branch
git checkout main
git checkout -b main-backup-$(date +%Y%m%d)
git checkout main
```

### Phase 2: Merge (10 min)

```bash
# 4. Merge feature branch into main
git merge origin/feature/advanced-rules-engine --no-ff -m "feat: AST engine + taint analysis + 1000+ Semgrep rules (v3.0.0)"
```

**Expected Conflicts:**
- `package.json` (version: 2.0.4 vs 2.0.7)
- `index.js` (SARIF output added in main)
- `README.md` (changelog differences)

**Resolution Strategy:**
- Keep main's version (2.0.7) → bump to 3.0.0
- Keep main's SARIF additions in index.js
- Merge README changelogs

### Phase 3: Version Bump

```bash
# 5. Update package.json to v3.0.0 (major version for breaking changes)
# - New AST engine is a major upgrade
# - Rule format changes
```

### Phase 4: Testing (30 min)

```bash
# 6. Run existing test suite
npm test

# 7. Test AST engine specifically
python3 test_ast_engine.py

# 8. Test taint analysis
python3 test_taint_e2e.py

# 9. Test on real vulnerable files
node -e "
const { spawn } = require('child_process');
// Test scan_security on demo files
"

# 10. Test package size
npm pack --dry-run
```

**Test Checklist:**
- [ ] All 72 existing tests pass
- [ ] AST engine detects SQL injection
- [ ] AST engine detects XSS
- [ ] Taint analysis works
- [ ] Regex fallback works when tree-sitter unavailable
- [ ] SARIF output still works
- [ ] Package size < 5MB
- [ ] MCP tools respond correctly

### Phase 5: Release

```bash
# 11. Commit resolved conflicts
git add .
git commit -m "chore: resolve merge conflicts, bump to v3.0.0"

# 12. Tag release
git tag -a v3.0.0 -m "AST engine + taint analysis + 1000+ Semgrep rules"

# 13. Push to GitHub
git push origin main --tags

# 14. Publish to npm
npm publish --otp=YOUR_CODE
```

---

## Rollback Plan

If issues are found post-merge:

```bash
# Revert to backup
git checkout main-backup-YYYYMMDD
git branch -D main
git checkout -b main
git push origin main --force
```

---

## Version Strategy

| Version | Reason |
|---------|--------|
| 3.0.0 | Major: AST engine replaces regex, new rule format |
| 2.1.0 | Minor: If AST is additive only |

**Recommendation:** Use **3.0.0** — AST engine is a fundamental architecture change.

---

## Post-Release Validation

```bash
# Install from npm and test
npx agent-security-scanner-mcp@3.0.0 doctor
npx agent-security-scanner-mcp@3.0.0 demo
```

---

## Changelog Entry (for README)

```markdown
### v3.0.0 (2025-02-10)
- **AST Engine**: Tree-sitter based analysis replaces regex (10x more accurate)
- **Taint Analysis**: Dataflow tracking for source-to-sink vulnerabilities
- **1000+ Rules**: Full Semgrep rule library integration
- **Regex Fallback**: Graceful degradation when tree-sitter unavailable
- **Languages**: Added C, PHP, Ruby, Go, Rust, C# AST support
```
