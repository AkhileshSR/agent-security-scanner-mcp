# Agent Security Analyzer

A VS Code extension that analyzes code for common security vulnerabilities including SQL injection, XSS, path traversal, command injection, and hardcoded secrets.

## Features

- 🔍 **Automated Security Scanning**: Detects common security vulnerabilities in your code
- 🛡️ **Security Sidebar**: Dedicated "Security Explorer" view to browse issues by file
- 🎯 **Multiple Detection Rules**: 
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Path Traversal (including Sync methods)
  - Command Injection (exec, spawn, etc.)
  - Hardcoded Secrets (API keys, passwords, PEM keys)
- ⚙️ **Configurable**: Enable/disable specific rules and adjust severity levels
- 🔄 **Auto-scan on Save**: Automatically scan files when you save them
- 📊 **In-editor Diagnostics**: Security issues highlighted directly in your code

## Usage

### Sidebar View
Click the **Shield Icon** in the Activity Bar to open the **Security Explorer**. This view lists all scanned files and their detected vulnerabilities. Click any issue to jump directly to the code.

### Commands

- **Security: Scan Current File** - Scan the currently active file
- **Security: Scan Entire Workspace** - Scan all code files in your workspace
- **Security: Clear All Warnings** - Clear all security diagnostics
- **Refresh Security View** - Manually refresh the sidebar list

### Configuration

Configure the extension in your VS Code settings:

```json
{
  "agentSecurity.enabledRules": [
    "sql-injection",
    "xss",
    "path-traversal",
    "command-injection",
    "hardcoded-secrets"
  ],
  "agentSecurity.severity": "warning",
  "agentSecurity.autoScan": true
}
```

## Supported Languages

- JavaScript/TypeScript
- Python
- Java
- C#
- PHP
- Ruby
- Go
- Rust
- SQL

## Requirements

- **Node.js**: Required to run the VS Code extension wrapper
- **Python 3.x**: Required to run the security analysis engine

## Development

### Building from Source

1. **Install Prerequisites**:
   - Install [Node.js](https://nodejs.org/)
   - Install [Python](https://www.python.org/) (Ensure it's added to PATH)

2. **Setup Project**:
   ```bash
   # Install dependencies
   npm install

   # Compile TypeScript wrapper
   npm run compile
   ```

### Testing

Press `F5` in VS Code to open a new Extension Development Host window with the extension loaded.

## Disclaimer

This tool provides basic pattern-based security analysis. It should not be considered a replacement for comprehensive security audits or professional security tools.
