#!/usr/bin/env node

// PromptFoo custom provider that calls scan_agent_prompt via MCP SDK
// Usage: This file is called by PromptFoo with the prompt as an argument

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_PATH = join(__dirname, '..', '..', 'index.js');

async function main() {
  // Read prompt from stdin (PromptFoo sends it via stdin)
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString());
  const promptText = input.prompt || input.vars?.prompt || '';

  const transport = new StdioClientTransport({
    command: 'node',
    args: [SERVER_PATH]
  });

  const client = new Client({
    name: 'promptfoo-provider',
    version: '1.0.0'
  });

  await client.connect(transport);

  try {
    const result = await client.callTool({
      name: 'scan_agent_prompt',
      arguments: { prompt_text: promptText, verbosity: 'compact' }
    });

    const parsed = JSON.parse(result.content[0].text);
    // Output the action for PromptFoo assertion
    process.stdout.write(JSON.stringify({
      output: `${parsed.action} (risk: ${parsed.risk_score}, findings: ${parsed.findings_count})`
    }));
  } finally {
    await client.close();
  }
}

main().catch(err => {
  process.stdout.write(JSON.stringify({ output: `ERROR: ${err.message}` }));
  process.exit(0);
});
