#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { decode } from '../src/decode.js';
import { scanPage, fetchText } from '../src/page.js';
import { explain } from '../src/explain.js';
import { toText, toMarkdown } from '../src/report.js';

const HELP = `signread — read a wallet signature request before you sign it.

Usage
  signread [sign] <payload|file|->      decode typed data, a message or calldata
  signread page <url|file|->            scan a mint page / airdrop post / skill.md for traps

Payload can be EIP-712 JSON, eth_signTypedData_v4 params, a personal_sign
message (text or 0x hex), or a tx object {"to","data","value"}.

Options
  --ai                 explain with a local open-weight model (Ollama)
  --model <name>       model name (default qwen2.5:1.5b, env SIGNREAD_MODEL)
  --host <url>         model server (default http://127.0.0.1:11434, env OLLAMA_HOST)
  --api openai         use an OpenAI-compatible server instead of Ollama
  --lang id|en         explanation language (default id)
  --origin <site>      site asking for the signature (checks SIWE domain)
  --chain <id>         chain you are on (checks EIP-712 chainId)
  --from <address>     your address (checks transferFrom source)
  --json | --markdown  output format
  --fail-on <level>    exit 2 if risk >= LOW|MEDIUM|HIGH
  -h, --help           this help
`;

function parse(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') o.help = true;
    else if (['--ai', '--json', '--markdown'].includes(a)) o[a.slice(2)] = true;
    else if (a.startsWith('--')) o[a.slice(2).replace(/-(\w)/g, (_, x) => x.toUpperCase())] = argv[++i];
    else o._.push(a);
  }
  return o;
}

function readInput(arg) {
  if (arg === undefined || arg === '-') return readFileSync(0, 'utf8');
  try { return readFileSync(arg, 'utf8'); } catch { return arg; }
}

const RANK = { LOW: 0, MEDIUM: 1, HIGH: 2 };

async function main() {
  const o = parse(process.argv.slice(2));
  if (o.help) { process.stdout.write(HELP); return; }
  let mode = 'sign';
  if (o._[0] === 'page' || o._[0] === 'sign') mode = o._.shift();
  const src = o._.join(' ') || undefined;
  if (src === undefined && process.stdin.isTTY) { process.stdout.write(HELP); process.exit(1); }

  let rep;
  if (mode === 'page') {
    const isUrl = /^https?:\/\//.test(src || '');
    const text = isUrl ? await fetchText(src) : readInput(src);
    rep = scanPage(text, { source: isUrl ? src : undefined });
  } else {
    rep = decode(readInput(src), { origin: o.origin, chainId: o.chain, from: o.from });
  }

  if (o.ai) {
    try { rep.ai = await explain(rep, { model: o.model, host: o.host, api: o.api, lang: o.lang || 'id' }); }
    catch (e) { rep.ai = { model: o.model || 'qwen2.5:1.5b', text: `(AI explanation unavailable: ${e.message})` }; }
  }

  if (o.json) process.stdout.write(JSON.stringify(rep, null, 2) + '\n');
  else if (o.markdown) process.stdout.write(toMarkdown(rep));
  else process.stdout.write(toText(rep, { color: process.stdout.isTTY }) + '\n');

  if (o.failOn && RANK[rep.risk] >= RANK[String(o.failOn).toUpperCase()]) process.exit(2);
}

main().catch((e) => { console.error(`signread: ${e.message}`); process.exit(1); });
