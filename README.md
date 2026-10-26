<div align="center">

# 🔍 signread

**Read a wallet signature request before you sign it.**

Decodes permits, Permit2, Seaport orders, approvals and sign-in messages, flags the patterns behind most wallet drains,
and explains the result in plain words with a **local open-weight model**. No API key, no data leaves the runner.

[![CI](https://github.com/DaddyUnikii/signread/actions/workflows/ci.yml/badge.svg)](https://github.com/DaddyUnikii/signread/actions/workflows/ci.yml)
![node](https://img.shields.io/badge/node-%3E%3D18-3c873a)
![deps](https://img.shields.io/badge/dependencies-0-blue)
![AI](https://img.shields.io/badge/AI-Qwen%202.5%20via%20Ollama-8a2be2)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

</div>

---

## Why

Most drains are not hacks. Someone **signs** something they could not read: a gasless `Permit`, a Permit2 batch,
a Seaport listing for 0 ETH, a `setApprovalForAll`, or a blind 32-byte hash. Wallets show hex; people click *Sign*.

signread turns that payload into one line you can act on:

```
🔴 HIGH  Seaport order: you list items for sale

  you give             ERC721 0xBC4C...f13D #1234 x1
  paid out             1 of native 0x0000...0000 to 0x9d4e...7F80
  order end time       never expires

  HIGH   you receive nothing for these items (classic free-listing drain)
  HIGH   order end time never expires
```

and, with `--ai`, a short explanation from an open-weight model:

> Ini bukan sekadar login. Kalau kamu sign, NFT #1234 bisa diambil siapa saja tanpa kamu dibayar, dan izinnya tidak pernah kedaluwarsa. **Jangan sign.**

## AI explains, rules decide

```
payload ──► deterministic decoder ──► verdict (HIGH / MEDIUM / LOW) + facts
                                            │
                                            ▼
                         open-weight model (Ollama, local) ──► plain-language explanation
```

The verdict comes from a deterministic decoder with tests, so a prompt-injected page or a sweet-talking message
**cannot talk the model into saying "safe"**. The model only receives the structured findings, is told to treat
quoted text as untrusted data, and is forbidden from changing the verdict. That keeps the open model doing what it
is good at (explaining in your language) and out of the part that must be exact.

## What it reads

| Input | Detects |
|---|---|
| EIP-2612 / DAI `Permit` | unlimited value, unknown spender, deadline that never expires |
| Permit2 `PermitSingle` / `PermitBatch` / `PermitTransferFrom` | unlimited amounts, multi-token batches, long expirations |
| Seaport `OrderComponents` | items listed for nothing, payouts to someone else, endless orders |
| any other EIP-712 | unknown spender/operator fields, unlimited amounts, `approved: true`, chain id mismatch |
| `personal_sign` | blind 32-byte hashes, unreadable bytes, SIWE domain mismatch (`--origin`), seed-phrase bait |
| transaction calldata | `approve`, `increaseAllowance`, `setApprovalForAll`, Permit2 `approve`, transfers, `transferOwnership`, mints |
| **page mode** (airdropsense) | seed-phrase asks, `curl \| sh`, prompt injection aimed at AI agents, blanket approvals, "send to receive", loosened wallet settings, hidden fees, refund-later, urgency |

Page mode knows the difference between *"enter your seed phrase"* and *"never share your seed phrase"*.

## Use it from your phone

1. Open **Actions → Read before you sign → Run workflow**.
2. Pick `sign` and paste what your wallet shows (or `page` and paste a mint link / skill.md link).
3. Open the run: the report and the AI explanation are in the summary.

The runner installs [Ollama](https://ollama.com), pulls **Qwen 2.5 1.5B** (Apache-2.0, open weights), and runs it on CPU.
Pick another open model in the `model` input, e.g. `llama3.2:3b` or `gemma2:2b`.

## CLI

```bash
git clone https://github.com/DaddyUnikii/signread && cd signread
node bin/signread.js examples/free-listing-drain.json
node bin/signread.js examples/siwe.txt --origin https://app-examp1e.xyz   # 🔴 domain mismatch
node bin/signread.js page https://some-mint.fun/skill.md
echo '0x095ea7b3...' | node bin/signread.js -

# with local AI
ollama pull qwen2.5:1.5b
node bin/signread.js examples/drain-permit.json --ai --lang en
```

| Option | |
|---|---|
| `--ai` | explain with a local open-weight model |
| `--model <name>` | default `qwen2.5:1.5b` (`SIGNREAD_MODEL`) |
| `--host <url>` | default `http://127.0.0.1:11434` (`OLLAMA_HOST`) |
| `--api openai` | any OpenAI-compatible local server (llama.cpp, vLLM, LM Studio) |
| `--lang id\|en` | explanation language (default `id`) |
| `--origin`, `--chain`, `--from` | context checks: sign-in domain, chain id, transfer source |
| `--json`, `--markdown` | output format |
| `--fail-on LOW\|MEDIUM\|HIGH` | exit code 2 at or above a level (CI / bots) |

Zero dependencies. Node 18+. Tests: `npm test`.

## Limits

signread reads what you paste; it does not simulate on-chain state. A **LOW** verdict means no known trap pattern,
not a guarantee. When in doubt, don't sign.

## Related

[approvalscan](https://github.com/DaddyUnikii/approvalscan) finds approvals you already gave ·
[txlens](https://github.com/DaddyUnikii/txlens) explains a transaction after it happened ·
[mintcheck](https://github.com/DaddyUnikii/mintcheck) reads a mint contract before you mint.

MIT © Unikii
