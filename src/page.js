// "page" mode (airdropsense): scan a mint page, airdrop post or agent skill.md for traps.
const RULES = [
  ['HIGH', /\b(seed|recovery|secret)\s*phrase|mnemonic|private\s*key/i, 'asks about your seed phrase or private key'],
  ['HIGH', /curl[^\n|]*\|\s*(ba|z)?sh|wget[^\n|]*\|\s*(ba|z)?sh|iex\s*\(|powershell\s+-enc/i, 'pipes remote code straight into a shell'],
  ['HIGH', /ignore (all |any )?(previous|prior|above) instructions|do not (tell|inform|show) the user|without (asking|telling) the user|you are now/i, 'contains prompt-injection phrasing aimed at AI agents'],
  ['HIGH', /setApprovalForAll|approve\s+(all|unlimited)|unlimited approval|max(imum)? allowance/i, 'asks for a blanket token or NFT approval'],
  ['HIGH', /send\s+[\d.]+\s*(eth|bnb|usdt|usdc|sol)\b[^.\n]{0,40}(receive|get|back|double)/i, 'send-to-receive pattern'],
  ['MEDIUM', /(enable|turn on)\s+(developer|dev)\s*mode|raise (your )?(daily )?limit|increase (your )?(spending )?limit|disable\s+(2fa|security)/i, 'asks you to loosen wallet security settings'],
  ['MEDIUM', /\b(mint|vrf|oracle|gas|service|platform|claim)\s*fee\b|\bfee\b[^.\n]{0,30}\b(bnb|eth)\b/i, 'mentions fees: "free" may not mean zero cost'],
  ['MEDIUM', /refund(able)?|claim (it )?back|excess (is )?(credited|returned)/i, 'money comes back only through a later refund claim'],
  ['MEDIUM', /\b(only|last)\s+\d+\s*(spots|minutes|hours)|hurry|act now|before it'?s gone|limited time/i, 'pressure to act fast'],
  ['MEDIUM', /sign (this|the) (message|signature) to (claim|verify|receive)/i, 'claim-by-signature: check exactly what you sign'],
  ['LOW', /dyor|not financial advice/i, 'author hedges with DYOR'],
];

const NEGATION = /\b(no|never|not|don'?t|do not|must not|avoid|without)\b/i;
const ADDR = /0x[a-fA-F0-9]{40}\b/g;
const URL = /https?:\/\/[^\s)"'`<>\]]+/g;

export function scanPage(text, opts = {}) {
  const t = String(text);
  const r = { kind: 'page', summary: `Page scan${opts.source ? ` of ${opts.source}` : ''}`, risk: 'LOW', reasons: [], facts: [] };
  const RANK = { LOW: 0, MEDIUM: 1, HIGH: 2 };
  for (const [level, re, why] of RULES) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    let hit = null, warned = null;
    for (const m of t.matchAll(g)) {
      const before = t.slice(Math.max(0, m.index - 60), m.index);
      const clause = before.split(/[.!?\n]/).pop();
      if (NEGATION.test(clause)) { warned ??= m; continue; }
      hit = m; break;
    }
    const m = hit || warned;
    if (!m) continue;
    const at = Math.max(0, m.index - 40);
    const quote = t.slice(at, m.index + m[0].length + 40).replace(/\s+/g, ' ').trim();
    const lv = hit ? level : 'LOW';
    r.reasons.push({ level: lv, reason: hit ? why : `mentions it only as a warning: ${why}`, quote });
    if (RANK[lv] > RANK[r.risk]) r.risk = lv;
  }
  const addrs = [...new Set(t.match(ADDR) || [])];
  const urls = [...new Set(t.match(URL) || [])];
  if (addrs.length) r.facts.push(['contracts mentioned', addrs.slice(0, 8).join(', ') + (addrs.length > 8 ? ` (+${addrs.length - 8})` : '')]);
  if (urls.length) {
    const hosts = [...new Set(urls.map((u) => { try { return new globalThis.URL(u).host; } catch { return null; } }).filter(Boolean))];
    r.facts.push(['domains linked', hosts.slice(0, 8).join(', ')]);
    if (opts.source) {
      try {
        const own = new globalThis.URL(opts.source).host.split('.').slice(-2).join('.');
        const odd = hosts.filter((h) => /\.(zip|mov|top|xyz|click|live)$/.test(h) && !h.endsWith(own));
        if (odd.length) { r.reasons.push({ level: 'MEDIUM', reason: `links to unusual domains: ${odd.join(', ')}` }); if (r.risk === 'LOW') r.risk = 'MEDIUM'; }
      } catch { /* ignore */ }
    }
  }
  r.facts.push(['length', `${t.length} characters`]);
  if (!r.reasons.length) r.reasons.push({ level: 'LOW', reason: 'no known trap patterns found (that is not a guarantee)' });
  return r;
}

export async function fetchText(url, fetchImpl = globalThis.fetch) {
  const res = await fetchImpl(url, { headers: { 'user-agent': 'signread' }, redirect: 'follow' });
  if (!res.ok) throw new Error(`fetch ${url} failed: HTTP ${res.status}`);
  const body = await res.text();
  return /<html|<body/i.test(body)
    ? body.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ')
    : body;
}
