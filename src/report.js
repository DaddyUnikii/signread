const ICON = { HIGH: '🔴', MEDIUM: '🟡', LOW: '🟢' };
const C = { HIGH: '\x1b[31m', MEDIUM: '\x1b[33m', LOW: '\x1b[32m', dim: '\x1b[2m', b: '\x1b[1m', r: '\x1b[0m' };

export function toText(rep, { color = false } = {}) {
  const c = (k, s) => (color ? C[k] + s + C.r : s);
  const out = [c('b', `${ICON[rep.risk]} ${rep.risk}  ${rep.summary}`), ''];
  for (const [k, v] of rep.facts) out.push(`  ${c('dim', k.padEnd(20))} ${v}`);
  out.push('');
  for (const x of rep.reasons) out.push(`  ${c(x.level, x.level.padEnd(6))} ${x.reason}${x.quote ? c('dim', `\n         "${x.quote}"`) : ''}`);
  if (rep.ai) out.push('', c('b', `AI (${rep.ai.model}):`), rep.ai.text);
  return out.join('\n');
}

export function toMarkdown(rep) {
  const out = [`## ${ICON[rep.risk]} ${rep.risk}: ${rep.summary}`, ''];
  if (rep.ai) out.push(`> ${rep.ai.text.replace(/\n+/g, '\n> ')}`, `> — explained by \`${rep.ai.model}\` (open-weight, run locally)`, '');
  if (rep.facts.length) {
    out.push('| Field | Value |', '|---|---|');
    for (const [k, v] of rep.facts) out.push(`| ${k} | \`${String(v).replace(/\|/g, '\\|')}\` |`);
    out.push('');
  }
  out.push('**Findings**', '');
  for (const x of rep.reasons) out.push(`- ${ICON[x.level]} **${x.level}** ${x.reason}${x.quote ? ` — _"${x.quote.replace(/[_*]/g, '')}"_` : ''}`);
  return out.join('\n') + '\n';
}
