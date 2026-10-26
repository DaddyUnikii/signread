// Deterministic decoder: turns a signature request into findings with a risk level.
// The AI layer only explains these findings; it never decides the verdict.
import { KNOWN, PERMIT2, SELECTORS, MAX_UINT256, MAX_UINT160, MAX_UINT48 } from './known.js';

const RANK = { LOW: 0, MEDIUM: 1, HIGH: 2 };
const lc = (s) => String(s ?? '').toLowerCase();
export const label = (addr) => KNOWN[lc(addr)] || null;
const who = (addr) => (label(addr) ? `${addr} (${label(addr)})` : String(addr));

function bump(r, level, reason) {
  r.reasons.push({ level, reason });
  if (RANK[level] > RANK[r.risk]) r.risk = level;
}

export function fmtAmount(v, max = MAX_UINT256) {
  let n;
  try { n = BigInt(v); } catch { return String(v); }
  if (n >= max || n >= MAX_UINT160) return 'UNLIMITED';
  return n.toString();
}

function isUnlimited(v) {
  try { const n = BigInt(v); return n >= MAX_UINT160; } catch { return false; }
}

function fmtTime(ts, now) {
  let n;
  try { n = BigInt(ts); } catch { return { text: String(ts), days: null }; }
  if (n >= MAX_UINT48 || n > 10n ** 12n) return { text: 'never expires', days: Infinity };
  const secs = Number(n);
  const days = (secs - now) / 86400;
  return { text: new Date(secs * 1000).toISOString().replace('.000Z', 'Z'), days };
}

function expiryCheck(r, ts, now, field) {
  const t = fmtTime(ts, now);
  r.facts.push([field, t.text]);
  if (t.days === Infinity) bump(r, 'HIGH', `${field} never expires`);
  else if (t.days !== null && t.days > 30) bump(r, 'MEDIUM', `${field} is ${Math.round(t.days)} days away`);
  else if (t.days !== null && t.days < 0) bump(r, 'LOW', `${field} is already in the past`);
}

function base(kind, summary) {
  return { kind, summary, risk: 'LOW', reasons: [], facts: [] };
}

// ---------- EIP-712 typed data ----------
export function decodeTypedData(td, opts = {}) {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const d = td.domain || {};
  const m = td.message || {};
  const pt = td.primaryType || '';
  const vc = lc(d.verifyingContract);
  let r;

  if (vc === PERMIT2 || /^Permit(Single|Batch|TransferFrom|BatchTransferFrom|WitnessTransferFrom)/.test(pt) && d.name === 'Permit2') {
    r = base('permit2', `Permit2 ${pt}: lets a spender move your tokens through Permit2`);
    const details = m.details ? [].concat(m.details) : [];
    const permitted = m.permitted ? [].concat(m.permitted) : [];
    const spender = m.spender;
    r.facts.push(['spender', who(spender)]);
    if (!label(spender)) bump(r, 'HIGH', 'spender is not a known router or marketplace');
    for (const x of details) {
      r.facts.push(['token', who(x.token)], ['amount', fmtAmount(x.amount, MAX_UINT160)]);
      if (isUnlimited(x.amount)) bump(r, 'HIGH', 'unlimited token amount');
      if (x.expiration !== undefined) expiryCheck(r, x.expiration, now, 'allowance expiration');
    }
    for (const x of permitted) {
      r.facts.push(['token', who(x.token)], ['amount', fmtAmount(x.amount)]);
      if (isUnlimited(x.amount)) bump(r, 'HIGH', 'unlimited token amount');
    }
    if (details.length + permitted.length > 1) bump(r, 'MEDIUM', `covers ${details.length + permitted.length} tokens at once`);
    if (m.sigDeadline !== undefined) expiryCheck(r, m.sigDeadline, now, 'signature deadline');
    if (m.deadline !== undefined) expiryCheck(r, m.deadline, now, 'signature deadline');
  } else if (pt === 'Permit' && ('spender' in m)) {
    const dai = 'allowed' in m;
    r = base('permit', `${dai ? 'DAI-style' : 'EIP-2612'} permit on ${d.name || 'a token'}: gasless approval`);
    r.facts.push(['token', who(d.verifyingContract)], ['spender', who(m.spender)]);
    if (dai) {
      r.facts.push(['allowed', String(m.allowed)]);
      if (m.allowed === true || m.allowed === 'true') bump(r, 'HIGH', 'grants an unlimited allowance (DAI permit)');
      if (m.expiry !== undefined) expiryCheck(r, m.expiry, now, 'expiry');
    } else {
      r.facts.push(['amount', fmtAmount(m.value)]);
      if (isUnlimited(m.value)) bump(r, 'HIGH', 'unlimited token amount');
      else bump(r, 'MEDIUM', 'gives a spender the right to move your tokens without another prompt');
      if (m.deadline !== undefined) expiryCheck(r, m.deadline, now, 'deadline');
    }
    if (!label(m.spender)) bump(r, 'HIGH', 'spender is not a known router or marketplace');
  } else if (pt === 'OrderComponents' && Array.isArray(m.offer)) {
    r = base('seaport', 'Seaport order: you list items for sale');
    const offerer = lc(m.offerer);
    const kinds = ['native', 'ERC20', 'ERC721', 'ERC1155', 'ERC721 (any id)', 'ERC1155 (any id)'];
    for (const o of m.offer) r.facts.push(['you give', `${kinds[Number(o.itemType)] || 'item'} ${who(o.token)} #${o.identifierOrCriteria} x${o.startAmount}`]);
    let toYou = 0n, toOthers = 0n;
    for (const c of m.consideration || []) {
      const amt = BigInt(c.startAmount ?? 0);
      if (lc(c.recipient) === offerer) toYou += amt; else toOthers += amt;
      r.facts.push(['paid out', `${amt} of ${kinds[Number(c.itemType)] || 'item'} ${c.token} to ${lc(c.recipient) === offerer ? 'you' : c.recipient}`]);
    }
    if (toYou === 0n) bump(r, 'HIGH', 'you receive nothing for these items (classic free-listing drain)');
    else if (toOthers > toYou) bump(r, 'HIGH', 'most of the payment goes to someone other than you');
    else bump(r, 'MEDIUM', 'check the price: anyone can fill this order until it expires');
    if (m.offer.length > 1) bump(r, 'MEDIUM', `lists ${m.offer.length} items in one signature`);
    if (m.endTime !== undefined) expiryCheck(r, m.endTime, now, 'order end time');
  } else {
    r = base('typed-data', `EIP-712 ${pt || 'message'} for ${d.name || 'an unnamed app'}`);
    const scan = (obj, path = '') => {
      for (const [k, v] of Object.entries(obj || {})) {
        const p = path ? `${path}.${k}` : k;
        if (v && typeof v === 'object') { scan(v, p); continue; }
        if (/spender|operator|delegate|to$|recipient/i.test(k)) { r.facts.push([p, who(v)]); if (!label(v)) bump(r, 'MEDIUM', `${p} points at an unknown address`); }
        if (/amount|value|allowance/i.test(k) && isUnlimited(v)) bump(r, 'HIGH', `${p} is unlimited`);
        if (/approved|allowed/i.test(k) && (v === true || v === 'true')) bump(r, 'HIGH', `${p} = true grants blanket permission`);
      }
    };
    scan(m);
  }

  if (d.verifyingContract) r.facts.push(['verifying contract', who(d.verifyingContract)]);
  if (d.chainId !== undefined) {
    r.facts.push(['chain id', String(BigInt(d.chainId))]);
    if (opts.chainId && BigInt(d.chainId) !== BigInt(opts.chainId)) bump(r, 'HIGH', `chain id ${d.chainId} does not match your chain ${opts.chainId}`);
  }
  return r;
}

// ---------- personal_sign ----------
function hexToText(h) {
  const b = Buffer.from(h.slice(2), 'hex');
  const t = b.toString('utf8');
  return /^[\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]*$/.test(t) && !t.includes('\ufffd') ? t : null;
}

export function decodeMessage(msg, opts = {}) {
  let text = String(msg);
  if (/^0x[0-9a-fA-F]*$/.test(text)) {
    if (text.length === 66) {
      const r = base('blind-hash', 'Blind signature of a 32-byte hash');
      bump(r, 'HIGH', 'you cannot see what this hash stands for; it can authorize an order, a permit or a transaction');
      r.facts.push(['hash', text]);
      return r;
    }
    const t = hexToText(text);
    if (t === null) {
      const r = base('blind-bytes', 'Signature of raw bytes that are not readable text');
      bump(r, 'HIGH', 'unreadable binary payload');
      return r;
    }
    text = t;
  }
  const siwe = text.match(/^(\S+) wants you to sign in with your Ethereum account:\n(0x[0-9a-fA-F]{40})/);
  if (siwe) {
    const r = base('siwe', `Sign-In with Ethereum for ${siwe[1]}`);
    const field = (k) => (text.match(new RegExp(`^${k}: (.+)$`, 'm')) || [])[1];
    r.facts.push(['domain', siwe[1]], ['address', siwe[2]]);
    for (const k of ['URI', 'Chain ID', 'Expiration Time']) if (field(k)) r.facts.push([k.toLowerCase(), field(k)]);
    if (opts.origin) {
      const host = lc(opts.origin).replace(/^https?:\/\//, '').split('/')[0];
      if (lc(siwe[1]) !== host) bump(r, 'HIGH', `message is for ${siwe[1]} but the site you are on is ${host}`);
    }
    bump(r, 'LOW', 'a sign-in proves you own the address; it cannot move funds by itself');
    return r;
  }
  const r = base('message', 'Plain text message');
  r.facts.push(['text', text.length > 160 ? text.slice(0, 157) + '...' : text]);
  if (/private key|seed|mnemonic|recovery phrase/i.test(text)) bump(r, 'HIGH', 'mentions your seed phrase or private key');
  if (/approve|transfer|permit|setApprovalForAll|withdraw/i.test(text)) bump(r, 'MEDIUM', 'talks about moving or approving assets; a text signature should not need that');
  if (!r.reasons.length) bump(r, 'LOW', 'readable text with no asset permissions');
  return r;
}

// ---------- transaction calldata ----------
function word(data, i) { return data.slice(10 + i * 64, 10 + (i + 1) * 64); }

export function decodeCalldata(tx, opts = {}) {
  const data = lc(tx.data || tx.input || '0x');
  const to = tx.to;
  const value = BigInt(tx.value ?? 0);
  const sel = data.slice(0, 10);
  const spec = SELECTORS[sel];
  const r = base('transaction', spec ? `Transaction: ${spec.name}` : `Transaction calling ${sel === '0x' ? 'no function (plain transfer)' : 'unknown function ' + sel}`);
  r.facts.push(['to', who(to)]);
  if (value > 0n) r.facts.push(['native value (wei)', value.toString()]);
  if (!spec) {
    if (sel !== '0x' && sel.length === 10) bump(r, 'MEDIUM', 'function not recognized; check it on the explorer');
    if (value > 0n) bump(r, 'MEDIUM', 'sends native coin');
    if (!r.reasons.length) bump(r, 'LOW', 'plain transfer');
    return r;
  }
  const args = {};
  spec.args.forEach((t, i) => {
    const w = word(data, i);
    args[spec.names[i]] = t === 'address' ? '0x' + w.slice(24) : t === 'bool' ? BigInt('0x' + (w || '0')) !== 0n : BigInt('0x' + (w || '0'));
  });
  for (const [k, v] of Object.entries(args)) if (!['v', 'r', 's'].includes(k)) r.facts.push([k, typeof v === 'string' ? who(v) : typeof v === 'bigint' && (/amount|value|added/.test(k)) ? fmtAmount(v) : String(v)]);

  switch (spec.name) {
    case 'approve': case 'increaseAllowance': case 'Permit2.approve':
      if (isUnlimited(args.amount ?? args.added)) bump(r, 'HIGH', 'unlimited allowance');
      if (!label(args.spender)) bump(r, 'HIGH', 'spender is not a known router or marketplace');
      if (!r.reasons.length) bump(r, 'MEDIUM', 'gives a spender the right to move this token');
      break;
    case 'setApprovalForAll':
      if (args.approved) {
        bump(r, label(args.operator) ? 'MEDIUM' : 'HIGH', `hands over EVERY NFT you hold in this collection to ${label(args.operator) || 'an unknown operator'}`);
      } else bump(r, 'LOW', 'revokes an operator (safe)');
      break;
    case 'permit':
      bump(r, 'MEDIUM', 'submits a signed permit on-chain');
      break;
    case 'transferOwnership':
      bump(r, 'HIGH', 'transfers ownership of a contract');
      break;
    case 'transfer': case 'transferFrom': case 'safeTransferFrom':
      bump(r, 'MEDIUM', 'moves assets out; double-check the recipient');
      if (opts.from && args.from && lc(args.from) !== lc(opts.from)) bump(r, 'HIGH', 'moves assets from an address that is not yours');
      break;
    case 'mint':
      bump(r, value > 0n ? 'MEDIUM' : 'LOW', value > 0n ? 'paid mint' : 'mint with no native value');
      break;
    default:
      bump(r, 'LOW', 'no asset permissions');
  }
  return r;
}

// ---------- dispatcher ----------
export function detect(input) {
  if (typeof input === 'object' && input) return input;
  const s = String(input).trim();
  if (s.startsWith('{') || s.startsWith('[')) {
    try { return JSON.parse(s); } catch { /* fall through */ }
  }
  return s;
}

export function decode(input, opts = {}) {
  let x = detect(input);
  // eth_signTypedData_v4 params: [address, json]
  if (Array.isArray(x)) x = detect(x.find((v) => typeof v === 'object' || String(v).trim().startsWith('{')) ?? x[x.length - 1]);
  if (x && x.method && x.params) return decode(x.params, opts);
  if (x && typeof x === 'object' && x.types && x.message) return decodeTypedData(x, opts);
  if (x && typeof x === 'object' && (x.data || x.input)) return decodeCalldata(x, opts);
  if (typeof x === 'string' && /^0x[0-9a-fA-F]{8}/.test(x) && x.length > 66 && SELECTORS[lc(x.slice(0, 10))]) return decodeCalldata({ data: x, to: opts.to }, opts);
  return decodeMessage(typeof x === 'string' ? x : JSON.stringify(x), opts);
}
