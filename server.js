import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const E = process.env;
const SECRET = E.FLW_SECRET_KEY, HASH = E.FLW_WEBHOOK_HASH, TSEC = E.TOKEN_SECRET;
const BASE = (E.BASE_URL || '').replace(/\/$/, ''), CUR = E.CURRENCY || 'USD';
if (!SECRET || !HASH || !TSEC || !BASE) throw new Error('Missing env vars');

const PLANS = {
  m: { amount: Number(E.PRICE_MONTHLY || 3.99), plan: E.PLAN_ID_MONTHLY, days: 31 },
  y: { amount: Number(E.PRICE_YEARLY || 24.99), plan: E.PLAN_ID_YEARLY, days: 366 },
  l: { amount: Number(E.PRICE_LIFETIME || 49.99), plan: null, days: null }
};
const GRACE = 3 * 86400000;

const FILE = E.DATA_FILE || 'data.json';
const read = () => { try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { return { users: {}, tx: {} }; } };
const write = d => fs.writeFileSync(FILE, JSON.stringify(d));

const b64 = s => Buffer.from(s).toString('base64url');
const sig = s => crypto.createHmac('sha256', TSEC).update(s).digest('base64url');
const sign = email => `${b64(email)}.${sig(b64(email))}`;
const unsign = t => {
  const [p, s] = String(t || '').split('.');
  if (!p || !s || sig(p) !== s) return null;
  return Buffer.from(p, 'base64url').toString();
};

const flw = (path, opts = {}) => fetch('https://api.flutterwave.com/v3' + path, {
  ...opts,
  headers: { Authorization: `Bearer ${SECRET}`, 'Content-Type': 'application/json' }
}).then(r => r.json());

async function verify(id, tx_ref) {
  const j = await flw(`/transactions/${encodeURIComponent(id)}/verify`);
  const d = j.data;
  if (j.status !== 'success' || !d || d.status !== 'successful') return null;
  if (tx_ref && d.tx_ref !== tx_ref) return null;
  if (d.currency !== CUR) return null;
  return d;
}

function grant(db, email, planKey) {
  const p = PLANS[planKey];
  const u = db.users[email] || {};
  const base = Math.max(Date.now(), u.expires || 0);
  db.users[email] = { plan: planKey, cancelled: false, expires: p.days ? base + p.days * 86400000 + GRACE : null };
}

const app = express();
app.use(express.json());
app.get('/', (req, res) => res.sendFile(path.resolve('index.html')));

app.post('/api/checkout', async (req, res) => {
  const { plan, email, name } = req.body || {};
  const p = PLANS[plan];
  if (!p || !/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Bad request' });
  if (plan !== 'l' && !p.plan) return res.status(500).json({ error: 'Plan not configured' });
  const tx_ref = 'ember_' + crypto.randomUUID();
  const db = read();
  db.tx[tx_ref] = { email: email.toLowerCase(), plan, amount: p.amount, status: 'pending' };
  write(db);
  const body = {
    tx_ref, amount: p.amount, currency: CUR,
    redirect_url: `${BASE}/api/callback`,
    customer: { email, name: name || 'Ember user' },
    customizations: { title: 'Ember Pro', description: plan === 'l' ? 'Lifetime' : plan === 'y' ? 'Yearly' : 'Monthly' }
  };
  if (p.plan) body.payment_plan = p.plan;
  const j = await flw('/payments', { method: 'POST', body: JSON.stringify(body) });
  if (j.status !== 'success') return res.status(502).json({ error: 'Payment provider error' });
  res.json({ link: j.data.link });
});

app.get('/api/callback', async (req, res) => {
  const { status, tx_ref, transaction_id } = req.query;
  const db = read(), t = db.tx[tx_ref];
  if (!t || !['successful', 'completed'].includes(status)) return res.redirect('/?paid=cancelled');
  if (t.status !== 'paid') {
    const d = await verify(transaction_id, tx_ref);
    if (!d || d.amount < t.amount) return res.redirect('/?paid=failed');
    t.status = 'paid';
    grant(db, t.email, t.plan);
    write(db);
  }
  res.redirect('/?paid=1&token=' + encodeURIComponent(sign(t.email)));
});

app.post('/api/webhook', async (req, res) => {
  const h = String(req.headers['verif-hash'] || '');
  if (h.length !== HASH.length || !crypto.timingSafeEqual(Buffer.from(h), Buffer.from(HASH))) return res.sendStatus(401);
  res.sendStatus(200);
  try {
    const { event, data } = req.body || {};
    const db = read();
    if (event === 'charge.completed' && data?.status === 'successful') {
      const d = await verify(data.id, null);
      if (!d) return;
      const email = (d.customer?.email || '').toLowerCase();
      const known = db.tx[d.tx_ref];
      const key = known?.plan || Object.keys(PLANS).find(k => PLANS[k].amount === d.amount);
      if (!email || !key) return;
      if (known) { if (known.status === 'paid') return; known.status = 'paid'; }
      else db.tx[d.tx_ref] = { email, plan: key, amount: d.amount, status: 'paid' };
      grant(db, email, key);
      write(db);
    } else if (/subscription\.cancelled/.test(event || '')) {
      const email = (data?.customer?.customer_email || data?.customer?.email || '').toLowerCase();
      if (db.users[email]) { db.users[email].cancelled = true; write(db); }
    }
  } catch (e) { console.error('webhook error', e); }
});

app.get('/api/status', (req, res) => {
  const email = unsign(req.query.token);
  const u = email && read().users[email];
  const active = !!u && (u.expires === null || u.expires > Date.now());
  res.json({ active, plan: active ? u.plan : null, cancelled: !!(u && u.cancelled) });
});

app.listen(E.PORT || 3000, () => console.log('Ember running'));
