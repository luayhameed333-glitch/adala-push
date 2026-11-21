import { createSign } from 'node:crypto';
const API_KEY = 'AIzaSyDh6IFSPtBAEFZiRDA4LPrWsD2jfHRobvM';
let cached = { t: '', exp: 0 };

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(200).json({ ok: true, service: 'adala-push' });
  try {
    const sa = JSON.parse(process.env.SERVICE_ACCOUNT);
    const b = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const uid = await whoIs(b.idToken);
    const at = await accessToken(sa);
    const base = `https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents`;
    const st = await fetch(`${base}/staff/${uid}`, { headers: { Authorization: 'Bearer ' + at } }).then(r => r.json());
    if (!st.fields || st.fields.active?.booleanValue === false) return res.status(403).json({ error: 'not staff' });
    const title = String(b.title || 'ثانوية العدالة للبنين').slice(0, 80);
    const appUrl = String(b.base || '').startsWith('https://') ? b.base : './';
    let sent = 0, next = null;
    if (Array.isArray(b.items) && b.items.length) {
      const items = b.items.slice(0, 30);
      const docs = await query(base, at, 'codes', items.map(i => String(i.code)), null, 200);
      const jobs = [];
      for (const d of docs) {
        const codes = (d.fields.codes?.arrayValue?.values || []).map(v => v.stringValue);
        for (const it of items) if (codes.includes(String(it.code)))
          jobs.push(send(sa, at, d, { title, body: String(it.body).slice(0, 300), url: appUrl + '?code=' + it.code, tag: 'k' + it.code + Date.now() }));
      }
      sent = (await Promise.all(jobs)).reduce((a, n) => a + n, 0);
    } else if (Array.isArray(b.scopes) && b.scopes.length) {
      const docs = await query(base, at, 'scopes', b.scopes.slice(0, 10).map(String), b.cursor || null, 300);
      sent = (await Promise.all(docs.map(d => send(sa, at, d, { title, body: String(b.body || '').slice(0, 300), url: appUrl, tag: 'n' + Date.now() })))).reduce((a, n) => a + n, 0);
      if (docs.length === 300) next = docs[docs.length - 1].name;
    }
    return res.status(200).json({ ok: true, sent, next });
  } catch (e) { return res.status(400).json({ error: String(e.message || e) }); }
}

async function whoIs(idToken) {
  const r = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${API_KEY}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ idToken }) }).then(r => r.json());
  const id = r.users?.[0]?.localId; if (!id) throw new Error('bad login'); return id;
}
async function query(base, at, field, values, cursor, limit) {
  const q = { structuredQuery: { from: [{ collectionId: 'tokens' }], where: { fieldFilter: { field: { fieldPath: field }, op: 'ARRAY_CONTAINS_ANY', value: { arrayValue: { values: values.map(v => ({ stringValue: v })) } } } }, orderBy: [{ field: { fieldPath: '__name__' } }], limit } };
  if (cursor) q.structuredQuery.startAt = { values: [{ referenceValue: cursor }], before: false };
  const r = await fetch(`${base}:runQuery`, { method: 'POST', headers: { Authorization: 'Bearer ' + at, 'content-type': 'application/json' }, body: JSON.stringify(q) }).then(r => r.json());
  return (Array.isArray(r) ? r : []).filter(x => x.document).map(x => x.document);
}
async function send(sa, at, doc, data) {
  const token = doc.fields.token?.stringValue; if (!token) return 0;
  const r = await fetch(`https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, 'content-type': 'application/json' },
    body: JSON.stringify({ message: { token, webpush: { headers: { Urgency: 'high', TTL: '172800' }, data } } })
  });
  if (r.ok) return 1;
  if (r.status === 404) await fetch(`https://firestore.googleapis.com/v1/${doc.name}`, { method: 'DELETE', headers: { Authorization: 'Bearer ' + at } }).catch(() => { });
  return 0;
}
async function accessToken(sa) {
  if (cached.t && cached.exp > Date.now() + 60000) return cached.t;
  const enc = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const unsigned = enc({ alg: 'RS256', typ: 'JWT' }) + '.' + enc({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/firebase.messaging https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 });
  const sig = createSign('RSA-SHA256').update(unsigned).sign(sa.private_key).toString('base64url');
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' + unsigned + '.' + sig }).then(r => r.json());
  if (!r.access_token) throw new Error('google auth failed');
  cached = { t: r.access_token, exp: Date.now() + (r.expires_in || 3600) * 1000 };
  return cached.t;
}
