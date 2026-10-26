// Opens a Cairn secure link: fetches the encrypted copy from Cairn's public iCloud database and decrypts it here
// with the key from the link's #fragment (AES-256-GCM). See SecureLink.swift.
const CONTAINER = 'iCloud.app.cairn.notes', TOKEN = '77619a7ba29956b7a80f0b78603845f691120c9ac98b07c269e98e0035142642';
const $ = id => document.getElementById(id);
const fail = msg => { $('title').textContent = 'Can’t open this link'; $('status').textContent = msg; };
const bytes = b64 => Uint8Array.from(atob(b64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const TYPES = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', heic: 'image/heic', webp: 'image/webp', txt: 'text/plain' };

async function open() {
  const [id, k] = location.hash.slice(1).split('.');
  if (!/^[0-9a-f]{32}$/.test(id || '') || !/^[\w-]{43}$/.test(k || '')) return fail('The link is incomplete. Copy the whole link, including everything after “#”.');
  const res = await fetch(`https://api.apple-cloudkit.com/database/1/${CONTAINER}/production/public/records/lookup?ckAPIToken=${TOKEN}`,
    { method: 'POST', body: JSON.stringify({ records: [{ recordName: id }], desiredKeys: ['data', 'expires'] }) });
  const rec = res.ok && (await res.json()).records?.[0];
  if (!rec || rec.serverErrorCode) return fail('This link has been revoked, or it’s wrong.');
  if (rec.fields.expires.value < Date.now()) return fail('This link has expired. Ask the sender for a new one.');
  const sealed = new Uint8Array(await (await fetch(rec.fields.data.value.downloadURL.replace('${f}', 'data'))).arrayBuffer());
  const key = await crypto.subtle.importKey('raw', bytes(k), 'AES-GCM', false, ['decrypt']);
  let plain;
  try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealed.slice(0, 12), additionalData: new TextEncoder().encode('CAIRNLINK1') }, key, sealed.slice(12)); }
  catch { return fail('The key in this link doesn’t match. Copy the whole link again.'); }
  show(JSON.parse(new TextDecoder().decode(plain)), rec.fields.expires.value);
}

function show(p, expires) {
  $('title').textContent = p.notebook;
  $('status').textContent = `${p.notes.length} note${p.notes.length == 1 ? '' : 's'} · link works until ${new Date(expires).toLocaleDateString()}`;
  for (const n of p.notes) {
    const d = document.createElement('details'), s = document.createElement('summary');
    d.open = p.notes.length == 1; s.textContent = n.title || 'Untitled'; d.append(s);
    const f = document.createElement('iframe');
    f.sandbox = 'allow-popups allow-popups-to-escape-sandbox';   // the note's HTML: no scripts, links open in a new tab
    f.srcdoc = '<base target="_blank"><style>body{font:16px/1.5 -apple-system,system-ui,sans-serif;color:#1d1d1f;margin:16px}img{max-width:100%}</style>' + n.html;
    d.append(f);
    const files = document.createElement('div'); files.className = 'files';
    for (const file of n.files) {
      const ext = file.name.split('.').pop().toLowerCase();
      const url = URL.createObjectURL(new Blob([bytes(file.data)], { type: TYPES[ext] || 'application/octet-stream' }));
      if ((TYPES[ext] || '').startsWith('image/')) { const img = new Image(); img.src = url; img.alt = file.name; files.append(img); }
      const a = document.createElement('a'); a.href = url; a.download = file.name; a.textContent = '⬇ ' + file.name; files.append(a);
    }
    d.append(files); $('notes').append(d);
  }
}
open().catch(() => fail('Couldn’t reach iCloud. Check your connection and reload.'));
