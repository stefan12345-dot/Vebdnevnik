const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { db } = require('./db');
const SESSION_SECRET = process.env.SESSION_SECRET || process.env.TURSO_AUTH_TOKEN || crypto.randomBytes(32).toString('hex');

function makeToken(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${signature}`;
}
function readToken(token) {
  if (!token) return null;
  const [body, signature] = token.split('.');
  if (!body || !signature) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest();
  let supplied;
  try { supplied = Buffer.from(signature, 'base64url'); } catch (_) { return null; }
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    return payload.exp > Date.now() ? payload : null;
  } catch (_) { return null; }
}
function requireUser(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const payload = readToken(token);
  if (!payload || payload.purpose !== 'session') return res.status(401).json({ greska: 'Prijava je istekla.' });
  req.username = payload.username;
  next();
}
function base32(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, output = '';
  for (const byte of buffer) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { output += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}
function decodeBase32(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const bytes = [];
  for (const char of text.toUpperCase().replace(/=+$/, '')) { const index = alphabet.indexOf(char); if (index < 0) throw new Error('Neispravan 2FA ključ.'); value = (value << 5) | index; bits += 5; if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(bytes);
}
function verifyTotp(secret, code) {
  if (!/^\d{6}$/.test(String(code || ''))) return false;
  const key = decodeBase32(secret);
  const counter = Math.floor(Date.now() / 30000);
  for (let offset = -1; offset <= 1; offset++) {
    const buffer = Buffer.alloc(8); buffer.writeBigUInt64BE(BigInt(counter + offset));
    const digest = crypto.createHmac('sha1', key).update(buffer).digest();
    const index = digest[digest.length - 1] & 15;
    const value = (digest.readUInt32BE(index) & 0x7fffffff) % 1000000;
    if (String(value).padStart(6, '0') === String(code)) return true;
  }
  return false;
}
async function findUser(username) {
  const { rows } = await db.execute({ sql: 'SELECT * FROM korisnici WHERE korisnicko_ime = ?', args: [username] });
  return rows[0];
}
async function requireAdmin(req, res, next) {
  try {
    const user = await findUser(req.username);
    if (!user || String(user.uloga).toLocaleLowerCase('sr') !== 'administrator') return res.status(403).json({ greska: 'Samo administrator može upravljati korisnicima.' });
    req.admin = user;
    next();
  } catch (error) { res.status(500).json({ greska: 'Provera administratorskih prava nije uspela.' }); }
}
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `scrypt$${salt}$${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}
function checkPassword(password, stored) {
  if (!String(stored || '').startsWith('scrypt$')) return stored === password;
  const [, salt, expectedHex] = stored.split('$');
  const expected = Buffer.from(expectedHex || '', 'hex');
  const actual = crypto.scryptSync(password, salt, 64);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}
function publicUser(user) {
  return { id: user.id, ime: user.ime, korisnicko_ime: user.korisnicko_ime, uloga: user.uloga, email: user.email || '', telefon: user.telefon || '', twofa_enabled: Boolean(user.twofa_secret) };
}
function issueSession(user) { return makeToken({ username: user.korisnicko_ime, purpose: 'session' }); }

// ─── HELPER ───────────────────────────────────────────────
function slugify(text) {
  return text.trim().toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// ─── LOGIN I DVOFAKTORSKA PRIJAVA ─────────────────────────
router.post('/login', async (req, res) => {
  try {
    const korisnickoIme = req.body.username || req.body.korisnickoIme;
    const lozinka = req.body.password || req.body.lozinka;
    const user = await findUser(korisnickoIme);
    if (!user || !checkPassword(lozinka, user.lozinka)) return res.status(401).json({ greska: 'Pogrešno korisničko ime ili lozinka.' });
    if (!String(user.lozinka).startsWith('scrypt$')) {
      user.lozinka = hashPassword(lozinka);
      await db.execute({ sql: 'UPDATE korisnici SET lozinka=? WHERE id=?', args: [user.lozinka, user.id] });
    }
    if (user.twofa_secret) {
      return res.json({ twofaRequired: true, challengeToken: makeToken({ username: user.korisnicko_ime, purpose: '2fa' }) });
    }
    res.json({ korisnik: publicUser(user), token: issueSession(user) });
  } catch (e) {
    console.error('Greška pri prijavi:', e);
    res.status(500).json({ greska: 'Greška pri prijavi.' });
  }
});

router.post('/login/verify-2fa', async (req, res) => {
  try {
    const challenge = readToken(req.body.challengeToken);
    if (!challenge || challenge.purpose !== '2fa') return res.status(401).json({ greska: 'Prijava je istekla. Pokušajte ponovo.' });
    const user = await findUser(challenge.username);
    if (!user || !verifyTotp(user.twofa_secret, req.body.code)) return res.status(401).json({ greska: 'Neispravan 2FA kod.' });
    res.json({ korisnik: publicUser(user), token: issueSession(user) });
  } catch (e) { res.status(400).json({ greska: e.message || 'Neispravan 2FA kod.' }); }
});

router.get('/profil', requireUser, async (req, res) => {
  const user = await findUser(req.username);
  if (!user) return res.status(404).json({ greska: 'Korisnik nije pronađen.' });
  res.json({ korisnik: publicUser(user) });
});
router.put('/profil', requireUser, async (req, res) => {
  try {
    const { ime, email, telefon } = req.body;
    if (!String(ime || '').trim()) return res.status(400).json({ greska: 'Ime i prezime su obavezni.' });
    await db.execute({ sql: 'UPDATE korisnici SET ime=?, email=?, telefon=? WHERE korisnicko_ime=?', args: [ime.trim(), String(email || '').trim(), String(telefon || '').trim(), req.username] });
    res.json({ korisnik: publicUser(await findUser(req.username)) });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});
router.put('/profil/lozinka', requireUser, async (req, res) => {
  try {
    const user = await findUser(req.username);
    if (!user || !checkPassword(req.body.staraLozinka, user.lozinka)) return res.status(400).json({ greska: 'Stara lozinka nije ispravna.' });
    if (String(req.body.novaLozinka || '').length < 8) return res.status(400).json({ greska: 'Nova lozinka mora imati najmanje 8 znakova.' });
    await db.execute({ sql: 'UPDATE korisnici SET lozinka=? WHERE korisnicko_ime=?', args: [hashPassword(req.body.novaLozinka), req.username] });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});
router.post('/profil/2fa/setup', requireUser, async (req, res) => {
  const secret = base32(crypto.randomBytes(20));
  await db.execute({ sql: 'UPDATE korisnici SET twofa_pending=? WHERE korisnicko_ime=?', args: [secret, req.username] });
  const user = await findUser(req.username);
  const label = encodeURIComponent(`e-Dnevnik:${user.korisnicko_ime}`);
  res.json({ secret, otpauth: `otpauth://totp/${label}?secret=${secret}&issuer=e-Dnevnik` });
});
router.post('/profil/2fa/enable', requireUser, async (req, res) => {
  const user = await findUser(req.username);
  if (!user?.twofa_pending || !verifyTotp(user.twofa_pending, req.body.code)) return res.status(400).json({ greska: 'Kod nije ispravan. Probajte ponovo.' });
  await db.execute({ sql: 'UPDATE korisnici SET twofa_secret=twofa_pending, twofa_pending=? WHERE korisnicko_ime=?', args: ['', req.username] });
  res.json({ ok: true });
});
router.post('/profil/2fa/disable', requireUser, async (req, res) => {
  const user = await findUser(req.username);
  if (!user || !checkPassword(req.body.lozinka, user.lozinka)) return res.status(400).json({ greska: 'Lozinka nije ispravna.' });
  await db.execute({ sql: 'UPDATE korisnici SET twofa_secret=?, twofa_pending=? WHERE korisnicko_ime=?', args: ['', '', req.username] });
  res.json({ ok: true });
});

// ─── ŠKOLE ───────────────────────────────────────────────
router.get('/skole', async (req, res) => {
  const { rows } = await db.execute('SELECT * FROM skole ORDER BY naziv');
  res.json(rows);
});
router.post('/skole', async (req, res) => {
  try {
    const { naziv } = req.body;
    await db.execute({ sql: 'INSERT INTO skole (naziv) VALUES (?)', args: [naziv.trim()] });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});
router.delete('/skole/:id', async (req, res) => {
  await db.execute({ sql: 'DELETE FROM skole WHERE id = ?', args: [req.params.id] });
  res.json({ ok: true });
});

// ─── PREDMETI ─────────────────────────────────────────────
router.get('/predmeti', async (req, res) => {
  const { rows } = await db.execute('SELECT * FROM predmeti ORDER BY naziv');
  res.json(rows);
});
router.post('/predmeti', async (req, res) => {
  try {
    const { naziv } = req.body;
    await db.execute({ sql: 'INSERT INTO predmeti (naziv) VALUES (?)', args: [naziv.trim()] });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});
router.delete('/predmeti/:id', async (req, res) => {
  await db.execute({ sql: 'DELETE FROM predmeti WHERE id = ?', args: [req.params.id] });
  res.json({ ok: true });
});

// ─── ODELJENJA ────────────────────────────────────────────
router.get('/odeljenja', async (req, res) => {
  const { rows } = await db.execute('SELECT * FROM odeljenja ORDER BY naziv');
  res.json(rows);
});
router.post('/odeljenja', async (req, res) => {
  try {
    const { naziv } = req.body;
    await db.execute({ sql: 'INSERT INTO odeljenja (naziv) VALUES (?)', args: [naziv.trim()] });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});
router.delete('/odeljenja/:id', async (req, res) => {
  await db.execute({ sql: 'DELETE FROM odeljenja WHERE id = ?', args: [req.params.id] });
  res.json({ ok: true });
});

// ─── KORISNICI ────────────────────────────────────────────
router.get('/korisnici', requireUser, requireAdmin, async (req, res) => {
  const { rows } = await db.execute('SELECT id, ime, korisnicko_ime, uloga, email, telefon FROM korisnici ORDER BY ime');
  res.json(rows);
});
router.post('/korisnici', requireUser, requireAdmin, async (req, res) => {
  try {
    const { ime, korisnicko_ime, lozinka, uloga, email, telefon } = req.body;
    if (!String(ime || '').trim() || !String(korisnicko_ime || '').trim() || String(lozinka || '').length < 8) {
      return res.status(400).json({ greska: 'Unesite ime i prezime, korisničko ime i lozinku od najmanje 8 znakova.' });
    }
    const inserted = await db.execute({
      sql: 'INSERT INTO korisnici (ime, korisnicko_ime, lozinka, uloga, email, telefon) VALUES (?, ?, ?, ?, ?, ?)',
      args: [ime.trim(), korisnicko_ime.trim(), hashPassword(lozinka), uloga || 'Nastavnik', String(email || '').trim(), String(telefon || '').trim()],
    });
    res.json({ ok: true, id: Number(inserted.lastInsertRowid) });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});
router.delete('/korisnici/:id', requireUser, requireAdmin, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM korisnici WHERE id = ?', args: [req.params.id] });
  res.json({ ok: true });
});

// ─── UČENICI ──────────────────────────────────────────────
router.get('/ucenici', async (req, res) => {
  const { odeljenje } = req.query;
  let sql = 'SELECT * FROM ucenici';
  const args = [];
  if (odeljenje) { sql += ' WHERE odeljenje = ?'; args.push(odeljenje); }
  sql += ' ORDER BY ime';
  const { rows } = await db.execute({ sql, args });
  res.json(rows);
});

router.get('/ucenici/:id', async (req, res) => {
  const { rows } = await db.execute({ sql: 'SELECT * FROM ucenici WHERE id = ?', args: [req.params.id] });
  if (!rows.length) return res.status(404).json({ greska: 'Učenik nije pronađen.' });
  res.json(rows[0]);
});

router.post('/ucenici', async (req, res) => {
  try {
    const { ime, odeljenje } = req.body;
    const id = slugify(ime);
    const { rows: existing } = await db.execute({ sql: 'SELECT id FROM ucenici WHERE id = ?', args: [id] });
    if (existing.length) return res.status(400).json({ greska: 'Učenik sa ovim imenom već postoji.' });
    await db.execute({
      sql: 'INSERT INTO ucenici (id, ime, odeljenje) VALUES (?, ?, ?)',
      args: [id, ime.trim(), odeljenje || 'VIII-2'],
    });
    res.json({ ok: true, id });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});

router.put('/ucenici/:id', async (req, res) => {
  try {
    const { ime, odeljenje, datum_rodjenja, roditelj, telefon, adresa } = req.body;
    await db.execute({
      sql: 'UPDATE ucenici SET ime=?, odeljenje=?, datum_rodjenja=?, roditelj=?, telefon=?, adresa=? WHERE id=?',
      args: [ime, odeljenje, datum_rodjenja || '', roditelj || '', telefon || '', adresa || '', req.params.id],
    });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});

router.delete('/ucenici/:id', async (req, res) => {
  await db.execute({ sql: 'DELETE FROM ucenici WHERE id = ?', args: [req.params.id] });
  res.json({ ok: true });
});

// ─── OCENE ────────────────────────────────────────────────
router.get('/ucenici/:id/ocene', async (req, res) => {
  const { predmet } = req.query;
  let sql = 'SELECT * FROM ocene WHERE ucenik_id = ?';
  const args = [req.params.id];
  if (predmet) { sql += ' AND predmet = ?'; args.push(predmet); }
  sql += ' ORDER BY datum DESC';
  const { rows } = await db.execute({ sql, args });
  res.json(rows);
});

router.post('/ucenici/:id/ocene', async (req, res) => {
  try {
    const { predmet, vrednost, beleska } = req.body;
    const datum = new Date().toLocaleDateString('sr-RS');
    await db.execute({
      sql: 'INSERT INTO ocene (ucenik_id, predmet, vrednost, beleska, datum) VALUES (?, ?, ?, ?, ?)',
      args: [req.params.id, predmet, vrednost, beleska || '', datum],
    });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});

router.put('/ocene/:id', async (req, res) => {
  try {
    const { vrednost, beleska } = req.body;
    await db.execute({
      sql: 'UPDATE ocene SET vrednost=?, beleska=? WHERE id=?',
      args: [vrednost, beleska || '', req.params.id],
    });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});

router.delete('/ocene/:id', async (req, res) => {
  await db.execute({ sql: 'DELETE FROM ocene WHERE id = ?', args: [req.params.id] });
  res.json({ ok: true });
});

// ─── BELEŠKE ──────────────────────────────────────────────
router.get('/ucenici/:id/beleske', async (req, res) => {
  const { rows } = await db.execute({
    sql: 'SELECT * FROM beleske WHERE ucenik_id = ? ORDER BY datum DESC, id DESC',
    args: [req.params.id],
  });
  res.json(rows);
});

router.post('/ucenici/:id/beleske', async (req, res) => {
  try {
    const { predmet, tekst } = req.body;
    const datum = new Date().toLocaleDateString('sr-RS');
    await db.execute({
      sql: 'INSERT INTO beleske (ucenik_id, predmet, tekst, datum) VALUES (?, ?, ?, ?)',
      args: [req.params.id, predmet || '', tekst, datum],
    });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});

router.delete('/beleske/:id', async (req, res) => {
  await db.execute({ sql: 'DELETE FROM beleske WHERE id = ?', args: [req.params.id] });
  res.json({ ok: true });
});

// ─── VLADANJE ─────────────────────────────────────────────
router.get('/ucenici/:id/vladanje', async (req, res) => {
  const { rows } = await db.execute({
    sql: 'SELECT * FROM vladanje WHERE ucenik_id = ? ORDER BY datum DESC, id DESC',
    args: [req.params.id],
  });
  res.json(rows);
});

router.post('/ucenici/:id/vladanje', async (req, res) => {
  try {
    const { vrednost, beleska } = req.body;
    const datum = new Date().toLocaleDateString('sr-RS');
    await db.execute({
      sql: 'INSERT INTO vladanje (ucenik_id, vrednost, beleska, datum) VALUES (?, ?, ?, ?)',
      args: [req.params.id, vrednost, beleska || '', datum],
    });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});

router.delete('/vladanje/:id', async (req, res) => {
  await db.execute({ sql: 'DELETE FROM vladanje WHERE id = ?', args: [req.params.id] });
  res.json({ ok: true });
});

// ─── IZOSTANCI ────────────────────────────────────────────
router.get('/ucenici/:id/izostanci', async (req, res) => {
  const { rows } = await db.execute({
    sql: 'SELECT * FROM izostanci WHERE ucenik_id = ? ORDER BY datum DESC',
    args: [req.params.id],
  });
  res.json(rows);
});

router.put('/izostanci/:id', async (req, res) => {
  try {
    const { status, beleska } = req.body;
    await db.execute({
      sql: 'UPDATE izostanci SET status=?, beleska=? WHERE id=?',
      args: [status, beleska || '', req.params.id],
    });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});

// ─── ČASOVI ───────────────────────────────────────────────
router.get('/casovi', async (req, res) => {
  const { datum_iso } = req.query;
  let sql = 'SELECT * FROM casovi';
  const args = [];
  if (datum_iso) { sql += ' WHERE datum_iso = ?'; args.push(datum_iso); }
  sql += ' ORDER BY datum_iso DESC, redni_broj DESC';
  const { rows } = await db.execute({ sql, args });
  res.json(rows);
});

router.post('/casovi', async (req, res) => {
  try {
    const { predmet, datum, datum_iso, redni_broj, tema, beleska, odsutni } = req.body;
    const id = Date.now().toString();

    await db.execute({
      sql: 'INSERT INTO casovi (id, predmet, datum, datum_iso, redni_broj, tema, beleska) VALUES (?, ?, ?, ?, ?, ?, ?)',
      args: [id, predmet, datum, datum_iso, redni_broj, tema, beleska || ''],
    });

    // Dodaj izostanke za odsutne učenike
    if (Array.isArray(odsutni) && odsutni.length) {
      function normalize(t) {
        return t.trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      }
      const { rows: sviUcenici } = await db.execute('SELECT id, ime FROM ucenici');
      for (const ime of odsutni) {
        const ucenik = sviUcenici.find(u => normalize(u.ime) === normalize(ime));
        if (ucenik) {
          await db.execute({
            sql: 'INSERT INTO izostanci (ucenik_id, cas_id, predmet, datum, redni_broj, tema, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
            args: [ucenik.id, id, predmet, datum, redni_broj, tema, 'Neregulisan'],
          });
        }
      }
    }

    res.json({ ok: true, id });
  } catch (e) { res.status(400).json({ greska: e.message }); }
});

router.delete('/casovi/:id', async (req, res) => {
  await db.execute({ sql: 'DELETE FROM casovi WHERE id = ?', args: [req.params.id] });
  res.json({ ok: true });
});

// ─── INICIJALIZACIJA (za proveru) ─────────────────────────
router.get('/status', async (req, res) => {
  const { rows } = await db.execute('SELECT COUNT(*) as cnt FROM ucenici');
  res.json({ ok: true, ucenici: rows[0].cnt });
});

module.exports = router;