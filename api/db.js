const { createClient } = require('@libsql/client');
const crypto = require('crypto');
require('dotenv').config();

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function initDB() {
  await db.executeMultiple(`
    CREATE TABLE IF NOT EXISTS skole (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      naziv TEXT NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS skolske_godine (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      naziv TEXT NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS odeljenja (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      naziv TEXT NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS predmeti (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      naziv TEXT NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS korisnici (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ime TEXT NOT NULL,
      korisnicko_ime TEXT NOT NULL UNIQUE,
      lozinka TEXT NOT NULL,
      uloga TEXT NOT NULL DEFAULT 'Nastavnik',
      email TEXT NOT NULL DEFAULT '',
      telefon TEXT NOT NULL DEFAULT '',
      twofa_secret TEXT NOT NULL DEFAULT '',
      twofa_pending TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS ucenici (
      id TEXT PRIMARY KEY,
      ime TEXT NOT NULL,
      odeljenje TEXT NOT NULL DEFAULT 'VIII-2',
      datum_rodjenja TEXT DEFAULT '',
      roditelj TEXT DEFAULT '',
      telefon TEXT DEFAULT '',
      adresa TEXT DEFAULT '',
      fotografija TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS ocene (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ucenik_id TEXT NOT NULL,
      predmet TEXT NOT NULL,
      vrednost INTEGER NOT NULL CHECK(vrednost BETWEEN 1 AND 5),
      beleska TEXT DEFAULT '',
      datum TEXT NOT NULL,
      FOREIGN KEY(ucenik_id) REFERENCES ucenici(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS beleske (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ucenik_id TEXT NOT NULL,
      predmet TEXT DEFAULT '',
      tekst TEXT NOT NULL,
      datum TEXT NOT NULL,
      FOREIGN KEY(ucenik_id) REFERENCES ucenici(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS vladanje (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ucenik_id TEXT NOT NULL,
      vrednost TEXT NOT NULL,
      beleska TEXT DEFAULT '',
      datum TEXT NOT NULL,
      FOREIGN KEY(ucenik_id) REFERENCES ucenici(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS casovi (
      id TEXT PRIMARY KEY,
      predmet TEXT NOT NULL,
      datum TEXT NOT NULL,
      datum_iso TEXT NOT NULL,
      redni_broj INTEGER NOT NULL,
      tema TEXT NOT NULL,
      beleska TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS izostanci (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ucenik_id TEXT NOT NULL,
      cas_id TEXT NOT NULL,
      predmet TEXT NOT NULL,
      datum TEXT NOT NULL,
      redni_broj INTEGER NOT NULL,
      tema TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'Neregulisan',
      beleska TEXT DEFAULT '',
      FOREIGN KEY(ucenik_id) REFERENCES ucenici(id) ON DELETE CASCADE
    );
  `);

  // Bezbedna migracija postojece Turso baze:
  // CREATE TABLE IF NOT EXISTS ne menja kolone vec kreiranih tabela.
  // Starija verzija baze moze imati korisnici tabelu bez kolone 'ime'.
  const { rows: korisniciKolone } = await db.execute('PRAGMA table_info(korisnici)');
  const postojeceKolone = new Set(korisniciKolone.map(kolona => kolona.name));

  if (!postojeceKolone.has('ime')) {
    await db.execute("ALTER TABLE korisnici ADD COLUMN ime TEXT NOT NULL DEFAULT ''");
    console.log('🔧 Migracija: dodata kolona korisnici.ime');
  }

  // Popuni prazna imena postojećih naloga korisničkim imenom, ako postoji.
  const { rows: proveriKorisnickoIme } = await db.execute('PRAGMA table_info(korisnici)');
  const imaKorisnickoIme = proveriKorisnickoIme.some(kolona => kolona.name === 'korisnicko_ime');
  if (imaKorisnickoIme) {
    await db.execute("UPDATE korisnici SET ime = korisnicko_ime WHERE ime IS NULL OR ime = ''");
  }

  const { rows: korisniciKoloneFinal } = await db.execute('PRAGMA table_info(korisnici)');
  const postojeceKorisnickeKolone = new Set(korisniciKoloneFinal.map(kolona => kolona.name));
  for (const [kolona, definicija] of [
    ['email', "TEXT NOT NULL DEFAULT ''"],
    ['telefon', "TEXT NOT NULL DEFAULT ''"],
    ['twofa_secret', "TEXT NOT NULL DEFAULT ''"],
    ['twofa_pending', "TEXT NOT NULL DEFAULT ''"],
  ]) {
    if (!postojeceKorisnickeKolone.has(kolona)) {
      await db.execute(`ALTER TABLE korisnici ADD COLUMN ${kolona} ${definicija}`);
    }
  }

  // Seed default data if empty
  const { rows: existingPredmeti } = await db.execute('SELECT COUNT(*) as cnt FROM predmeti');
  if (existingPredmeti[0].cnt === 0) {
    await db.executeMultiple(`
      INSERT OR IGNORE INTO predmeti (naziv) VALUES ('Srpski jezik');
      INSERT OR IGNORE INTO predmeti (naziv) VALUES ('Matematika');
      INSERT OR IGNORE INTO predmeti (naziv) VALUES ('Biologija');
      INSERT OR IGNORE INTO predmeti (naziv) VALUES ('Istorija');
      INSERT OR IGNORE INTO predmeti (naziv) VALUES ('Engleski jezik');
      INSERT OR IGNORE INTO predmeti (naziv) VALUES ('Fizika');
      INSERT OR IGNORE INTO predmeti (naziv) VALUES ('Hemija');
      INSERT OR IGNORE INTO predmeti (naziv) VALUES ('Geografija');

      INSERT OR IGNORE INTO odeljenja (naziv) VALUES ('VIII-2');

      INSERT OR IGNORE INTO skolske_godine (naziv) VALUES ('2024/2025');

      INSERT OR IGNORE INTO ucenici (id, ime, odeljenje) VALUES ('jovana-petrovic', 'Jovana Petrović', 'VIII-2');
      INSERT OR IGNORE INTO ucenici (id, ime, odeljenje) VALUES ('marko-ilic', 'Marko Ilić', 'VIII-2');
      INSERT OR IGNORE INTO ucenici (id, ime, odeljenje) VALUES ('milica-jovanovic', 'Milica Jovanović', 'VIII-2');
      INSERT OR IGNORE INTO ucenici (id, ime, odeljenje) VALUES ('luka-nikolic', 'Luka Nikolić', 'VIII-2');
      INSERT OR IGNORE INTO ucenici (id, ime, odeljenje) VALUES ('teodora-simic', 'Teodora Simić', 'VIII-2');
      INSERT OR IGNORE INTO ucenici (id, ime, odeljenje) VALUES ('lazar-otasevic', 'Lazar Otašević', 'VIII-2');
      INSERT OR IGNORE INTO ucenici (id, ime, odeljenje) VALUES ('lara-tomic', 'Lara Tomić', 'VIII-2');
    `);
  }

  // Remove the legacy public admin/admin account, including its scrypt-upgraded form.
  const { rows: legacyAdmins } = await db.execute({
    sql: "SELECT id, lozinka FROM korisnici WHERE korisnicko_ime = 'admin'",
    args: [],
  });
  for (const user of legacyAdmins) {
    const [scheme, salt, storedHex] = String(user.lozinka || '').split('$');
    let isLegacyPassword = user.lozinka === 'admin';
    if (!isLegacyPassword && scheme === 'scrypt' && salt && storedHex) {
      const storedHash = Buffer.from(storedHex, 'hex');
      if (storedHash.length === 64) {
        isLegacyPassword = crypto.timingSafeEqual(
          crypto.scryptSync('admin', salt, 64),
          storedHash
        );
      }
    }
    if (isLegacyPassword) {
      await db.execute({ sql: 'DELETE FROM korisnici WHERE id = ?', args: [user.id] });
    }
  }

  const adminUsername = String(process.env.INIT_ADMIN_USERNAME || '').trim();
  const adminPassword = process.env.INIT_ADMIN_PASSWORD || '';
  if (Boolean(adminUsername) !== Boolean(adminPassword)) {
    throw new Error('Podesite i INIT_ADMIN_USERNAME i INIT_ADMIN_PASSWORD za početni administratorski nalog.');
  }
  const { rows: userCount } = await db.execute('SELECT COUNT(*) AS cnt FROM korisnici');
  if (userCount[0].cnt === 0 && adminUsername && adminPassword) {
    if (adminPassword.length < 12) {
      throw new Error('INIT_ADMIN_PASSWORD mora imati najmanje 12 znakova.');
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = `scrypt$${salt}$${crypto.scryptSync(adminPassword, salt, 64).toString('hex')}`;
    await db.execute({
      sql: 'INSERT INTO korisnici (ime, korisnicko_ime, lozinka, uloga) VALUES (?, ?, ?, ?)',
      args: ['Administrator', adminUsername, passwordHash, 'Administrator'],
    });
  } else if (userCount[0].cnt === 0) {
    console.warn('⚠️ Baza nema naloge. Podesite INIT_ADMIN_USERNAME i INIT_ADMIN_PASSWORD da biste napravili administratora.');
  }

  console.log('✅ Baza inicijalizovana.');
}

module.exports = { db, initDB };