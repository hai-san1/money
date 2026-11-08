const express = require('express');
const app = express();

// MoneyFlow local server: serves the app, handles accounts and keeps all data in a SQLite file (moneyflow.db).
// Run with:  node server.js      (needs Node 22.5 or newer, no packages to install)
//
// Pages:  /login (sign in or register)   /  (dashboard)
// The first account that registers becomes the admin. Later registrations use the configured default role (Customer by default).
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');

const scrypt = promisify(crypto.scrypt);
const PORT = Number(process.env.PORT) || 3000;
// 127.0.0.1 = only this computer. Use HOST=0.0.0.0 to let phones on your Wi-Fi reach the customer page.
const HOST = process.env.HOST || '127.0.0.1';
const LOOPBACK = ['127.0.0.1', 'localhost', '::1'].includes(HOST);
const SECURE_COOKIE = process.env.SECURE_COOKIES === '1'; // set when served over HTTPS
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'moneyflow.db');
const ADMIN_SETUP_KEY = process.env.ADMIN_SETUP_KEY || '';
const MAX_JSON = 20 * 1024 * 1024; // finance state includes small images
const MAX_FILE = 6 * 1024 * 1024; // one attachment
const SESSION_MS = 7 * 864e5;
// sign-ups allowed per hour from one network address (a shop's Wi-Fi shares one address, so keep this generous)
const SIGNUP_LIMIT = Number(process.env.SIGNUP_LIMIT) || 30;

/* ----------------------------------------------------------------- database */
const db = new DatabaseSync(DB_FILE);
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS settings   (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS categories (id TEXT PRIMARY KEY, name TEXT NOT NULL, color TEXT, icon TEXT, budget REAL NOT NULL DEFAULT 0, image TEXT, position INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS payments   (name TEXT PRIMARY KEY, position INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY, type TEXT NOT NULL CHECK (type IN ('expense','income')), date TEXT NOT NULL,
    title TEXT NOT NULL, merchant TEXT, category TEXT, payment TEXT, amount REAL NOT NULL);
  CREATE INDEX IF NOT EXISTS idx_tx_date ON transactions(date);
  CREATE TABLE IF NOT EXISTS goals (id TEXT PRIMARY KEY, name TEXT NOT NULL, emoji TEXT, target REAL NOT NULL, saved REAL NOT NULL DEFAULT 0, deadline TEXT, position INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, tx_id TEXT, name TEXT, type TEXT, size INTEGER NOT NULL DEFAULT 0, data BLOB NOT NULL, created INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS idx_files_tx ON files(tx_id);

  CREATE TABLE IF NOT EXISTS roles (name TEXT PRIMARY KEY, label TEXT NOT NULL, perms TEXT NOT NULL, builtin INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT NOT NULL UNIQUE, name TEXT NOT NULL, pass TEXT NOT NULL,
    role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, avatar TEXT, created INTEGER NOT NULL, last_login INTEGER);
  CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, channel TEXT NOT NULL CHECK (channel IN ('ai','admin')),
    sender TEXT NOT NULL CHECK (sender IN ('customer','admin','ai')), sender_id INTEGER, body TEXT NOT NULL, created INTEGER NOT NULL, read INTEGER NOT NULL DEFAULT 0);
  CREATE INDEX IF NOT EXISTS idx_msg ON messages(user_id, channel, id);
  CREATE TABLE IF NOT EXISTS faq (id INTEGER PRIMARY KEY AUTOINCREMENT, question TEXT NOT NULL, answer TEXT NOT NULL, keywords TEXT);
  CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor_id INTEGER, actor_name TEXT, action TEXT NOT NULL, target_id INTEGER, target_name TEXT, detail TEXT);
`);
// older databases get the new columns
{
    const have = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
    for (const [name, def] of[['pending', 'INTEGER NOT NULL DEFAULT 0'], ['muted', 'INTEGER NOT NULL DEFAULT 0'], ['chat_status', "TEXT NOT NULL DEFAULT 'open'"], ['email', 'TEXT']]) {
        if (!have.includes(name)) db.exec(`ALTER TABLE users ADD COLUMN ${name} ${def}`);
    }
}

// what each role may do; "admin" always has everything and can also manage users and roles
const PERMS = {
    'dashboard.view': 'View the dashboard and finances',
    'dashboard.edit': 'Add, edit and delete finance data',
    'chat.reply': 'Reply to customer messages and edit the customer assistant',
    'portal.use': 'Use the customer page',
};
const ALL_PERMS = Object.keys(PERMS);
const SEED_ROLES = [
    ['admin', 'Admin', ALL_PERMS],
    ['manager', 'Manager', ALL_PERMS],
    ['staff', 'Staff', ['dashboard.view', 'chat.reply', 'portal.use']],
    ['customer', 'Customer', ALL_PERMS],
];
const seedRole = db.prepare('INSERT OR IGNORE INTO roles (name, label, perms, builtin) VALUES (?, ?, ?, 1)');
for (const [n, l, p] of SEED_ROLES) seedRole.run(n, l, JSON.stringify(p));

// Make Customer a full-app, non-admin role and use it for new sign-ups on existing installations.
const customerAccessMigration = 'customer-full-app-access-v1';
if (!db.prepare('SELECT 1 FROM kv WHERE key = ?').get(customerAccessMigration)) {
    db.prepare('UPDATE roles SET perms = ? WHERE name = ?').run(JSON.stringify(ALL_PERMS), 'customer');
    const saved = db.prepare("SELECT value FROM kv WHERE key = 'registration'").get();
    if (saved) {
        const config = JSON.parse(saved.value);
        if (config.defaultRole === 'customer' || config.defaultRole === 'manager') {
            config.defaultRole = 'customer';
            db.prepare("UPDATE kv SET value = ? WHERE key = 'registration'").run(JSON.stringify(config));
        }
    }
    db.prepare('INSERT INTO kv (key, value) VALUES (?, ?)').run(customerAccessMigration, '1');
}

db.prepare('DELETE FROM files WHERE tx_id IS NULL AND created < ?').run(Date.now() - 864e5);
db.prepare('DELETE FROM sessions WHERE expires < ?').run(Date.now());

/* ----------------------------------------------------------------- helpers */
const str = (v, max = 500) => (v == null ? '' : String(v)).slice(0, max);
const num = v => { const n = Number(v); if (!Number.isFinite(n)) throw httpError(400, 'Invalid number'); return n; };
// `field` tells the page which input to highlight (name, phone, password, or login for "either one is wrong")
function httpError(status, message, field) { return Object.assign(new Error(message), { status, field }); }
const sha = s => crypto.createHash('sha256').update(s).digest('hex');

function normEmail(e) {
    const s = String(e == null ? '' : e).trim().toLowerCase();
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) ? s : null;
}

function normPhone(p) {
    const s = String(p == null ? '' : p).replace(/[\s\-().]/g, '');
    return /^\+?\d{8,15}$/.test(s) ? s : null;
}

function normLoginId(raw) {
    if (!raw) return null;
    const s = String(raw).trim();
    const email = normEmail(s);
    if (email) return { val: email, isEmail: true };
    const phone = normPhone(s);
    if (phone) return { val: phone, isEmail: false };
    return null;
}
async function hashPassword(pw) {
    const salt = crypto.randomBytes(16);
    return `${salt.toString('hex')}:${(await scrypt(pw, salt, 64)).toString('hex')}`;
}
async function verifyPassword(pw, stored) {
    const [s, h] = String(stored).split(':');
    const key = await scrypt(pw, Buffer.from(s, 'hex'), 64),
        want = Buffer.from(h, 'hex');
    return want.length === key.length && crypto.timingSafeEqual(want, key);
}
const DUMMY_HASH = `${'00'.repeat(16)}:${'00'.repeat(64)}`; // makes "unknown phone" take as long as "wrong password"
function checkPassword(pw) {
    if (typeof pw !== 'string' || pw.length < 8) throw httpError(400, 'Password must be at least 8 characters.', 'password');
    if (pw.length > 128) throw httpError(400, 'Password is too long (128 characters at most).', 'password');
}

// very small in-memory limiter: max `max` attempts per `windowMs` for a key
const hits = new Map();

function limited(key, max, windowMs) {
    const now = Date.now(),
        h = hits.get(key);
    if (!h || h.until < now) { hits.set(key, { n: 1, until: now + windowMs }); return false; }
    h.n++;
    return h.n > max;
}
const clearLimit = key => hits.delete(key);
setInterval(() => {
    const now = Date.now();
    for (const [k, h] of hits)
        if (h.until < now) hits.delete(k);
}, 60000).unref();

const userPub = u => ({
    id: u.id,
    name: u.name,
    phone: u.phone,
    email: u.email || (u.phone && u.phone.includes('@') ? u.phone : ''),
    role: u.role,
    active: !!u.active,
    pending: !!u.pending,
    muted: !!u.muted,
    chatStatus: u.chat_status || 'open',
    avatar: u.avatar || '',
    created: u.created,
    lastLogin: u.last_login || null
});
const roleRow = name => db.prepare('SELECT * FROM roles WHERE name = ?').get(name);
const activeAdmins = () => db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'admin' AND active = 1").get().n;

function cleanPerms(list) {
    const p = new Set((Array.isArray(list) ? list : []).filter(x => ALL_PERMS.includes(x)));
    if (p.has('dashboard.edit')) p.add('dashboard.view'); // editing without viewing makes no sense
    return ALL_PERMS.filter(x => p.has(x));
}

/* ----------------------------------------------------------------- sessions */
function startSession(res, userId) {
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)').run(sha(token), userId, Date.now() + SESSION_MS);
    db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(Date.now(), userId);
    res.setHeader('Set-Cookie', cookie(token, SESSION_MS / 1000));
}
const cookie = (value, maxAge) => `mf_session=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(maxAge)}${SECURE_COOKIE ? '; Secure' : ''}`;

function getAuth(req) {
    const m = (req.headers.cookie || '').match(/(?:^|;\s*)mf_session=([a-f0-9]{64})(?:;|$)/);
    if (!m) return null;
    const s = db.prepare('SELECT user_id, expires FROM sessions WHERE token_hash = ?').get(sha(m[1]));
    if (!s || s.expires < Date.now()) return null;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(s.user_id);
    if (!user || !user.active) return null;
    const role = roleRow(user.role);
    const isAdmin = user.role === 'admin';
    const perms = new Set(isAdmin ? ALL_PERMS : role ? JSON.parse(role.perms) : []);
    return { user, perms, isAdmin, token: m[1], roleLabel: role ? role.label : user.role };
}

function need(a, perm) {
    if (!a) throw httpError(401, 'Please log in');
    if (perm === 'admin' ? !a.isAdmin : !a.perms.has(perm)) throw httpError(403, 'Your role does not allow this');
}
const meJson = a => ({ user: userPub(a.user), roleLabel: a.roleLabel, perms: [...a.perms], isAdmin: a.isAdmin, ai: !!AI_KEY });
const homeFor = () => '/';

/* ----------------------------------------------------------------- finance state */
function getState() {
    const rows = db.prepare('SELECT key, value FROM settings').all();
    if (!rows.length) return null;
    const settings = {};
    let readNotifs = [],
        dismissed = [];
    for (const r of rows) {
        if (r.key === '_readNotifs') readNotifs = JSON.parse(r.value);
        else if (r.key === '_dismissed') dismissed = JSON.parse(r.value);
        else settings[r.key] = JSON.parse(r.value);
    }
    const files = {};
    for (const f of db.prepare('SELECT id, tx_id, name, type, size FROM files WHERE tx_id IS NOT NULL ORDER BY created, rowid').all()) {
        // GOOD (Fixed):
        files[f.tx_id] = files[f.tx_id] || [];
        files[f.tx_id].push({ id: f.id, name: f.name, type: f.type, size: f.size });
    }
    return {
        settings,
        readNotifs,
        dismissed,
        categories: db.prepare('SELECT * FROM categories ORDER BY position').all()
            .map(c => ({ id: c.id, name: c.name, color: c.color, icon: c.icon, limit: c.budget, ...(c.image ? { img: c.image } : {}) })),
        payments: db.prepare('SELECT name FROM payments ORDER BY position').all().map(p => p.name),
        transactions: db.prepare('SELECT * FROM transactions ORDER BY date DESC, rowid DESC').all()
            .map(t => ({ id: t.id, type: t.type, date: t.date, title: t.title, merchant: t.merchant, cat: t.category, pay: t.payment, amount: t.amount, files: files[t.id] || [] })),
        goals: db.prepare('SELECT * FROM goals ORDER BY position').all()
            .map(g => ({ id: g.id, name: g.name, emoji: g.emoji, target: g.target, saved: g.saved, deadline: g.deadline })),
    };
}

function saveState(s) {
    if (!s || typeof s !== 'object' || !Array.isArray(s.transactions) || !Array.isArray(s.categories) || !s.settings) throw httpError(400, 'Invalid state');
    db.exec('BEGIN');
    try {
        db.exec('DELETE FROM settings; DELETE FROM categories; DELETE FROM payments; DELETE FROM transactions; DELETE FROM goals; UPDATE files SET tx_id = NULL;');
        const putSetting = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
        for (const [k, v] of Object.entries(s.settings)) putSetting.run(str(k, 60), JSON.stringify(v));
        putSetting.run('_readNotifs', JSON.stringify(Array.isArray(s.readNotifs) ? s.readNotifs.map(x => str(x, 120)) : []));
        putSetting.run('_dismissed', JSON.stringify(Array.isArray(s.dismissed) ? s.dismissed.map(x => str(x, 200)) : []));

        const putCat = db.prepare('INSERT INTO categories (id, name, color, icon, budget, image, position) VALUES (?, ?, ?, ?, ?, ?, ?)');
        s.categories.forEach((c, i) => putCat.run(str(c.id, 60), str(c.name, 60), str(c.color, 20), str(c.icon, 30), num(c.limit || 0), c.img ? str(c.img, 600000) : null, i));

        const putPay = db.prepare('INSERT OR IGNORE INTO payments (name, position) VALUES (?, ?)');
        (s.payments || []).forEach((p, i) => putPay.run(str(p, 60), i));

        const putTx = db.prepare('INSERT INTO transactions (id, type, date, title, merchant, category, payment, amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
        const link = db.prepare('UPDATE files SET tx_id = ?, name = ?, type = ?, size = ? WHERE id = ?');
        for (const t of s.transactions) {
            putTx.run(str(t.id, 60), t.type === 'income' ? 'income' : 'expense', str(t.date, 10), str(t.title, 120), str(t.merchant, 120), str(t.cat, 60), str(t.pay, 60), num(t.amount));
            for (const f of t.files || []) link.run(str(t.id, 60), str(f.name, 200), str(f.type, 100), Math.max(0, Math.floor(num(f.size || 0))), str(f.id, 60));
        }

        const putGoal = db.prepare('INSERT INTO goals (id, name, emoji, target, saved, deadline, position) VALUES (?, ?, ?, ?, ?, ?, ?)');
        (s.goals || []).forEach((g, i) => putGoal.run(str(g.id, 60), str(g.name, 80), str(g.emoji, 8), num(g.target), num(g.saved || 0), str(g.deadline, 10), i));
        db.exec('COMMIT');
    } catch (e) {
        db.exec('ROLLBACK');
        throw e;
    }
}

/* ----------------------------------------------------------------- AI (optional Claude) */
// Off by default: both assistants then run on rules and nothing leaves this computer.
// To turn Claude on, start the server with BOTH:  MONEYFLOW_AI=on  ANTHROPIC_API_KEY=your-key   (optional: MONEYFLOW_AI_MODEL)
// Questions and the data shown to the assistant are then sent to Anthropic. The key never reaches the browser.
const AI_KEY = process.env.MONEYFLOW_AI === 'on' ? (process.env.ANTHROPIC_API_KEY || '') : '';
const AI_MODEL = process.env.MONEYFLOW_AI_MODEL || 'claude-sonnet-5-5';
const AI_URL = process.env.MONEYFLOW_AI_URL || 'https://api.anthropic.com/v1/messages';
const ADMIN_AI_SYSTEM = 'You are the assistant inside MoneyFlow, a personal finance app. Answer using only the data below; if the answer is not in the data, say so. ' +
    'Be friendly and brief (under 120 words), use the currency given, and format money clearly. You cannot change data yourself; ' +
    'if the user wants to log something, tell them to type e.g. "add expense 12.50 coffee at Starbucks".\n\nUSER DATA\n';

function alternating(messages) {
    const merged = [];
    for (const m of(Array.isArray(messages) ? messages : []).slice(-12)) {
        const msg = { role: m && m.role === 'assistant' ? 'assistant' : 'user', content: str(m && m.content, 2000).trim() };
        if (!msg.content) continue;
        const last = merged[merged.length - 1];
        if (last && last.role === msg.role) last.content += '\n' + msg.content;
        else merged.push(msg); // the API wants alternating roles
    }
    while (merged.length && merged[0].role !== 'user') merged.shift();
    if (!merged.length || merged[merged.length - 1].role !== 'user') throw httpError(400, 'No question');
    return merged;
}
async function callClaude(system, messages) {
    const r = await fetch(AI_URL, {
        method: 'POST',
        headers: { 'x-api-key': AI_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({ model: AI_MODEL, max_tokens: 700, system, messages: alternating(messages) }),
        signal: AbortSignal.timeout(30000),
    });
    if (!r.ok) throw httpError(502, 'The AI service returned an error');
    const j = await r.json();
    return (j.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
}

/* ----------------------------------------------------------------- customer assistant */
const STOP = new Set('a an the is are am i you do does did to of for in on at my me we our your it this that and or can could would please with be have has how what when where who why will there any some get want need'.split(' '));
// "groceries" and "grocery", "delivering" and "deliver" count as the same word
const stem = w => (w.length > 4 ? w.replace(/ies$/, 'y').replace(/(ing|ed|es|s)$/, '') : w);
const tokens = s => String(s).toLowerCase().split(/[^a-z0-9]+/).filter(w => w.length > 1 && !STOP.has(w)).map(stem);

function portalInfo() {
    const row = db.prepare("SELECT value FROM kv WHERE key = 'portal'").get();
    const info = row ? JSON.parse(row.value) : {};
    const st = db.prepare("SELECT value FROM settings WHERE key = 'storeName'").get();
    return {
        storeName: info.storeName || (st ? JSON.parse(st.value) : 'our store'),
        about: info.about || '',
        hours: info.hours || '',
        contact: info.contact || '',
        address: info.address || '',
        replyTime: info.replyTime || '',
    };
}

function faqMatch(text) {
    const q = new Set(tokens(text));
    let best = null,
        bestScore = 0;
    if (!q.size) return null;
    for (const f of db.prepare('SELECT * FROM faq').all()) {
        const ft = new Set(tokens(f.question + ' ' + (f.keywords || '')));
        const kw = new Set(tokens(f.keywords || ''));
        let n = 0,
            k = 0;
        for (const w of q) { if (ft.has(w)) n++; if (kw.has(w)) k++; }
        // a word the admin listed as a keyword is enough on its own; otherwise two shared words are needed
        if (k < 1 && n < Math.min(2, ft.size)) continue;
        const score = n + 2 * k + n / Math.sqrt(ft.size || 1);
        if (score > bestScore) {
            best = f;
            bestScore = score;
        }
    }
    return best;
}
async function customerAnswer(user, text) {
    const info = portalInfo(),
        t = text.toLowerCase(),
        first = user.name.split(' ')[0];
    const has = re => re.test(t);
    const handoff = 'If you would like a person to help, switch to the **Admin** tab and send them a message.';
    const faq = faqMatch(text);
    if (faq) return { reply: faq.answer };
    if (has(/^(hi|hello|hey|hai|good (morning|afternoon|evening))\b/)) return { reply: `Hi ${first}! I'm the virtual assistant for ${info.storeName}. Ask me about opening hours, contact details or common questions, or switch to the Admin tab to message a person.` };
    if (has(/\b(thanks?|thank you|thx|bye|goodbye)\b/)) return { reply: `You're welcome, ${first}! Anything else I can help with?` };
    if (has(/\b(admin|human|person|agent|staff|manager|someone|talk|speak|complain|complaint|refund)\b/)) return { reply: `Sure. ${handoff}`, handoff: true };
    if (has(/\b(hours?|open|opening|close|closing|closed|time)\b/)) return info.hours ? { reply: `${info.storeName} is open: ${info.hours}` } : { reply: `I don't have the opening hours yet. ${handoff}`, handoff: true };
    if (has(/\b(contact|phone|call|email|address|where|location|find you|reach)\b/)) {
        const parts = [info.contact && `Contact: ${info.contact}`, info.address && `Address: ${info.address}`].filter(Boolean);
        return parts.length ? { reply: parts.join('\n') } : { reply: `I don't have contact details yet. ${handoff}`, handoff: true };
    }
    if (has(/\b(password|login|log in|register|sign ?up|account|phone number)\b/)) return { reply: 'You sign in with your phone number and password. To change your password or name, use the Profile card on this page. If you forgot your password, ask the admin to reset it.' };
    if (has(/\b(about|who are you|what is this|what do you do)\b/) && info.about) return { reply: info.about };
    if (AI_KEY) {
        try {
            const faqs = db.prepare('SELECT question, answer FROM faq LIMIT 40').all();
            const system = `You are the friendly customer assistant for "${info.storeName}". Answer ONLY from the store information and FAQ below. ` +
                'If the answer is not there, say you are not sure and suggest messaging the admin from the Admin tab. Keep answers under 80 words. Never mention or guess private business data.\n\n' +
                `STORE INFO\nAbout: ${info.about}\nHours: ${info.hours}\nContact: ${info.contact}\nAddress: ${info.address}\n\nFAQ\n` + faqs.map(f => `Q: ${f.question}\nA: ${f.answer}`).join('\n');
            const history = db.prepare("SELECT sender, body FROM messages WHERE user_id = ? AND channel = 'ai' ORDER BY id DESC LIMIT 8").all(user.id).reverse()
                .map(m => ({ role: m.sender === 'ai' ? 'assistant' : 'user', content: m.body }));
            const reply = await callClaude(system, [...history, { role: 'user', content: text }]);
            if (reply) return { reply };
        } catch (e) { /* fall through to the built-in answer */ }
    }
    return { reply: `I'm not sure about that one. ${handoff}`, handoff: true };
}

/* ----------------------------------------------------------------- http plumbing */
const SAFE_TYPES = /^(image\/(jpeg|png|gif|webp|bmp)|application\/pdf|text\/plain|text\/csv)$/;
const PAGES = { '/': 'index.html', '/login': 'login.html' };
const CSP = "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-src blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

function readBody(req, limit) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', c => {
            size += c.length;
            if (size > limit) {
                reject(httpError(413, 'Payload too large'));
                req.destroy();
            } else chunks.push(c);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}
async function readJson(req, limit = 200 * 1024) {
    const raw = (await readBody(req, limit)).toString('utf8');
    try { return raw ? JSON.parse(raw) : {}; } catch (e) { throw httpError(400, 'Invalid JSON'); }
}
const cleanName = v => {
    const n = str(v, 80).trim().replace(/\s+/g, ' ');
    if (n.length < 1 || n.length > 60) throw httpError(400, 'Please enter your name (1 to 60 characters).', 'name');
    return n;
};

function cleanAvatar(v) {
    const s = str(v, 400000);
    if (s && !/^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(s)) throw httpError(400, 'Invalid image');
    return s;
}

/* ----------------------------------------------------------------- user management helpers */
// every change an admin makes to people, roles, sign-up rules or broadcasts is written to the activity log
function audit(a, action, target, detail = '') {
    db.prepare('INSERT INTO audit (ts, actor_id, actor_name, action, target_id, target_name, detail) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(Date.now(), a ? a.user.id : null, a ? a.user.name : 'system', action, target ? target.id : null, target ? target.name : null, str(detail, 300));
}

function guardLastAdmin(target, losing) {
    if (losing && target.role === 'admin' && target.active && activeAdmins() <= 1) throw httpError(400, 'There must always be at least one active admin');
}

function changeRole(a, target, role) {
    if (!roleRow(role)) throw httpError(400, 'Unknown role');
    if (role === target.role) return;
    guardLastAdmin(target, role !== 'admin');
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, target.id);
    audit(a, 'user.role', target, `${target.role} → ${role}`);
}

function setActive(a, target, on) {
    if (!on) guardLastAdmin(target, true);
    db.prepare('UPDATE users SET active = ?, pending = 0 WHERE id = ?').run(on ? 1 : 0, target.id);
    if (!on) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id);
    audit(a, target.pending && on ? 'user.approve' : on ? 'user.enable' : 'user.disable', target);
}

function signOutUser(a, target) {
    const n = Number(db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id).changes);
    audit(a, 'user.signout', target, `${n} device${n === 1 ? '' : 's'}`);
}

function removeUser(a, target) {
    if (target.id === a.user.id) throw httpError(400, 'You cannot delete your own account');
    guardLastAdmin(target, true);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM messages WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
    audit(a, target.pending ? 'user.reject' : 'user.delete', target, target.phone);
}
// rules for people who register themselves
function regConfig() {
    const r = db.prepare("SELECT value FROM kv WHERE key = 'registration'").get(),
        c = r ? JSON.parse(r.value) : {};
    const role = c.defaultRole && c.defaultRole !== 'admin' && roleRow(c.defaultRole) ? c.defaultRole : 'customer';
    return { open: c.open !== false, approval: !!c.approval, defaultRole: role };
}
const DEFAULT_QUICK = [
    'Thanks for your message! We will check and get back to you shortly.',
    'Your order is ready for pickup at the front desk.',
    'Sorry about that. Could you send us your order number so we can look into it?',
    'Our opening hours are shown on your page. Is there anything else we can help with?',
];

const server = http.createServer(async(req, res) => {
    const send = (code, data, type = 'application/json', extra = {}) => {
        res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...extra });
        res.end(data);
    };
    const json = (obj, code = 200) => send(code, JSON.stringify(obj));
    const redirect = to => {
        res.writeHead(302, { location: to, 'cache-control': 'no-store' });
        res.end();
    };
    try {
        // Allow localhost, 127.0.0.1, and Render hostnames (*.onrender.com)
        const currentHost = req.headers.host || '';
        const isAllowedHost = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(currentHost) || currentHost.includes('onrender.com');

        if (LOOPBACK && !isAllowedHost) return json({ error: 'forbidden host' }, 403);

        if (req.headers.origin) {
            let same = false;
            try { same = new URL(req.headers.origin).host === req.headers.host; } catch (_) { /* e.g. Origin: null */ }
            if (!same) return json({ error: 'forbidden origin' }, 403);
        }

        const url = new URL(req.url, 'http://localhost');
        const p = url.pathname,
            method = req.method,
            ip = req.socket.remoteAddress || '?';
        let m;

        /* ---- pages ---- */
        if (method === 'GET' && p === '/customer') return redirect('/');
        if (method === 'GET' && PAGES[p]) {
            const a = getAuth(req);
            if (p === '/login' && a) return redirect(homeFor());
            if (p !== '/login' && !a) return redirect('/login');
            if (p === '/' && !a.perms.has('dashboard.view')) return send(403, '<h1>No dashboard access</h1><p>Ask an admin to grant dashboard access to your role.</p><p><a href="/logout">Log out</a></p>', 'text/html; charset=utf-8');
            const file = path.join(__dirname, PAGES[p]);
            if (!fs.existsSync(file)) return send(404, 'Page not found', 'text/plain');
            return send(200, fs.readFileSync(file), 'text/html; charset=utf-8', { 'content-security-policy': CSP, 'x-frame-options': 'DENY', 'referrer-policy': 'same-origin' });
        }
        if (method === 'GET' && p === '/logout') { // convenience link, same as the button
            const a = getAuth(req);
            if (a) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(a.token));
            res.setHeader('Set-Cookie', cookie('', 0));
            return redirect('/login');
        }
        if (!p.startsWith('/api/')) return send(404, 'Not found', 'text/plain');

        /* ---- public auth routes ---- */
        if (p === '/api/health') return json({ ok: true });
        if (p === '/api/auth/status') { const c = regConfig(); return json({ hasUsers: db.prepare('SELECT COUNT(*) n FROM users').get().n > 0, open: c.open, approval: c.approval, setupKeyRequired: !!ADMIN_SETUP_KEY }); }

        if (p === '/api/auth/register' && method === 'POST') {
            if (limited(`reg|${ip}`, SIGNUP_LIMIT, 3600e3)) throw httpError(429, 'Too many sign-ups from this device. Try again later.');
            const b = await readJson(req);
            const name = cleanName(b.name);
            const rawId = b.email || b.phone;
            const login = normLoginId(rawId);
            if (!login) throw httpError(400, 'Enter a valid Gmail or email address (e.g. name@gmail.com).', 'email');
            const idVal = login.val;
            checkPassword(b.password);
            if (db.prepare('SELECT 1 FROM users WHERE phone = ? OR email = ?').get(idVal, idVal)) throw httpError(409, 'That email or account is already registered. Try signing in instead.', 'email');
            const first = db.prepare('SELECT COUNT(*) n FROM users').get().n === 0,
                cfg = regConfig();
            if (first && ADMIN_SETUP_KEY) {
                const suppliedKey = str(b.adminSetupKey, 512);
                const matches = crypto.timingSafeEqual(Buffer.from(sha(suppliedKey), 'hex'), Buffer.from(sha(ADMIN_SETUP_KEY), 'hex'));
                if (!matches) throw httpError(400, 'Enter the admin setup key configured for this deployment.', 'adminSetupKey');
            }
            if (!first && !cfg.open) throw httpError(403, 'New sign-ups are turned off. Please ask the admin to create your account.');
            const waiting = !first && cfg.approval; // the admin must approve before this person can sign in
            const info = db.prepare('INSERT INTO users (phone, email, name, pass, role, active, pending, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
                .run(idVal, login.isEmail ? idVal : null, name, await hashPassword(b.password), 'admin', waiting ? 0 : 1, waiting ? 1 : 0, Date.now());
            if (waiting) {
                audit(null, 'user.signup', { id: Number(info.lastInsertRowid), name }, 'waiting for approval');
                return json({ pending: true, message: 'Your account was created. The admin needs to approve it before you can sign in.' }, 202);
            }
            startSession(res, Number(info.lastInsertRowid));
            return json(meJson(getAuth({ headers: { cookie: res.getHeader('set-cookie') } })), 201);
        }
        if (p === '/api/auth/login' && method === 'POST') {
            const b = await readJson(req),
                rawId = b.email || b.phone,
                login = normLoginId(rawId),
                idVal = login ? login.val : str(rawId, 100),
                key = `login|${ip}|${idVal}`;
            const lock = hits.get(key);
            if (limited(`ip|${ip}`, 60, 15 * 60e3) || (lock && lock.until > Date.now() && lock.n >= 8)) throw httpError(429, 'Too many attempts. Wait a few minutes and try again.');
            const u = login && db.prepare('SELECT * FROM users WHERE phone = ? OR email = ?').get(idVal, idVal);
            const ok = await verifyPassword(str(b.password, 200), u ? u.pass : DUMMY_HASH);
            if (!u || !ok) { limited(key, 8, 15 * 60e3); throw httpError(401, 'Email or password is incorrect.', 'login'); }
            if (u.pending) throw httpError(403, 'Your account is waiting for the admin to approve it. Please try again later.', 'email');
            if (!u.active) throw httpError(403, 'This account has been disabled. Please contact the admin.', 'email');
            clearLimit(key);
            startSession(res, u.id);
            return json(meJson(getAuth({ headers: { cookie: res.getHeader('set-cookie') } })));
        }
        if (p === '/api/auth/logout' && method === 'POST') {
            const a = getAuth(req);
            if (a) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(a.token));
            res.setHeader('Set-Cookie', cookie('', 0));
            return json({ ok: true });
        }

        /* ---- everything below needs a signed-in user ---- */
        const a = getAuth(req);
        if (!a) return json({ error: 'Please log in' }, 401);
        const uid = a.user.id;

        if (p === '/api/me' && method === 'GET') return json(meJson(a));
        if (p === '/api/me' && method === 'PATCH') {
            const b = await readJson(req, 500 * 1024);
            if (b.name !== undefined) db.prepare('UPDATE users SET name = ? WHERE id = ?').run(cleanName(b.name), uid);
            if (b.avatar !== undefined) db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(cleanAvatar(b.avatar) || null, uid);
            if (b.newPassword !== undefined) {
                checkPassword(b.newPassword);
                if (limited(`pw|${uid}`, 8, 15 * 60e3)) throw httpError(429, 'Too many attempts. Try again later.');
                if (!(await verifyPassword(str(b.currentPassword, 200), a.user.pass))) throw httpError(400, 'Current password is incorrect.', 'currentPassword');
                db.prepare('UPDATE users SET pass = ? WHERE id = ?').run(await hashPassword(b.newPassword), uid);
                db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').run(uid, sha(a.token)); // sign out other devices
                clearLimit(`pw|${uid}`);
            }
            return json(meJson(getAuth(req)));
        }

        /* ---- finance data ---- */
        if (p === '/api/state') {
            if (method === 'GET') { need(a, 'dashboard.view'); return json(getState() || { empty: true }); }
            if (method === 'PUT') {
                need(a, 'dashboard.edit');
                saveState(await readJson(req, MAX_JSON));
                return json({ ok: true });
            }
        }
        if (p === '/api/chat' && method === 'POST') {
            need(a, 'dashboard.view');
            if (!AI_KEY) return json({ error: 'AI is not configured' }, 503);
            const b = await readJson(req, 100 * 1024);
            return json({ reply: await callClaude(ADMIN_AI_SYSTEM + str(b.context, 12000), b.messages) });
        }
        if (p === '/api/files' && method === 'DELETE') {
            need(a, 'dashboard.edit');
            db.exec('DELETE FROM files');
            return json({ ok: true });
        }
        if ((m = p.match(/^\/api\/files\/([\w-]{1,60})$/))) {
            const id = m[1];
            if (method === 'PUT') {
                need(a, 'dashboard.edit');
                const buf = await readBody(req, MAX_FILE);
                const type = str(req.headers['content-type'], 100) || 'application/octet-stream';
                db.prepare(`INSERT INTO files (id, tx_id, name, type, size, data, created) VALUES (?, NULL, '', ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET type = excluded.type, size = excluded.size, data = excluded.data`).run(id, type, buf.length, buf, Date.now());
                return json({ ok: true });
            }
            if (method === 'GET') {
                need(a, 'dashboard.view');
                const f = db.prepare('SELECT type, data FROM files WHERE id = ?').get(id);
                if (!f) return json({ error: 'not found' }, 404);
                return send(200, Buffer.from(f.data), SAFE_TYPES.test(f.type) ? f.type : 'application/octet-stream', { 'content-security-policy': 'sandbox' });
            }
            if (method === 'DELETE') {
                need(a, 'dashboard.edit');
                db.prepare('DELETE FROM files WHERE id = ?').run(id);
                return json({ ok: true });
            }
        }

        /* ---- user & role management (admin only) ---- */
        if (p === '/api/users' && method === 'GET') {
            need(a, 'admin');
            const rows = db.prepare(`SELECT u.*,
          (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires > ?) AS sessions,
          (SELECT COUNT(*) FROM messages m WHERE m.user_id = u.id AND m.channel = 'admin') AS msgs
        FROM users u ORDER BY u.id`).all(Date.now());
            return json({ users: rows.map(u => ({...userPub(u), sessions: u.sessions, messages: u.msgs })) });
        }
        if (p === '/api/users' && method === 'POST') {
            need(a, 'admin');
            const b = await readJson(req),
                rawId = b.email || b.phone,
                login = normLoginId(rawId),
                role = str(b.role, 30) || 'customer';
            if (!login) throw httpError(400, 'Enter a valid Gmail or email address.', 'email');
            if (!roleRow(role)) throw httpError(400, 'Unknown role');
            checkPassword(b.password);
            const idVal = login.val;
            if (db.prepare('SELECT 1 FROM users WHERE phone = ? OR email = ?').get(idVal, idVal)) throw httpError(409, 'That email or account is already registered.', 'email');
            const info = db.prepare('INSERT INTO users (phone, email, name, pass, role, active, created) VALUES (?, ?, ?, ?, ?, 1, ?)')
                .run(idVal, login.isEmail ? idVal : null, cleanName(b.name), await hashPassword(b.password), role, Date.now());
            const created = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(info.lastInsertRowid));
            audit(a, 'user.create', created, `role ${role}`);
            return json({ user: userPub(created) }, 201);
        }
        if (p === '/api/users/bulk' && method === 'POST') { // the same safety rules apply to every person in the batch
            need(a, 'admin');
            const b = await readJson(req),
                action = str(b.action, 20);
            const ids = [...new Set((Array.isArray(b.ids) ? b.ids : []).map(Number).filter(Number.isInteger))].slice(0, 200);
            if (!['role', 'enable', 'disable', 'signout', 'delete', 'approve'].includes(action)) throw httpError(400, 'Unknown action');
            if (!ids.length) throw httpError(400, 'Select at least one person');
            const done = [],
                skipped = [];
            for (const id of ids) {
                const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
                if (!target) { skipped.push({ id, reason: 'not found' }); continue; }
                try {
                    if (action === 'role') changeRole(a, target, str(b.role, 30));
                    else if (action === 'enable' || action === 'approve') setActive(a, target, true);
                    else if (action === 'disable') {
                        if (id === uid) throw httpError(400, 'You cannot disable your own account');
                        setActive(a, target, false);
                    } else if (action === 'signout') signOutUser(a, target);
                    else removeUser(a, target);
                    done.push(id);
                } catch (e) {
                    if (!e.status) throw e;
                    skipped.push({ id, name: target.name, reason: e.message });
                }
            }
            return json({ done: done.length, skipped });
        }
        if ((m = p.match(/^\/api\/users\/(\d+)(\/signout)?$/))) {
            need(a, 'admin');
            const id = Number(m[1]),
                fresh = () => db.prepare('SELECT * FROM users WHERE id = ?').get(id);
            const target = fresh();
            if (!target) throw httpError(404, 'User not found');
            if (m[2]) {
                if (method !== 'POST') throw httpError(405, 'Use POST');
                signOutUser(a, target);
                return json({ ok: true });
            }
            if (method === 'PATCH') {
                const b = await readJson(req);
                if (b.role !== undefined) changeRole(a, fresh(), str(b.role, 30));
                if (b.name !== undefined) {
                    const n = cleanName(b.name);
                    if (n !== target.name) {
                        db.prepare('UPDATE users SET name = ? WHERE id = ?').run(n, id);
                        audit(a, 'user.edit', target, `name → ${n}`);
                    }
                }
                if (b.email !== undefined || b.phone !== undefined) {
                    const raw = b.email !== undefined ? b.email : b.phone;
                    const login = normLoginId(raw);
                    if (!login) throw httpError(400, 'Enter a valid Gmail or email address.', 'email');
                    const idVal = login.val;
                    const other = db.prepare('SELECT id FROM users WHERE (phone = ? OR email = ?) AND id != ?').get(idVal, idVal, id);
                    if (other) throw httpError(409, 'That email is already registered to another account.', 'email');
                    db.prepare('UPDATE users SET phone = ?, email = ? WHERE id = ?').run(idVal, login.isEmail ? idVal : null, id);
                    audit(a, 'user.edit', target, `email/phone → ${idVal}`);
                }
                if (b.active !== undefined) setActive(a, fresh(), !!b.active);
                if (b.pending === false && fresh().pending) setActive(a, fresh(), true);
                if (b.muted !== undefined) {
                    if (target.role === 'admin' && b.muted) throw httpError(400, 'Admins cannot be muted');
                    db.prepare('UPDATE users SET muted = ? WHERE id = ?').run(b.muted ? 1 : 0, id);
                    audit(a, b.muted ? 'user.mute' : 'user.unmute', target);
                }
                if (b.password !== undefined) {
                    checkPassword(b.password);
                    db.prepare('UPDATE users SET pass = ? WHERE id = ?').run(await hashPassword(b.password), id);
                    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
                    audit(a, 'user.password', target, 'password reset by admin');
                }
                return json({ user: userPub(fresh()) });
            }
            if (method === 'DELETE') { removeUser(a, target); return json({ ok: true }); }
        }
        if (p === '/api/audit' && method === 'GET') {
            need(a, 'admin');
            const limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit')) || 200));
            return json({ entries: db.prepare('SELECT id, ts, actor_id AS actorId, actor_name AS actor, action, target_id AS targetId, target_name AS target, detail FROM audit ORDER BY id DESC LIMIT ?').all(limit) });
        }
        if (p === '/api/registration') {
            need(a, 'admin');
            if (method === 'GET') return json({...regConfig(), roles: db.prepare("SELECT name, label FROM roles WHERE name != 'admin' ORDER BY builtin DESC, name").all() });
            if (method === 'PUT') {
                const b = await readJson(req),
                    want = str(b.defaultRole, 30);
                const cfg = { open: !!b.open, approval: !!b.approval, defaultRole: want && want !== 'admin' && roleRow(want) ? want : 'customer' };
                db.prepare("INSERT INTO kv (key, value) VALUES ('registration', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(JSON.stringify(cfg));
                audit(a, 'signups.update', null, `${cfg.open ? 'open' : 'closed'}, ${cfg.approval ? 'approval required' : 'no approval'}, new accounts start as ${cfg.defaultRole}`);
                return json(regConfig());
            }
        }
        if (p === '/api/roles' && method === 'GET') {
            need(a, 'admin');
            const counts = Object.fromEntries(db.prepare('SELECT role, COUNT(*) n FROM users GROUP BY role').all().map(r => [r.role, r.n]));
            return json({
                perms: PERMS,
                roles: db.prepare('SELECT * FROM roles ORDER BY builtin DESC, name').all()
                    .map(r => ({ name: r.name, label: r.label, builtin: !!r.builtin, locked: r.name === 'admin', perms: r.name === 'admin' ? ALL_PERMS : JSON.parse(r.perms), users: counts[r.name] || 0 })),
            });
        }
        if (p === '/api/roles' && method === 'POST') {
            need(a, 'admin');
            const b = await readJson(req),
                name = str(b.name, 30).trim().toLowerCase();
            if (!/^[a-z][a-z0-9_-]{1,23}$/.test(name)) throw httpError(400, 'Role id must be 2 to 24 letters, numbers, - or _, starting with a letter');
            if (roleRow(name)) throw httpError(409, 'That role already exists');
            const label = str(b.label, 40).trim() || name;
            db.prepare('INSERT INTO roles (name, label, perms, builtin) VALUES (?, ?, ?, 0)').run(name, label, JSON.stringify(cleanPerms(b.perms)));
            audit(a, 'role.create', null, `${label} (${name}): ${cleanPerms(b.perms).join(', ') || 'no permissions'}`);
            return json({ ok: true }, 201);
        }
        if ((m = p.match(/^\/api\/roles\/([a-z][a-z0-9_-]{1,23})$/))) {
            need(a, 'admin');
            const r = roleRow(m[1]);
            if (!r) throw httpError(404, 'Role not found');
            if (method === 'PUT') {
                if (r.name === 'admin') throw httpError(400, 'The admin role always has every permission');
                const b = await readJson(req);
                db.prepare('UPDATE roles SET label = ?, perms = ? WHERE name = ?').run(str(b.label, 40).trim() || r.label, JSON.stringify(cleanPerms(b.perms)), r.name);
                audit(a, 'role.update', null, `${r.label}: ${cleanPerms(b.perms).join(', ') || 'no permissions'}`);
                return json({ ok: true });
            }
            if (method === 'DELETE') {
                if (r.builtin) throw httpError(400, 'Built-in roles cannot be deleted');
                if (db.prepare('SELECT COUNT(*) n FROM users WHERE role = ?').get(r.name).n) throw httpError(400, 'Move the users in this role to another role first');
                db.prepare('DELETE FROM roles WHERE name = ?').run(r.name);
                audit(a, 'role.delete', null, r.label);
                return json({ ok: true });
            }
        }

        /* ---- customer assistant content (FAQ + store info) ---- */
        if (p === '/api/portal' && method === 'GET') {
            need(a, 'portal.use');
            return json({ info: portalInfo(), faq: db.prepare('SELECT id, question, answer, keywords FROM faq ORDER BY id').all() });
        }
        if (p === '/api/portal' && method === 'PUT') {
            need(a, 'chat.reply');
            const b = await readJson(req);
            db.prepare("INSERT INTO kv (key, value) VALUES ('portal', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(JSON.stringify({
                storeName: str(b.storeName, 80).trim(),
                about: str(b.about, 600).trim(),
                hours: str(b.hours, 200).trim(),
                contact: str(b.contact, 200).trim(),
                address: str(b.address, 200).trim(),
                replyTime: str(b.replyTime, 100).trim(),
            }));
            return json({ info: portalInfo() });
        }
        if (p === '/api/faq' && method === 'POST') {
            need(a, 'chat.reply');
            const b = await readJson(req),
                q = str(b.question, 200).trim(),
                ans = str(b.answer, 1000).trim();
            if (!q || !ans) throw httpError(400, 'Enter a question and an answer');
            const info = db.prepare('INSERT INTO faq (question, answer, keywords) VALUES (?, ?, ?)').run(q, ans, str(b.keywords, 200).trim());
            return json({ id: Number(info.lastInsertRowid) }, 201);
        }
        if ((m = p.match(/^\/api\/faq\/(\d+)$/))) {
            need(a, 'chat.reply');
            if (method === 'PUT') {
                const b = await readJson(req),
                    q = str(b.question, 200).trim(),
                    ans = str(b.answer, 1000).trim();
                if (!q || !ans) throw httpError(400, 'Enter a question and an answer');
                db.prepare('UPDATE faq SET question = ?, answer = ?, keywords = ? WHERE id = ?').run(q, ans, str(b.keywords, 200).trim(), Number(m[1]));
                return json({ ok: true });
            }
            if (method === 'DELETE') { db.prepare('DELETE FROM faq WHERE id = ?').run(Number(m[1])); return json({ ok: true }); }
        }

        /* ---- customer side of the chat ---- */
        const msgPub = r => ({ id: r.id, sender: r.sender, body: r.body, at: r.created });
        if (p === '/api/my/messages' && method === 'GET') {
            need(a, 'portal.use');
            const channel = url.searchParams.get('channel') === 'admin' ? 'admin' : 'ai',
                after = Number(url.searchParams.get('after')) || 0;
            const rows = db.prepare('SELECT * FROM messages WHERE user_id = ? AND channel = ? AND id > ? ORDER BY id LIMIT 200').all(uid, channel, after);
            if (channel === 'admin') db.prepare("UPDATE messages SET read = 1 WHERE user_id = ? AND channel = 'admin' AND sender = 'admin' AND read = 0").run(uid);
            const unread = db.prepare("SELECT COUNT(*) n FROM messages WHERE user_id = ? AND channel = 'admin' AND sender = 'admin' AND read = 0").get(uid).n;
            return json({ messages: rows.map(msgPub), unread, muted: !!db.prepare('SELECT muted FROM users WHERE id = ?').get(uid).muted });
        }
        if (p === '/api/my/unread' && method === 'GET') {
            need(a, 'portal.use');
            return json({ unread: db.prepare("SELECT COUNT(*) n FROM messages WHERE user_id = ? AND channel = 'admin' AND sender = 'admin' AND read = 0").get(uid).n });
        }
        if (p === '/api/my/messages' && method === 'POST') {
            need(a, 'portal.use');
            if (db.prepare('SELECT muted FROM users WHERE id = ?').get(uid).muted) throw httpError(403, 'The admin has turned off messages from your account. Please contact the store another way.');
            if (limited(`msg|${uid}`, 30, 60e3)) throw httpError(429, 'You are sending messages too fast');
            const b = await readJson(req),
                body = str(b.body, 1000).trim();
            if (!body) throw httpError(400, 'Write a message first');
            const info = db.prepare("INSERT INTO messages (user_id, channel, sender, sender_id, body, created) VALUES (?, 'admin', 'customer', ?, ?, ?)").run(uid, uid, body, Date.now());
            db.prepare("UPDATE users SET chat_status = 'open' WHERE id = ?").run(uid);
            return json({ message: msgPub(db.prepare('SELECT * FROM messages WHERE id = ?').get(Number(info.lastInsertRowid))) }, 201);
        }
        if (p === '/api/my/ai' && method === 'POST') {
            need(a, 'portal.use');
            if (limited(`ai|${uid}`, 20, 60e3)) throw httpError(429, 'Please slow down a little');
            const b = await readJson(req),
                body = str(b.body, 500).trim();
            if (!body) throw httpError(400, 'Write a message first');
            const ins = db.prepare("INSERT INTO messages (user_id, channel, sender, sender_id, body, created, read) VALUES (?, 'ai', ?, ?, ?, ?, 1)");
            const q = ins.run(uid, 'customer', uid, body, Date.now());
            const ans = await customerAnswer(a.user, body);
            const r = ins.run(uid, 'ai', null, ans.reply, Date.now());
            return json({ messages: [q, r].map(i => msgPub(db.prepare('SELECT * FROM messages WHERE id = ?').get(Number(i.lastInsertRowid)))), handoff: !!ans.handoff });
        }
        if (p === '/api/my/messages' && method === 'DELETE') { // customers can wipe their own assistant history
            need(a, 'portal.use');
            db.prepare("DELETE FROM messages WHERE user_id = ? AND channel = 'ai'").run(uid);
            return json({ ok: true });
        }

        /* ---- admin side of the chat ---- */
        if (p === '/api/chats' && method === 'GET') {
            need(a, 'chat.reply');
            const threads = db.prepare(`
        SELECT u.id, u.name, u.phone, u.email, u.avatar, u.role, u.chat_status AS status, u.muted,
          (SELECT body FROM messages m WHERE m.user_id = u.id AND m.channel = 'admin' ORDER BY m.id DESC LIMIT 1) AS last,
          (SELECT sender FROM messages m WHERE m.user_id = u.id AND m.channel = 'admin' ORDER BY m.id DESC LIMIT 1) AS lastSender,
          (SELECT created FROM messages m WHERE m.user_id = u.id AND m.channel = 'admin' ORDER BY m.id DESC LIMIT 1) AS lastAt,
          (SELECT COUNT(*) FROM messages m WHERE m.user_id = u.id AND m.channel = 'admin' AND m.sender = 'customer' AND m.read = 0) AS unread
        FROM users u WHERE u.id != ?
        ORDER BY COALESCE(lastAt, 0) DESC, u.id DESC`).all(uid).map(t => ({...t, email: t.email || (t.phone && t.phone.includes('@') ? t.phone : ''), avatar: t.avatar || '', muted: !!t.muted }));
            return json({ threads, unread: threads.reduce((s, t) => s + (t.status === 'resolved' ? 0 : t.unread), 0) });
        }
        if (p === '/api/chats/broadcast' && method === 'POST') { // one message to many people
            need(a, 'chat.reply');
            if (limited(`bc|${uid}`, 5, 3600e3)) throw httpError(429, 'You can announce at most 5 times an hour');
            const b = await readJson(req),
                body = str(b.body, 1000).trim(),
                audience = str(b.role, 30) || 'customer';
            if (!body) throw httpError(400, 'Write the announcement first');
            const targets = audience === 'all' ?
                db.prepare('SELECT id FROM users WHERE active = 1 AND id != ?').all(uid) :
                db.prepare('SELECT id FROM users WHERE active = 1 AND role = ? AND id != ?').all(audience, uid);
            const ins = db.prepare("INSERT INTO messages (user_id, channel, sender, sender_id, body, created) VALUES (?, 'admin', 'admin', ?, ?, ?)");
            db.exec('BEGIN');
            try {
                for (const t of targets) ins.run(t.id, uid, body, Date.now());
                db.exec('COMMIT');
            } catch (e) { db.exec('ROLLBACK'); throw e; }
            audit(a, 'chat.broadcast', null, `to ${targets.length} ${audience === 'all' ? 'people' : audience}: ${body.slice(0, 80)}`);
            return json({ sent: targets.length });
        }
        if (p === '/api/quick-replies') {
            need(a, 'chat.reply');
            if (method === 'GET') {
                const r = db.prepare("SELECT value FROM kv WHERE key = 'quick'").get();
                return json({ items: r ? JSON.parse(r.value) : DEFAULT_QUICK });
            }
            if (method === 'PUT') {
                const b = await readJson(req),
                    items = (Array.isArray(b.items) ? b.items : []).map(x => str(x, 300).trim()).filter(Boolean).slice(0, 12);
                db.prepare("INSERT INTO kv (key, value) VALUES ('quick', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(JSON.stringify(items));
                return json({ items });
            }
        }
        if ((m = p.match(/^\/api\/chats\/(\d+)$/)) && method === 'DELETE') { // clear a conversation
            need(a, 'chat.reply');
            const cu = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(m[1]));
            if (!cu) throw httpError(404, 'User not found');
            const n = Number(db.prepare("DELETE FROM messages WHERE user_id = ? AND channel = 'admin'").run(cu.id).changes);
            audit(a, 'chat.clear', cu, `${n} message${n === 1 ? '' : 's'}`);
            return json({ ok: true });
        }
        if ((m = p.match(/^\/api\/chats\/(\d+)\/(status|unread|mute)$/)) && method === 'POST') {
            need(a, 'chat.reply');
            const cu = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(m[1]));
            if (!cu) throw httpError(404, 'User not found');
            const b = await readJson(req);
            if (m[2] === 'status') {
                const st = b.status === 'resolved' ? 'resolved' : 'open';
                db.prepare('UPDATE users SET chat_status = ? WHERE id = ?').run(st, cu.id);
            } else if (m[2] === 'unread') {
                db.prepare("UPDATE messages SET read = 0 WHERE id = (SELECT MAX(id) FROM messages WHERE user_id = ? AND channel = 'admin' AND sender = 'customer')").run(cu.id);
            } else {
                if (cu.role === 'admin' && b.muted) throw httpError(400, 'Admins cannot be muted');
                db.prepare('UPDATE users SET muted = ? WHERE id = ?').run(b.muted ? 1 : 0, cu.id);
                audit(a, b.muted ? 'user.mute' : 'user.unmute', cu);
            }
            return json({ ok: true });
        }
        if ((m = p.match(/^\/api\/chats\/(\d+)\/messages$/))) {
            need(a, 'chat.reply');
            const cid = Number(m[1]);
            if (method === 'GET') {
                const after = Number(url.searchParams.get('after')) || 0;
                const rows = db.prepare("SELECT * FROM messages WHERE user_id = ? AND channel = 'admin' AND id > ? ORDER BY id LIMIT 200").all(cid, after);
                db.prepare("UPDATE messages SET read = 1 WHERE user_id = ? AND channel = 'admin' AND sender = 'customer' AND read = 0").run(cid);
                return json({ messages: rows.map(msgPub) });
            }
            if (method === 'POST') {
                const cu = db.prepare('SELECT id FROM users WHERE id = ?').get(cid);
                if (!cu) throw httpError(404, 'User not found');
                const b = await readJson(req),
                    body = str(b.body, 1000).trim();
                if (!body) throw httpError(400, 'Write a message first');
                const info = db.prepare("INSERT INTO messages (user_id, channel, sender, sender_id, body, created) VALUES (?, 'admin', 'admin', ?, ?, ?)").run(cid, uid, body, Date.now());
                return json({ message: msgPub(db.prepare('SELECT * FROM messages WHERE id = ?').get(Number(info.lastInsertRowid))) }, 201);
            }
        }

        json({ error: 'not found' }, 404);
    } catch (e) {
        const code = e.status || 500;
        try { res.headersSent ? res.end() : (res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }), res.end(JSON.stringify({ error: e.status ? e.message : 'Server error', ...(e.field ? { field: e.field } : {}) }))); } catch (_) { /* socket closed */ }
        if (!e.status) console.error(e);
    }
});

server.listen(process.env.PORT || 3000, '0.0.0.0', () => {
    console.log(`MoneyFlow is running on port ${process.env.PORT || 3000}`);
    console.log(`Data is stored in ${DB_FILE}`);
});

module.exports = app;