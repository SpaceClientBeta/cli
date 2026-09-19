const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const PORT = Number(process.env.PORT || 10000);
const ROOT = __dirname;
const SUPABASE_URL = String(process.env.SUPABASE_URL || '').trim().replace(/\/rest\/v1\/?$/, '');
const SUPABASE_SECRET_KEY = String(process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
const ADMIN_NICK = String(process.env.ADMIN_NICK || 'winzuxx').trim().toLowerCase();

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.warn('WARNING: SUPABASE_URL / SUPABASE_SECRET_KEY are not configured.');
}

const SUPABASE_TIMEOUT_MS = Number(process.env.SUPABASE_TIMEOUT_MS || 10000);

async function supabaseFetch(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SUPABASE_TIMEOUT_MS);
  try { return await fetch(url, { ...options, signal: controller.signal }); }
  finally { clearTimeout(timer); }
}

const supabase = SUPABASE_URL && SUPABASE_SECRET_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
      global: { fetch: supabaseFetch }
    })
  : null;

const resetCodes = new Map();
const resendState = new Map();

// Server activity log: stored in Supabase so the external monitor can follow it.
function getClientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || String(req.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, '');
}
function getClientDevice(userAgent, body = {}) {
  const ua = String(userAgent || '');
  const requested = String(body.deviceLabel || '').trim();
  const allowed = ['Windows 10', 'Windows 11', 'Windows', 'Android', 'Linux', 'Linux (Ubuntu)', 'Linux (Mint)'];
  if (allowed.includes(requested)) return requested;

  if (/Android/i.test(ua)) return 'Android';
  if (/Windows/i.test(ua)) return 'Windows';
  if (/Linux/i.test(ua)) {
    if (/Ubuntu/i.test(ua)) return 'Linux (Ubuntu)';
    if (/Linux Mint|Mint/i.test(ua)) return 'Linux (Mint)';
    return 'Linux';
  }
  return 'Неизвестное устройство';
}
function getClientMeta(req, body = {}) {
  const width = Number(body.screenWidth);
  const height = Number(body.screenHeight);
  const dpr = Number(body.devicePixelRatio);
  return {
    ip: getClientIp(req),
    user_agent: String(req.headers['user-agent'] || '').slice(0, 500),
    device: getClientDevice(req.headers['user-agent'], body),
    screen_width: Number.isInteger(width) && width > 0 && width <= 10000 ? width : null,
    screen_height: Number.isInteger(height) && height > 0 && height <= 10000 ? height : null,
    screen_dpr: Number.isFinite(dpr) && dpr > 0 && dpr <= 10 ? Math.round(dpr * 100) / 100 : null
  };
}
function adminUser(row) {
  const user = safeUser(row);
  if (!user) return null;
  return {
    ...user,
    lastIp: row.last_ip || null,
    lastDevice: row.last_device || getClientDevice(row.last_user_agent),
    lastUserAgent: row.last_user_agent || null,
    screenWidth: row.last_screen_width == null ? null : Number(row.last_screen_width),
    screenHeight: row.last_screen_height == null ? null : Number(row.last_screen_height),
    screenDpr: row.last_screen_dpr == null ? null : Number(row.last_screen_dpr)
  };
}
function auditActionName(url, method) {
  const map = {
    '/api/auth/login':'Вход в аккаунт',
    '/api/auth/register':'Регистрация аккаунта',
    '/api/auth/check-username':'Проверка имени пользователя',
    '/api/auth/me':'Проверка сессии',
    '/api/auth/change-password':'Смена пароля',
    '/api/auth/delete-account':'Удаление аккаунта',
    '/api/auth/logout':'Выход из аккаунта',
    '/api/admin/login':'Вход в админ-панель',
    '/api/admin/logout':'Выход из админ-панели',
    '/api/admin/find-player':'Поиск игрока',
    '/api/admin/ban':'Изменение блокировки',
    '/api/admin/role':'Изменение прав администратора',
    '/api/friends/search':'Поиск друга',
    '/api/friends/request':'Запрос в друзья',
    '/api/friends/requests':'Просмотр запросов в друзья',
    '/api/friends/respond':'Ответ на запрос в друзья',
    '/api/friends':'Список друзей',
    '/api/friends/messages':'Сообщения друзей',
    '/api/storage/sync':'Синхронизация хранилища',
  };
  return map[url] || `${method} ${url}`;
}
async function auditLog(req, action, details = '') {
  if (!supabase) return;
  try {
    const session = await getPersistentSession(req, 'user');
    const admin = session ? null : await getAdmin(req);
    const actor = session || admin;
    await supabase.from('activity_logs').insert({
      ip: getClientIp(req),
      nick: actor?.nick || null,
      action: String(action || '').slice(0, 200),
      details: String(details || '').slice(0, 500)
    });
  } catch (e) {
    console.warn('Audit log error:', e.message);
  }
}

// Sessions are stored in Supabase, not only in the Layero runtime memory.
// This means a login survives runtime restarts/redeploys and browser restarts.
function sessionHash(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}
async function createPersistentSession(email, nick, kind = 'user') {
  const t = token();
  const { error } = await supabase.from('sessions').insert({
    token_hash: sessionHash(t),
    email: String(email || '').trim().toLowerCase(),
    nick: String(nick || '').trim(),
    kind
  });
  if (error) throw error;
  return t;
}
async function getPersistentSession(req, kind = 'user') {
  const t = authToken(req);
  if (!t) return null;
  const { data, error } = await supabase.from('sessions').select('email,nick,kind,created_at').eq('token_hash', sessionHash(t)).eq('kind', kind).maybeSingle();
  if (error) throw error;
  return data ? { ...data, token: t } : null;
}
async function deletePersistentSession(tokenValue, kind = null) {
  if (!tokenValue) return;
  let query = supabase.from('sessions').delete().eq('token_hash', sessionHash(tokenValue));
  if (kind) query = query.eq('kind', kind);
  await query;
}
async function deleteSessionsForEmail(email, kind = null) {
  let query = supabase.from('sessions').delete().eq('email', String(email || '').trim().toLowerCase());
  if (kind) query = query.eq('kind', kind);
  await query;
}
async function updatePersistentSessionToken(oldToken, email, nick) {
  if (!oldToken) return;
  const { error } = await supabase.from('sessions').update({
    email: String(email || '').trim().toLowerCase(),
    nick: String(nick || '').trim()
  }).eq('token_hash', sessionHash(oldToken));
  if (error) throw error;
}

const ALLOWED_ORIGINS = new Set([
  'https://spaceclientbeta.github.io',
  'https://spaceclientbeta.layero.app',
  'https://space-client.layero.app',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
]);

function isAllowedOrigin(origin) {
  if (ALLOWED_ORIGINS.has(origin)) return true;
  // GitHub Pages project sites can use any *.github.io origin.
  try {
    const u = new URL(origin);
    return u.protocol === 'https:' && u.hostname.endsWith('.github.io');
  } catch {
    return false;
  }
}

function corsHeaders(req) {
  const origin = String(req.headers.origin || '');
  const headers = {
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Vary': 'Origin'
  };
  if (isAllowedOrigin(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Credentials'] = 'true';
  }
  return headers;
}

function json(res, status, body, req = null) {
  if (!req && res._corsRequest) req = res._corsRequest;
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...(req ? corsHeaders(req) : {})
  };
  res.writeHead(status, headers);
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1024 * 1024) { req.destroy(); reject(new Error('Слишком большой запрос.')); }
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { reject(new Error('Некорректный JSON.')); }
    });
    req.on('error', reject);
  });
}

function requireSupabase(res) {
  if (supabase) return true;
  json(res, 503, { message: 'Supabase не настроен. Добавьте SUPABASE_URL и SUPABASE_SECRET_KEY в переменные окружения Layero.' });
  return false;
}

function normalizeNick(value) { return String(value || '').trim().toLowerCase(); }
function validNick(value) { return /^[A-Za-zА-Яа-яЁё0-9_ .-]{3,24}$/.test(String(value || '').trim()); }
function validEmail(value) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim()); }
function token() { return crypto.randomBytes(32).toString('hex'); }

function safeUser(row) {
  if (!row) return null;
  return {
    email: row.email,
    nick: row.nick,
    balance: Number(row.balance || 0),
    banned: !!row.banned,
    plan: row.plan || null,
    isAdmin: normalizeNick(row.nick) === ADMIN_NICK || !!row.is_admin,
    expires: row.expires == null ? null : new Date(row.expires).getTime(),
    registeredAt: row.registered_at ? new Date(row.registered_at).getTime() : null,
    lastSeen: row.last_seen ? new Date(row.last_seen).getTime() : null,
    isOnline: !!row.is_online,
    lastIp: row.last_ip || null,
    lastDevice: row.last_device || getClientDevice(row.last_user_agent),
    lastUserAgent: row.last_user_agent || null,
    screenWidth: row.last_screen_width == null ? null : Number(row.last_screen_width),
    screenHeight: row.last_screen_height == null ? null : Number(row.last_screen_height),
    screenDpr: row.last_screen_dpr == null ? null : Number(row.last_screen_dpr)
  };
}

function authToken(req) {
  const value = String(req.headers.authorization || '');
  return value.startsWith('Bearer ') ? value.slice(7).trim() : '';
}
async function getUserSession(req) {
  return getPersistentSession(req, 'user');
}
function getCookie(req, name) {
  const raw = String(req.headers.cookie || '');
  const found = raw.split(';').map(x => x.trim()).find(x => x.startsWith(name + '='));
  return found ? decodeURIComponent(found.slice(name.length + 1)) : '';
}
function setCookie(res, name, value, maxAge) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=${process.env.NODE_ENV === 'production' ? 'None' : 'Lax'}${secure}`);
}
function clearCookie(res, name) { res.setHeader('Set-Cookie', `${name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`); }
async function getAdmin(req) {
  const cookieToken = getCookie(req, 'sc_admin');
  const bearer = authToken(req);
  const t = bearer || cookieToken;
  if (!t) return null;
  const { data, error } = await supabase.from('sessions').select('email,nick,kind,created_at').eq('token_hash', sessionHash(t)).eq('kind', 'admin').maybeSingle();
  if (error) throw error;
  return data ? { ...data, token: t } : null;
}

async function findByNick(nick) {
  const { data, error } = await supabase.from('accounts').select('*').eq('nick_normalized', normalizeNick(nick)).maybeSingle();
  if (error) throw error;
  return data || null;
}
async function findByEmail(email) {
  const { data, error } = await supabase.from('accounts').select('*').eq('email', String(email || '').trim().toLowerCase()).maybeSingle();
  if (error) throw error;
  return data || null;
}


async function handleLauncherAuthorize(req, res) {
  if (!requireSupabase(res)) return;
  const body = await readBody(req);
  const callback = String(body.callback || '').trim();
  const nonce = String(body.nonce || '').trim();
  const bearer = authToken(req);
  if (!bearer || !nonce || !/^https?:\/\/127\.0\.0\.1:\d+\/callback$/.test(callback)) return json(res, 400, { message: 'Некорректные данные лаунчера.' });
  const session = await getPersistentSession(req, 'user');
  if (!session) return json(res, 401, { message: 'Сначала войдите в аккаунт.' });
  const account = await findByEmail(session.email);
  if (!account || account.banned) return json(res, 403, { message: account?.banned ? 'Этот аккаунт заблокирован.' : 'Аккаунт не найден.' });
  const ticket = crypto.randomBytes(32).toString('hex');
  const ticketHash = sessionHash(ticket);
  const expires = new Date(Date.now() + 2 * 60 * 1000).toISOString();
  const { error } = await supabase.from('launcher_tickets').insert({ ticket_hash: ticketHash, token_hash: sessionHash(bearer), token_value: bearer, email: account.email, nick: account.nick, nonce, callback_url: callback, expires_at: expires });
  if (error) return json(res, 500, { message: error.message });
  json(res, 200, { ok: true, redirect: `${callback}?ticket=${encodeURIComponent(ticket)}&nonce=${encodeURIComponent(nonce)}` });
}
async function handleLauncherExchange(req, res) {
  if (!requireSupabase(res)) return;
  const body = await readBody(req);
  const ticket = String(body.ticket || '').trim();
  const nonce = String(body.nonce || '').trim();
  if (!ticket || !nonce) return json(res, 400, { message: 'Недействительный код авторизации.' });
  const { data: row, error: findError } = await supabase.from('launcher_tickets').select('*').eq('ticket_hash', sessionHash(ticket)).eq('nonce', nonce).maybeSingle();
  if (findError) return json(res, 500, { message: findError.message });
  if (!row) return json(res, 401, { message: 'Код авторизации не найден или уже использован.' });
  if (new Date(row.expires_at).getTime() < Date.now()) { await supabase.from('launcher_tickets').delete().eq('ticket_hash', row.ticket_hash); return json(res, 401, { message: 'Код авторизации истёк. Запусти вход ещё раз.' }); }
  const { error: delError } = await supabase.from('launcher_tickets').delete().eq('ticket_hash', row.ticket_hash);
  if (delError) return json(res, 500, { message: delError.message });
  const { data: account } = await supabase.from('accounts').select('email,nick,banned').eq('email', row.email).maybeSingle();
  if (!account || account.banned) return json(res, 403, { message: account?.banned ? 'Этот аккаунт заблокирован.' : 'Аккаунт не найден.' });
  // Return the same website session token that was used to authorize the ticket.
  // It is transferred only to the local launcher over HTTPS + localhost callback.
  const { data: sessionRow, error: sessionError } = await supabase.from('sessions').select('email,nick,kind').eq('token_hash', row.token_hash).eq('kind', 'user').maybeSingle();
  if (sessionError || !sessionRow) return json(res, 401, { message: 'Сессия сайта больше недействительна. Войди снова.' });
  json(res, 200, { ok: true, token: row.token_value, user: { email: account.email, nick: account.nick } });
}

async function handleRegister(req, res) {
  if (!requireSupabase(res)) return;
  const body = await readBody(req);
  const nick = String(body.nick || body.username || '').trim();
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!validNick(nick)) return json(res, 400, { message: 'Имя пользователя: 3–24 символа, без спецсимволов.' });
  if (!validEmail(email)) return json(res, 400, { message: 'Введите корректную почту.' });
  if (password.length < 8) return json(res, 400, { message: 'Пароль должен содержать минимум 8 символов.' });

  const [emailUser, nickUser] = await Promise.all([findByEmail(email), findByNick(nick)]);
  if (emailUser) return json(res, 409, { message: 'Такой аккаунт уже существует.' });
  if (nickUser) return json(res, 409, { message: 'Этот ник уже занят.' });

  const passwordHash = await bcrypt.hash(password, 12);
  const meta = getClientMeta(req, body);
  const row = { email, nick, nick_normalized: normalizeNick(nick), password_hash: passwordHash, balance: 0, banned: false, plan: 'none', expires: null, last_seen: new Date().toISOString(), is_online: true, last_ip: meta.ip, last_user_agent: meta.user_agent, last_device: meta.device, last_screen_width: meta.screen_width, last_screen_height: meta.screen_height, last_screen_dpr: meta.screen_dpr };
  const { data, error } = await supabase.from('accounts').insert(row).select('*').single();
  if (error) return json(res, 500, { message: error.message });

  const t = await createPersistentSession(data.email, data.nick, 'user');
  json(res, 200, { ok: true, token: t, user: safeUser(data) });
}

async function handleLogin(req, res) {
  if (!requireSupabase(res)) return;
  const body = await readBody(req);
  const nick = String(body.nick || body.username || '').trim();
  const password = String(body.password || '');
  const account = await findByNick(nick);
  if (!account) return json(res, 404, { message: 'Аккаунт с таким именем пользователя не найден.' });
  if (account.banned) return json(res, 403, { message: 'Этот аккаунт заблокирован администратором.' });
  if (!account.password_hash || !(await bcrypt.compare(password, account.password_hash))) return json(res, 401, { message: 'Неверный пароль.' });

  const now = new Date().toISOString();
  const meta = getClientMeta(req, body);
  const { data: updatedAccount } = await supabase.from('accounts').update({ last_seen: now, is_online: true, last_ip: meta.ip, last_user_agent: meta.user_agent, last_device: meta.device, last_screen_width: meta.screen_width, last_screen_height: meta.screen_height, last_screen_dpr: meta.screen_dpr }).eq('email', account.email).select('*').single();
  const t = await createPersistentSession(account.email, account.nick, 'user');
  json(res, 200, { ok: true, token: t, user: safeUser(updatedAccount || { ...account, last_seen: now }) });
}

async function handleCheckUsername(req, res) {
  if (!requireSupabase(res)) return;
  const body = await readBody(req);
  const account = await findByNick(body.nick);
  if (!account) return json(res, 404, { message: 'Аккаунт с таким именем пользователя не найден.' });
  json(res, 200, { ok: true, email: account.email, nick: account.nick });
}

async function handleMigrateLocal(req, res) {
  if (!requireSupabase(res)) return;
  const body = await readBody(req);
  const nick = String(body.nick || '').trim();
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!validNick(nick) || !validEmail(email) || password.length < 8) return json(res, 400, { message: 'Некорректные данные аккаунта.' });
  const existing = await findByEmail(email);
  if (existing) return json(res, 200, { ok: true, exists: true });
  const existingNick = await findByNick(nick);
  if (existingNick) return json(res, 409, { message: 'Этот ник уже занят.' });
  const passwordHash = await bcrypt.hash(password, 12);
  const { error } = await supabase.from('accounts').insert({ email, nick, nick_normalized: normalizeNick(nick), password_hash: passwordHash, balance: 0, banned: false, plan: 'none', expires: null, last_seen: null });
  if (error) return json(res, 500, { message: error.message });
  json(res, 200, { ok: true, migrated: true });
}

async function handleMe(req, res) {
  if (!requireSupabase(res)) return;
  const session = await getUserSession(req);
  if (!session) return json(res, 401, { message: 'Сессия истекла.' });
  const account = await findByEmail(session.email);
  if (!account || account.banned) return json(res, 401, { message: account?.banned ? 'Этот аккаунт заблокирован администратором.' : 'Аккаунт не найден.' });
  const now = new Date().toISOString();
  const meBody = await readBody(req).catch(() => ({}));
  const meta = getClientMeta(req, meBody);
  // /me may be called without browser activity metadata; don't erase a
  // previously detected Windows 10/11 or Linux label in that case.
  if (!meBody.deviceLabel && account.last_device) meta.device = account.last_device;
  const { data: updatedAccount, error } = await supabase.from('accounts').update({
    last_seen: now, is_online: true, last_ip: meta.ip, last_user_agent: meta.user_agent,
    last_device: meta.device, last_screen_width: meta.screen_width, last_screen_height: meta.screen_height, last_screen_dpr: meta.screen_dpr
  }).eq('email', account.email).select('*').single();
  if (error) return json(res, 500, { message: error.message });
  session.nick = updatedAccount.nick;
  json(res, 200, { ok: true, user: safeUser(updatedAccount) });
}

async function handleActivity(req, res) {
  if (!requireSupabase(res)) return;
  const body = await readBody(req);
  const session = await getUserSession(req);
  if (!session) return json(res, 401, { message: 'Сессия истекла.' });
  const account = await findByEmail(session.email);
  if (!account || account.banned) return json(res, 401, { message: account?.banned ? 'Этот аккаунт заблокирован администратором.' : 'Аккаунт не найден.' });
  const now = new Date().toISOString();
  const meta = getClientMeta(req, body);
  const offline = new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams.get('offline') === '1';
  const patch = offline ? { is_online: false } : { last_seen: now, is_online: true, last_ip: meta.ip, last_user_agent: meta.user_agent, last_device: meta.device, last_screen_width: meta.screen_width, last_screen_height: meta.screen_height, last_screen_dpr: meta.screen_dpr };
  const { data: updatedAccount, error } = await supabase.from('accounts').update(patch).eq('email', account.email).select('*').single();
  if (error) return json(res, 500, { message: error.message });
  const user = safeUser(updatedAccount || { ...account, ...patch });
  json(res, 200, {
    ok: true,
    lastSeen: offline ? (account.last_seen ? new Date(account.last_seen).getTime() : null) : Date.now(),
    online: !offline,
    activity: { lastIp: user.lastIp, lastDevice: user.lastDevice, screenWidth: user.screenWidth, screenHeight: user.screenHeight, screenDpr: user.screenDpr }
  });
}

async function handleLogout(req, res) {
  const t = authToken(req);
  if (t) {
    try {
      const session = await getUserSession(req);
      if (session) await supabase.from('accounts').update({ is_online: false }).eq('email', session.email);
    } catch (_) {}
    await deletePersistentSession(t, 'user');
  }
  json(res, 200, { ok: true });
}

async function handleUpdateProfile(req, res) {
  if (!requireSupabase(res)) return;
  const session = await getUserSession(req); if (!session) return json(res, 401, { message: 'Сессия истекла.' });
  const body = await readBody(req);
  const currentPassword = String(body.currentPassword || '');
  const nick = String(body.nick || '').trim();
  const email = String(body.email || '').trim().toLowerCase();
  const account = await findByEmail(session.email);
  if (!account) return json(res, 404, { message: 'Аккаунт не найден.' });
  if (!(await bcrypt.compare(currentPassword, account.password_hash || ''))) return json(res, 401, { message: 'Неверный текущий пароль.' });
  if (!validNick(nick)) return json(res, 400, { message: 'Ник: 3–24 символа, без спецсимволов.' });
  if (!validEmail(email)) return json(res, 400, { message: 'Введите корректную почту.' });
  if (email !== account.email && await findByEmail(email)) return json(res, 409, { message: 'Аккаунт с такой почтой уже существует.' });
  if (normalizeNick(nick) !== normalizeNick(account.nick) && await findByNick(nick)) return json(res, 409, { message: 'Этот ник уже занят.' });

  const { data, error } = await supabase.from('accounts').update({ email, nick, nick_normalized: normalizeNick(nick) }).eq('email', account.email).select('*').single();
  if (error) return json(res, 500, { message: error.message });
  const currentToken = authToken(req);
  await updatePersistentSessionToken(currentToken, data.email, data.nick);
  session.email = data.email; session.nick = data.nick;
  json(res, 200, { ok: true, user: safeUser(data) });
}

async function handleChangePassword(req, res) {
  if (!requireSupabase(res)) return;
  const session = await getUserSession(req); if (!session) return json(res, 401, { message: 'Сессия истекла.' });
  const body = await readBody(req);
  const currentPassword = String(body.currentPassword || '');
  const newPassword = String(body.newPassword || '');
  const account = await findByEmail(session.email);
  if (!account) return json(res, 404, { message: 'Аккаунт не найден.' });
  if (!(await bcrypt.compare(currentPassword, account.password_hash || ''))) return json(res, 401, { message: 'Неверный текущий пароль.' });
  if (newPassword.length < 8) return json(res, 400, { message: 'Новый пароль должен содержать минимум 8 символов.' });
  if (newPassword === currentPassword) return json(res, 400, { message: 'Новый пароль должен отличаться от текущего.' });
  const password_hash = await bcrypt.hash(newPassword, 12);
  const { error } = await supabase.from('accounts').update({ password_hash }).eq('email', account.email);
  if (error) return json(res, 500, { message: error.message });
  json(res, 200, { ok: true });
}

async function handleDeleteAccount(req, res) {
  if (!requireSupabase(res)) return;
  const session = await getUserSession(req); if (!session) return json(res, 401, { message: 'Сессия истекла.' });
  const body = await readBody(req);
  const account = await findByEmail(session.email);
  if (!account) return json(res, 404, { message: 'Аккаунт не найден.' });
  if (!(await bcrypt.compare(String(body.password || ''), account.password_hash || ''))) return json(res, 401, { message: 'Неверный пароль.' });
  if (normalizeNick(account.nick) === ADMIN_NICK) return json(res, 400, { message: 'Администратор не может удалить аккаунт через эту форму.' });
  const { error } = await supabase.from('accounts').delete().eq('email', account.email);
  if (error) return json(res, 500, { message: error.message });
  await deleteSessionsForEmail(account.email);
  json(res, 200, { ok: true });
}

async function handleAdminLogin(req, res) {
  if (!requireSupabase(res)) return;
  const session = await getUserSession(req);
  if (!session) return json(res, 401, { message: 'Сначала войдите в аккаунт администратора.' });
  const account = await findByEmail(session.email);
  const adminAllowed = !!account && !account.banned && (normalizeNick(account.nick) === ADMIN_NICK || !!account.is_admin);
  if (!adminAllowed) return json(res, 403, { message: 'Доступ к админ-панели запрещён.' });
  const t = await createPersistentSession(account.email, account.nick, 'admin');
  setCookie(res, 'sc_admin', t, 315360000);
  json(res, 200, { ok: true, adminToken: t });
}
async function handleAdminLogout(req, res) {
  const cookieToken = getCookie(req, 'sc_admin');
  const bearer = authToken(req);
  if (cookieToken) await deletePersistentSession(cookieToken, 'admin');
  if (bearer) await deletePersistentSession(bearer, 'admin');
  clearCookie(res, 'sc_admin');
  json(res, 200, { ok: true });
}

async function requireAdmin(req, res) {
  const admin = await getAdmin(req);
  if (!admin) { json(res, 401, { message: 'Сессия админа истекла.' }); return false; }
  const account = await findByEmail(admin.email);
  if (!account || account.banned || (normalizeNick(account.nick) !== ADMIN_NICK && !account.is_admin)) {
    const t = getCookie(req, 'sc_admin') || authToken(req);
    if (t) await deletePersistentSession(t, 'admin').catch(() => {});
    return json(res, 403, { message: 'Доступ к админ-панели запрещён.' }), false;
  }
  return true;
}
async function handleAdminFind(req, res) {
  if (!requireSupabase(res) || !(await requireAdmin(req, res))) return;
  const body = await readBody(req); const nick = normalizeNick(body.nick);
  if (!nick) return json(res, 400, { message: 'Укажи ник игрока.' });
  const account = await findByNick(nick);
  if (!account) return json(res, 404, { message: 'Игрок с таким ником не найден.' });
  json(res, 200, { ok: true, player: adminUser(account) });
}
async function handleAdminActivity(req, res) {
  if (!requireSupabase(res) || !(await requireAdmin(req, res))) return;
  const body = await readBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  const account = await findByEmail(email);
  if (!account) return json(res, 404, { message: 'Игрок не найден.' });
  const { data, error } = await supabase.from('activity_logs')
    .select('ip,nick,action,created_at')
    .eq('nick', account.nick)
    .order('created_at', { ascending: false })
    .limit(20);
  if (error) return json(res, 500, { message: error.message });
  json(res, 200, { ok: true, player: adminUser(account), history: Array.isArray(data) ? data : [] });
}
async function handleAdminBan(req, res) {
  if (!requireSupabase(res) || !(await requireAdmin(req, res))) return;
  const body = await readBody(req); const email = String(body.email || '').trim().toLowerCase(); const banned = !!body.banned;
  const account = await findByEmail(email); if (!account) return json(res, 404, { message: 'Игрок не найден.' });
  const currentAdmin = await getAdmin(req);
  if (banned && currentAdmin && String(currentAdmin.email || '').toLowerCase() === email) return json(res, 400, { message: 'Нельзя заблокировать самого себя.' });
  if (normalizeNick(account.nick) === ADMIN_NICK && banned) return json(res, 400, { message: 'Нельзя заблокировать администратора.' });
  const { data, error } = await supabase.from('accounts').update({ banned }).eq('email', email).select('*').single();
  if (error) return json(res, 500, { message: error.message });
  json(res, 200, { ok: true, player: adminUser(data) });
}

async function handleAdminRole(req, res) {
  if (!requireSupabase(res) || !(await requireAdmin(req, res))) return;
  const body = await readBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  const makeAdmin = !!body.isAdmin;
  const account = await findByEmail(email);
  if (!account) return json(res, 404, { message: 'Игрок не найден.' });
  if (normalizeNick(account.nick) === ADMIN_NICK) {
    return json(res, 400, { message: makeAdmin ? 'Нельзя повторно выдать админку winzuxx — он уже главный администратор.' : 'Нельзя забрать админку у winzuxx — это главный администратор.' });
  }
  if (!makeAdmin && email === String((await getAdmin(req))?.email || '').toLowerCase()) {
    return json(res, 400, { message: 'Нельзя забрать админку у самого себя.' });
  }
  const { data, error } = await supabase.from('accounts').update({ is_admin: makeAdmin }).eq('email', email).select('*').single();
  if (error) return json(res, 500, { message: error.message });
  if (!makeAdmin) await deleteSessionsForEmail(email, 'admin');
  json(res, 200, { ok: true, player: adminUser(data) });
}

// ===== Friends / real-time chat =====
function friendPair(a, b) {
  const x = String(a || '').trim().toLowerCase();
  const y = String(b || '').trim().toLowerCase();
  return x < y ? [x, y] : [y, x];
}
function friendOnline(lastSeen, isOnline = null) {
  if (!lastSeen) return false;
  const fresh = Date.now() - new Date(lastSeen).getTime() < 12000;
  return isOnline === false ? false : fresh && (isOnline === true || isOnline == null);
}
function publicFriend(row) {
  return { email: row.email, nick: row.nick, lastSeen: row.last_seen ? new Date(row.last_seen).getTime() : null, online: friendOnline(row.last_seen, row.is_online) };
}
async function requireUser(req, res) {
  if (!requireSupabase(res)) return null;
  const session = await getUserSession(req);
  if (!session) { json(res, 401, { message: 'Сначала войдите в аккаунт.' }); return null; }
  const account = await findByEmail(session.email);
  if (!account || account.banned) { json(res, 403, { message: 'Доступ к аккаунту запрещён.' }); return null; }
  return account;
}
async function findFriendRequestBetween(a, b, statuses = ['accepted']) {
  const x = String(a || '').trim().toLowerCase();
  const y = String(b || '').trim().toLowerCase();
  const { data, error } = await supabase
    .from('friend_requests')
    .select('id,status,requester_email,addressee_email')
    .in('status', statuses)
    .or(`and(requester_email.eq.${x},addressee_email.eq.${y}),and(requester_email.eq.${y},addressee_email.eq.${x})`)
    .order('created_at', { ascending: false })
    .limit(1);
  if (error) throw error;
  return data?.[0] || null;
}

async function handleFriendSearch(req, res) {
  const me = await requireUser(req,res); if (!me) return;
  const body = await readBody(req); const nick = normalizeNick(body.nick);
  if (!nick || nick.length < 2) return json(res,400,{message:'Введи ник игрока.'});
  const account = await findByNick(nick);
  if (!account) return json(res,404,{message:'Игрок с таким ником не найден.'});
  if (account.email.toLowerCase() === me.email.toLowerCase()) return json(res,400,{message:'Нельзя добавить самого себя в друзья.'});
  const request = await findFriendRequestBetween(me.email, account.email, ['pending','accepted']);
  json(res,200,{ok:true,player:publicFriend(account),friend:request?.status === 'accepted',status:request?.status||null});
}
async function handleFriendRequest(req,res){
  const me=await requireUser(req,res); if(!me)return;
  const body=await readBody(req); const nick=normalizeNick(body.nick); const target=await findByNick(nick);
  if(!target)return json(res,404,{message:'Игрок с таким ником не найден.'});
  if(target.email.toLowerCase()===me.email.toLowerCase())return json(res,400,{message:'Нельзя отправить запрос самому себе.'});
  const existingFriend = await findFriendRequestBetween(me.email, target.email, ['accepted']);
  if(existingFriend)return json(res,400,{message:'Вы уже друзья.'});
  const existing = await findFriendRequestBetween(me.email, target.email, ['pending']);
  if(existing){
    if(existing.requester_email.toLowerCase()===target.email.toLowerCase()) return json(res,200,{ok:true,message:'У этого игрока уже есть запрос к тебе.',incoming:true});
    return json(res,400,{message:'Запрос уже отправлен.'});
  }
  const {error}=await supabase.from('friend_requests').insert({requester_email:me.email,addressee_email:target.email,status:'pending'});
  if(error)return json(res,500,{message:error.message});
  json(res,200,{ok:true,message:'Запрос в друзья отправлен.'});
}
async function handleFriendRequests(req,res){
  const me=await requireUser(req,res);if(!me)return;
  const {data,error}=await supabase.from('friend_requests').select('id,requester_email,addressee_email,status,created_at').eq('addressee_email',me.email).eq('status','pending').order('created_at',{ascending:false});
  if(error)return json(res,500,{message:error.message});
  const items=[];
  for(const r of data||[]){const p=await findByEmail(r.requester_email);if(p)items.push({id:r.id,player:publicFriend(p),createdAt:new Date(r.created_at).getTime()});}
  json(res,200,{ok:true,requests:items});
}
async function handleFriendRespond(req,res){
  const me=await requireUser(req,res);if(!me)return;
  const body=await readBody(req); const id=String(body.id||''); const accept=!!body.accept;
  const {data:r,error}=await supabase.from('friend_requests').select('*').eq('id',id).eq('addressee_email',me.email).eq('status','pending').maybeSingle();
  if(error)return json(res,500,{message:error.message}); if(!r)return json(res,404,{message:'Запрос не найден.'});
  if(!accept){await supabase.from('friend_requests').update({status:'rejected',responded_at:new Date().toISOString()}).eq('id',id);return json(res,200,{ok:true});}
  const {error:ue}=await supabase.from('friend_requests').update({status:'accepted',responded_at:new Date().toISOString()}).eq('id',id);
  if(ue)return json(res,500,{message:ue.message});
  json(res,200,{ok:true});
}
async function handleFriendsList(req,res){
  const me=await requireUser(req,res);if(!me)return;
  const {data,error}=await supabase.from('friend_requests').select('requester_email,addressee_email,created_at').eq('status','accepted').or(`requester_email.eq.${me.email},addressee_email.eq.${me.email}`).order('created_at',{ascending:false});
  if(error)return json(res,500,{message:error.message});
  const items=[]; const seen=new Set();
  for(const f of data||[]){
    const email=String(f.requester_email).toLowerCase()===me.email.toLowerCase()?f.addressee_email:f.requester_email;
    if(seen.has(email.toLowerCase())) continue;
    seen.add(email.toLowerCase());
    const p=await findByEmail(email);if(p)items.push(publicFriend(p));
  }
  items.sort((x,y)=>Number(y.online)-Number(x.online)||x.nick.localeCompare(y.nick));
  json(res,200,{ok:true,friends:items});
}
async function handleFriendUnread(req,res){
  const me=await requireUser(req,res); if(!me)return;
  const {data,error}=await supabase.from('messages').select('id,sender_email,body,created_at').eq('receiver_email',me.email).is('read_at',null).order('created_at',{ascending:true}).limit(100);
  if(error)return json(res,500,{message:error.message});
  const counts={};
  const nickCache=new Map();
  const notifications=[];
  for(const row of data||[]){
    const k=String(row.sender_email||'').toLowerCase();
    counts[k]=(counts[k]||0)+1;
    if(!nickCache.has(k)){ const p=await findByEmail(row.sender_email); nickCache.set(k,p?.nick||''); }
    notifications.push({id:row.id,senderEmail:row.sender_email,senderNick:nickCache.get(k)||'',body:String(row.body||'').slice(0,140),createdAt:new Date(row.created_at).getTime()});
  }
  json(res,200,{ok:true,total:(data||[]).length,counts,notifications});
}

async function handleFriendMessages(req,res){
  const me=await requireUser(req,res);if(!me)return;
  const target=String(req.url.split('?')[1]||'').match(/friendEmail=([^&]+)/)?.[1]||'';
  const friendEmail=decodeURIComponent(target).trim().toLowerCase(); if(!friendEmail)return json(res,400,{message:'Не указан друг.'});
  const fr=await findFriendRequestBetween(me.email,friendEmail,['accepted']);
  if(!fr)return json(res,403,{message:'Этот игрок не находится в списке друзей.'});
  const {data,error}=await supabase.from('messages').select('id,sender_email,receiver_email,body,created_at,read_at,edited_at,deleted_at').or(`and(sender_email.eq.${me.email},receiver_email.eq.${friendEmail}),and(sender_email.eq.${friendEmail},receiver_email.eq.${me.email})`).order('created_at',{ascending:true}).limit(100);
  if(error)return json(res,500,{message:error.message});
  const incoming=(data||[]).filter(m=>String(m.receiver_email).toLowerCase()===me.email.toLowerCase() && !m.read_at).map(m=>m.id);
  if(incoming.length) await supabase.from('messages').update({read_at:new Date().toISOString()}).in('id',incoming);
  const ids=(data||[]).map(m=>m.id);
  let reactions=[];
  if(ids.length){ const rr=await supabase.from('message_reactions').select('message_id,email,emoji').in('message_id',ids); if(!rr.error) reactions=rr.data||[]; }
  const byId={};
  for(const r of reactions){ (byId[r.message_id] ||= []).push({email:r.email,emoji:r.emoji}); }
  json(res,200,{ok:true,messages:(data||[]).map(m=>({id:m.id,senderEmail:m.sender_email,body:m.deleted_at?'Сообщение удалено':m.body,deleted:!!m.deleted_at,edited:!!m.edited_at,createdAt:new Date(m.created_at).getTime(),readAt:m.read_at?new Date(m.read_at).getTime():null,reactions:byId[m.id]||[]}))});
}
async function handleFriendMessage(req,res){
  const me=await requireUser(req,res);if(!me)return;
  const body=await readBody(req); const friendEmail=String(body.friendEmail||'').trim().toLowerCase(); const text=String(body.message||'').trim();
  if(!friendEmail||!text)return json(res,400,{message:'Напиши сообщение.'}); if(text.length>2000)return json(res,400,{message:'Сообщение слишком длинное.'});
  const fr=await findFriendRequestBetween(me.email,friendEmail,['accepted']);
  if(!fr)return json(res,403,{message:'Сначала добавьте друг друга в друзья.'});
  const target=await findByEmail(friendEmail); if(!target)return json(res,404,{message:'Игрок не найден.'});
  const {data,error}=await supabase.from('messages').insert({sender_email:me.email,receiver_email:friendEmail,body:text}).select('id,sender_email,receiver_email,body,created_at,edited_at,deleted_at').single();
  if(error)return json(res,500,{message:error.message});
  json(res,200,{ok:true,message:{id:data.id,senderEmail:data.sender_email,body:data.body,createdAt:new Date(data.created_at).getTime(),edited:false,deleted:false,reactions:[]}});
}

async function getMessageForUser(me, id) {
  const {data,error}=await supabase.from('messages').select('id,sender_email,receiver_email,body,created_at,edited_at,deleted_at').eq('id',id).maybeSingle();
  if(error) throw error; if(!data) return null;
  const mine=String(data.sender_email).toLowerCase()===String(me.email).toLowerCase();
  const friend=await findFriendRequestBetween(me.email, mine?data.receiver_email:data.sender_email, ['accepted']);
  if(!friend) return null;
  return data;
}
async function handleFriendMessageEdit(req,res){
  const me=await requireUser(req,res);if(!me)return;
  const body=await readBody(req);const id=String(body.id||'');const text=String(body.message||'').trim();
  if(!id||!text)return json(res,400,{message:'Напиши сообщение.'});if(text.length>2000)return json(res,400,{message:'Сообщение слишком длинное.'});
  const m=await getMessageForUser(me,id);if(!m)return json(res,404,{message:'Сообщение не найдено.'});
  if(String(m.sender_email).toLowerCase()!==me.email.toLowerCase())return json(res,403,{message:'Можно изменять только свои сообщения.'});
  if(m.deleted_at)return json(res,400,{message:'Удалённое сообщение нельзя изменить.'});
  const {data,error}=await supabase.from('messages').update({body:text,edited_at:new Date().toISOString()}).eq('id',id).eq('sender_email',me.email).select('id,body,edited_at').single();
  if(error)return json(res,500,{message:error.message});json(res,200,{ok:true,message:{id:data.id,body:data.body,edited:true,editedAt:new Date(data.edited_at).getTime()}});
}
async function handleFriendMessageDelete(req,res){
  const me=await requireUser(req,res);if(!me)return;
  const body=await readBody(req);const id=String(body.id||'');if(!id)return json(res,400,{message:'Сообщение не найдено.'});
  const m=await getMessageForUser(me,id);if(!m)return json(res,404,{message:'Сообщение не найдено.'});
  if(String(m.sender_email).toLowerCase()!==me.email.toLowerCase())return json(res,403,{message:'Можно удалять только свои сообщения.'});
  const {error}=await supabase.from('messages').update({body:'',deleted_at:new Date().toISOString(),edited_at:null}).eq('id',id).eq('sender_email',me.email);
  if(error)return json(res,500,{message:error.message});json(res,200,{ok:true});
}
async function handleFriendMessageReaction(req,res){
  const me=await requireUser(req,res);if(!me)return;
  const body=await readBody(req);const id=String(body.id||'');const emoji=String(body.emoji||'').trim();
  const allowed=new Set(['❤️','😂','😍','😮','😢','👍','🔥','🎉']);
  if(!id||!allowed.has(emoji))return json(res,400,{message:'Недопустимая реакция.'});
  const m=await getMessageForUser(me,id);if(!m)return json(res,404,{message:'Сообщение не найдено.'});
  // One reaction per user per message. Clicking the same reaction removes it;
  // clicking another reaction replaces the previous one.
  const {data:existing,error:findError}=await supabase.from('message_reactions').select('id,emoji').eq('message_id',id).eq('email',me.email).maybeSingle();
  if(findError)return json(res,500,{message:findError.message});
  if(existing && existing.emoji===emoji){
    const {error}=await supabase.from('message_reactions').delete().eq('id',existing.id);
    if(error)return json(res,500,{message:error.message});
    return json(res,200,{ok:true,removed:true});
  }
  if(existing){
    const {error}=await supabase.from('message_reactions').update({emoji,created_at:new Date().toISOString()}).eq('id',existing.id);
    if(error)return json(res,500,{message:error.message});
    return json(res,200,{ok:true,replaced:true});
  }
  const {error}=await supabase.from('message_reactions').insert({message_id:Number(id),email:me.email,emoji});
  if(error)return json(res,500,{message:error.message});
  json(res,200,{ok:true,added:true});
}

// Legacy migration endpoint: imports local accounts with balance/plan reset to safe defaults.
async function handleStorageSync(req, res) {
  if (!requireSupabase(res)) return;
  const body = await readBody(req); const users = Array.isArray(body.users) ? body.users : [];
  if (users.length > 100) return json(res, 400, { message: 'Слишком много аккаунтов.' });
  let synced = 0;
  for (const u of users) {
    const email = String(u.email || '').trim().toLowerCase(); const nick = String(u.nick || u.username || '').trim(); const password = String(u.password || '');
    if (!validEmail(email) || !validNick(nick) || password.length < 8) continue;
    const existing = await findByEmail(email); if (existing) continue;
    if (await findByNick(nick)) continue;
    const password_hash = await bcrypt.hash(password, 12);
    const { error } = await supabase.from('accounts').insert({ email, nick, nick_normalized: normalizeNick(nick), password_hash, balance: 0, banned: false, plan: 'none', expires: null });
    if (!error) synced++;
  }
  json(res, 200, { ok: true, synced });
}

function createTransporter() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: String(process.env.SMTP_SECURE || 'false') === 'true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });
}
async function sendCode(email, code) {
  const transporter = createTransporter();
  if (!transporter) throw new Error('Почтовый сервер не настроен. Добавьте SMTP_HOST, SMTP_USER и SMTP_PASS.');
  const from = process.env.MAIL_FROM || process.env.SMTP_USER;
  await transporter.sendMail({ from, to: email, subject: 'Space Client — код восстановления пароля', text: `Ваш код восстановления: ${code}. Код действителен 10 минут.`, html: `<div style="font-family:Arial;background:#0b0810;color:#f5f2fa;padding:32px"><div style="max-width:520px;margin:auto;background:#15101d;border:1px solid #2c2139;border-radius:18px;padding:28px"><div style="color:#9d75ff;font-weight:700">SPACE CLIENT</div><h1>Восстановление пароля</h1><p style="color:#9a91a5">Введите этот код:</p><div style="font-size:34px;letter-spacing:9px;font-weight:800;color:#a77cff">${code}</div><p style="color:#777080;font-size:12px">Код действителен 10 минут.</p></div></div>` });
}
function cooldownFor(email) { const s = resendState.get(email); if (!s) return { retryAfter: 0, nextDelay: 60 }; return { retryAfter: Math.max(0, Math.ceil((s.nextAllowedAt - Date.now()) / 1000)), nextDelay: s.nextDelay }; }
async function handleForgot(req,res) { if (!requireSupabase(res)) return; const {email}=await readBody(req); const e=String(email||'').trim().toLowerCase(); if(!validEmail(e)) return json(res,400,{message:'Некорректная почта.'}); const cd=cooldownFor(e); if(cd.retryAfter>0)return json(res,429,{message:`Подожди ${cd.retryAfter} сек. перед повторной отправкой.`,retryAfter:cd.retryAfter}); if(!(await findByEmail(e)))return json(res,404,{message:'Аккаунт с такой почтой не найден.'}); const code=String(crypto.randomInt(0,1000000)).padStart(6,'0'); resetCodes.set(e,{code,expiresAt:Date.now()+600000}); try{await sendCode(e,code)}catch(err){resetCodes.delete(e);return json(res,503,{message:err.message})} const prev=resendState.get(e); const nextDelay=prev?Math.min(prev.nextDelay*2,360):60; resendState.set(e,{nextAllowedAt:Date.now()+nextDelay*1000,nextDelay}); json(res,200,{ok:true,retryAfter:nextDelay}); }
async function handleVerify(req,res) { if (!requireSupabase(res)) return; const {email,code}=await readBody(req); const e=String(email||'').trim().toLowerCase(); const r=resetCodes.get(e); if(!r||Date.now()>r.expiresAt||String(code||'')!==r.code)return json(res,400,{message:'Неверный или просроченный код.'}); const t=token(); resetCodes.set(e,{...r,verifiedToken:t,tokenExpiresAt:Date.now()+600000}); json(res,200,{ok:true,token:t}); }
async function handleReset(req,res) { if (!requireSupabase(res)) return; const {email,token:rt,password}=await readBody(req); const e=String(email||'').trim().toLowerCase(); const r=resetCodes.get(e); if(!r||r.verifiedToken!==rt||Date.now()>r.tokenExpiresAt)return json(res,400,{message:'Сессия восстановления истекла. Запроси новый код.'}); if(typeof password!=='string'||password.length<8)return json(res,400,{message:'Пароль должен содержать минимум 8 символов.'}); const password_hash=await bcrypt.hash(password,12); const {error}=await supabase.from('accounts').update({password_hash}).eq('email',e); if(error)return json(res,500,{message:error.message}); resetCodes.delete(e);resendState.delete(e);json(res,200,{ok:true}); }

const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.ico':'image/x-icon','.exe':'application/octet-stream','.json':'application/json; charset=utf-8','.mp3':'audio/mpeg','.wav':'audio/wav','.ogg':'audio/ogg','.m4a':'audio/mp4','.zip':'application/zip'};
function getMusicPlaylist(){
  const dir=path.join(ROOT,'music');
  const allowed=new Set(['.mp3','.wav','.ogg','.m4a']);
  try{
    const files=fs.readdirSync(dir,{withFileTypes:true})
      .filter(x=>x.isFile() && allowed.has(path.extname(x.name).toLowerCase()))
      .map(x=>x.name);
    const numeric=/^(\d+)(?:\s*[-_.].*)?$/;
    files.sort((a,b)=>{
      const aa=path.basename(a,path.extname(a)), bb=path.basename(b,path.extname(b));
      const ma=aa.match(numeric), mb=bb.match(numeric);
      if(ma && mb) return Number(ma[1])-Number(mb[1]);
      if(ma) return -1; if(mb) return 1;
      return a.localeCompare(b,undefined,{numeric:true,sensitivity:'base'});
    });
    return files.map(name=>'/music/'+encodeURIComponent(name));
  }catch(e){ return []; }
}
function serve(req,res){ let pathname=decodeURIComponent(new URL(req.url,`http://${req.headers.host||'localhost'}`).pathname); if(pathname==='/')pathname='/index.html'; const file=path.join(ROOT,pathname); if(!file.startsWith(ROOT)||!fs.existsSync(file)||fs.statSync(file).isDirectory())return json(res,404,{message:'Не найдено.'}); res.writeHead(200,{'Content-Type':mime[path.extname(file).toLowerCase()]||'application/octet-stream'}); fs.createReadStream(file).pipe(res); }

const server=http.createServer(async(req,res)=>{
  res._corsRequest = req;
  if(req.method==='OPTIONS'){res.writeHead(204,corsHeaders(req));return res.end();}
  if(req.url.startsWith('/api/') && req.url !== '/api/admin/logs') void auditLog(req, auditActionName(req.url, req.method));
  try {
    if(req.method==='POST'&&req.url==='/api/log')return await handleClientLog(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/register')return await handleRegister(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/login')return await handleLogin(req,res);
    if(req.method==='POST'&&req.url==='/api/launcher/authorize')return await handleLauncherAuthorize(req,res);
    if(req.method==='POST'&&req.url==='/api/launcher/exchange')return await handleLauncherExchange(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/migrate-local')return await handleMigrateLocal(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/check-username')return await handleCheckUsername(req,res);
    if(req.method==='GET'&&req.url==='/api/auth/me')return await handleMe(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/activity')return await handleActivity(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/logout')return await handleLogout(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/update-profile')return await handleUpdateProfile(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/change-password')return await handleChangePassword(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/delete-account')return await handleDeleteAccount(req,res);
    if(req.method==='POST'&&req.url==='/api/admin/login')return await handleAdminLogin(req,res);
    if(req.method==='POST'&&req.url==='/api/admin/logout')return await handleAdminLogout(req,res);
    if(req.method==='POST'&&req.url==='/api/admin/find-player')return await handleAdminFind(req,res);
    if(req.method==='POST'&&req.url==='/api/admin/player-activity')return await handleAdminActivity(req,res);
    if(req.method==='POST'&&req.url==='/api/admin/ban')return await handleAdminBan(req,res);
    if(req.method==='POST'&&req.url==='/api/admin/role')return await handleAdminRole(req,res);
    if(req.method==='POST'&&req.url==='/api/friends/search')return await handleFriendSearch(req,res);
    if(req.method==='POST'&&req.url==='/api/friends/request')return await handleFriendRequest(req,res);
    if(req.method==='GET'&&req.url==='/api/friends/unread')return await handleFriendUnread(req,res);
        if(req.method==='GET'&&req.url==='/api/friends/requests')return await handleFriendRequests(req,res);
    if(req.method==='POST'&&req.url==='/api/friends/respond')return await handleFriendRespond(req,res);
    if(req.method==='GET'&&req.url==='/api/friends')return await handleFriendsList(req,res);
    if(req.method==='GET'&&req.url.startsWith('/api/friends/messages'))return await handleFriendMessages(req,res);
    if(req.method==='POST'&&req.url==='/api/friends/messages')return await handleFriendMessage(req,res);
    if(req.method==='POST'&&req.url==='/api/friends/messages/edit')return await handleFriendMessageEdit(req,res);
    if(req.method==='POST'&&req.url==='/api/friends/messages/delete')return await handleFriendMessageDelete(req,res);
    if(req.method==='POST'&&req.url==='/api/friends/messages/reaction')return await handleFriendMessageReaction(req,res);
    if(req.method==='GET'&&req.url==='/api/admin/logs')return await handleAdminLogs(req,res);
    if(req.method==='GET'&&req.url==='/api/music')return json(res,200,{ok:true,tracks:getMusicPlaylist()});
    if(req.method==='GET'&&req.url==='/api/health') {
      if (!supabase) return json(res,503,{ok:false,service:'spaceclient',supabase:false,db:false,message:'Supabase environment variables are missing.'});
      try {
        const { error } = await supabase.from('accounts').select('email', { count: 'exact', head: true });
        if (error) return json(res,503,{ok:false,service:'spaceclient',supabase:true,db:false,message:error.message});
        return json(res,200,{ok:true,service:'spaceclient',supabase:true,db:true});
      } catch (e) {
        return json(res,503,{ok:false,service:'spaceclient',supabase:true,db:false,message:String(e?.message || e)});
      }
    }
    if(req.method==='POST'&&req.url==='/api/storage/sync')return await handleStorageSync(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/forgot-password')return await handleForgot(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/verify-reset-code')return await handleVerify(req,res);
    if(req.method==='POST'&&req.url==='/api/auth/reset-password')return await handleReset(req,res);
    if(req.method==='GET')return serve(req,res);
    return json(res,405,{message:'Метод не поддерживается.'});
  } catch(error) { console.error(error); return json(res,500,{message:'Внутренняя ошибка сервера.'}); }
});

server.listen(PORT,'0.0.0.0',()=>console.log(`Space Client listening on 0.0.0.0:${PORT}`));
async function handleClientLog(req, res) {
  if (!requireSupabase(res)) return;
  const body = await readBody(req);
  const action = String(body.action || body.type || 'event').slice(0, 200);
  const details = String(body.details || '').slice(0, 500);
  const session = await getUserSession(req).catch(() => null);
  const actor = session ? session : await getAdmin(req).catch(() => null);
  const meta = getClientMeta(req, body);
  const { error } = await supabase.from('activity_logs').insert({
    ip: meta.ip,
    nick: actor?.nick || null,
    action,
    details,
    user_agent: meta.user_agent,
    device: meta.device,
    screen_width: meta.screen_width,
    screen_height: meta.screen_height,
    screen_dpr: meta.screen_dpr
  });
  if (error) return json(res, 500, { message: error.message });
  json(res, 200, { ok: true });
}

async function handleAdminLogs(req, res) {
  if (!requireSupabase(res) || !(await requireAdmin(req, res))) return;
  const { data, error } = await supabase.from('activity_logs')
    .select('id,ip,nick,action,details,created_at')
    .order('id', { ascending: false }).limit(100);
  if (error) return json(res, 500, { message: error.message });
  json(res, 200, { ok: true, logs: (data || []).reverse() });
}


