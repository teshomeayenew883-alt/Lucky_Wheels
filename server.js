import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import Groq from 'groq-sdk';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const sb = createClient(
  process.env.SUPABASE_URL || 'https://placeholder.supabase.co',
  process.env.SUPABASE_SERVICE_KEY || 'placeholder'
);

const JWT_SECRET       = process.env.JWT_SECRET;
const ADMIN_PHONE      = process.env.ADMIN_PHONE;
const ADMIN_PASSWORD   = process.env.ADMIN_PASSWORD;
const ADMIN_RESET_CODE = process.env.ADMIN_RESET_CODE || '100510';

const groq = process.env.GROQ_API_KEY ? new Groq({ apiKey: process.env.GROQ_API_KEY }) : null;

const TELEGRAM_BOT_TOKEN    = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_ADMIN_CHAT   = process.env.TELEGRAM_ADMIN_CHAT;
const TELEGRAM_CHANNEL      = process.env.TELEGRAM_CHANNEL || '@Lucky21_Wheel';
const TELEGRAM_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME || 'Numbers_Betting_bot';

async function sendTelegram(chatId, message, keyboard) {
  if (!TELEGRAM_BOT_TOKEN || !chatId) return;
  try {
    const body = { chat_id: chatId, text: message, parse_mode: 'HTML', disable_web_page_preview: true };
    if (keyboard) body.reply_markup = keyboard;
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  } catch (e) { console.error('Telegram send error:', e.message); }
}
async function answerCallback(callbackId, text) {
  if (!TELEGRAM_BOT_TOKEN || !callbackId) return;
  try {
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ callback_query_id: callbackId, text: text || '', show_alert: false })
    });
  } catch (e) {}
}
async function notifyAdmin(message) { return sendTelegram(TELEGRAM_ADMIN_CHAT, message); }
async function notifyChannel(message) { return sendTelegram(TELEGRAM_CHANNEL, message); }
function escapeTele(s) { return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function maskPhone(phone) {
  if (!phone) return '—';
  const s = String(phone);
  if (s.length < 6) return s;
  return s.slice(0, 4) + '****' + s.slice(-2);
}
function publicUserId(publicId) {
  if (publicId === null || publicId === undefined) return '—';
  return 'U' + String(publicId).padStart(5, '0');
}

function sign(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' }); }

async function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

async function getSettings() {
  const { data, error } = await sb.from('settings').select('*').eq('id', 1).single();
  if (error) throw error;
  return data;
}
async function getTickets() {
  const settings = await getSettings();
  const { data, error } = await sb.from('tickets').select('*').eq('round_number', settings.round_number).order('number');
  if (error) throw error;
  return data;
}
async function getNbSettings() {
  const { data, error } = await sb.from('nb_settings').select('*').eq('id', 1).single();
  if (error) throw error;
  return data;
}
async function getNbTickets(roundNumber) {
  const { data, error } = await sb.from('nb_tickets').select('*').eq('round_number', roundNumber).order('number');
  if (error) throw error;
  return data || [];
}
async function generateReferralCode() {
  const letters = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const digits  = '23456789';
  for (let i = 0; i < 10; i++) {
    let code = '';
    for (let j = 0; j < 3; j++) code += letters[Math.floor(Math.random() * letters.length)];
    for (let j = 0; j < 4; j++) code += digits[Math.floor(Math.random() * digits.length)];
    const { data } = await sb.from('users').select('id').eq('referral_code', code).maybeSingle();
    if (!data) return code;
  }
  throw new Error('Could not generate referral code');
}
async function getAdminPassword() {
  try {
    const { data } = await sb.from('admin_auth').select('password_hash').eq('id', 1).maybeSingle();
    return data?.password_hash || null;
  } catch { return null; }
}

app.get('/api/config', (req, res) => {
  res.json({
    supabaseUrl: process.env.SUPABASE_URL,
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY,
    botUsername: TELEGRAM_BOT_USERNAME,
    channelUsername: TELEGRAM_CHANNEL
  });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, password, referralCode } = req.body;
    if (!name || !phone || !password) return res.status(400).json({ error: 'Please fill all fields' });
    const cleanName = String(name).trim();
    const cleanPhone = String(phone).trim();
    const cleanPassword = String(password).trim();
    if (cleanPhone === ADMIN_PHONE) return res.status(400).json({ error: 'This phone number is reserved' });
    if (cleanPassword.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
    const { data: exists } = await sb.from('users').select('id').eq('phone', cleanPhone).maybeSingle();
    if (exists) return res.status(400).json({ error: 'This phone is already registered' });
    let referredBy = null;
    if (referralCode && String(referralCode).trim()) {
      const { data: referrer } = await sb.from('users').select('id').eq('referral_code', String(referralCode).trim().toUpperCase()).maybeSingle();
      if (referrer) referredBy = referrer.id;
    }
    const hash = await bcrypt.hash(cleanPassword, 10);
    const myCode = await generateReferralCode();
    const { error } = await sb.from('users').insert({
      name: cleanName, phone: cleanPhone, password_hash: hash,
      password_plain: cleanPassword, role: 'user', balance: 0,
      referral_code: myCode, referred_by: referredBy, banned: false
    });
    if (error) return res.status(500).json({ error: error.message });
    notifyAdmin(`👤 <b>New User Registered</b>\n\nName: ${escapeTele(cleanName)}\nPhone: ${escapeTele(cleanPhone)}\nReferral: ${myCode}`);
    res.json({ ok: true, referral_code: myCode, referred: !!referredBy });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'Phone and password required' });
    const cleanPhone = String(phone).trim();
    const cleanPassword = String(password).trim();
    if (cleanPhone === ADMIN_PHONE) {
      const customHash = await getAdminPassword();
      let ok = false;
      if (customHash) ok = await bcrypt.compare(cleanPassword, customHash);
      else ok = (cleanPassword === ADMIN_PASSWORD);
      if (ok) {
        const token = sign({ id: 'ADMIN', role: 'admin', phone: cleanPhone });
        return res.json({ token, role: 'admin' });
      }
      return res.status(401).json({ error: 'Invalid admin password' });
    }
    const { data: user, error } = await sb.from('users').select('*').eq('phone', cleanPhone).maybeSingle();
    if (error || !user) return res.status(401).json({ error: 'Invalid phone number or password' });
    if (user.banned) return res.status(403).json({ error: 'Your account has been banned.' });
    const ok = await bcrypt.compare(cleanPassword, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid phone number or password' });
    const token = sign({ id: user.id, role: user.role, phone: user.phone });
    res.json({ token, role: user.role });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/change-password', auth, adminOnly, async (req, res) => {
  try {
    const { newPassword, code } = req.body;
    if (!newPassword || !code) return res.status(400).json({ error: 'Password and code required' });
    if (String(code).trim() !== ADMIN_RESET_CODE) return res.status(403).json({ error: 'Invalid secret code' });
    const clean = String(newPassword).trim();
    if (clean.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
    const hash = await bcrypt.hash(clean, 10);
    const { error } = await sb.from('admin_auth').update({ password_hash: hash, updated_at: new Date().toISOString() }).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    notifyAdmin(`🔐 <b>Admin Password Changed</b>`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/state', auth, async (req, res) => {
  try {
    const settings = await getSettings();
    const tickets = await getTickets();
    let me;
    if (req.user.role === 'admin') {
      me = { id: 'ADMIN', name: 'Administrator', phone: req.user.phone, role: 'admin', balance: 0 };
    } else {
      const { data } = await sb.from('users').select('id,name,phone,balance,role,referral_code,active_referrals,free_tickets,has_bought_ticket,public_id').eq('id', req.user.id).single();
      me = data;
    }
    res.json({ settings, tickets, me });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/referrals', auth, async (req, res) => {
  try {
    if (req.user.role === 'admin') return res.json({ referrals: [], activeCount: 0 });
    const { data } = await sb.from('users').select('id,name,phone,has_bought_ticket,created_at').eq('referred_by', req.user.id).order('created_at', { ascending: false });
    const referrals = data || [];
    const activeCount = referrals.filter(r => r.has_bought_ticket).length;
    res.json({ referrals, activeCount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { data, error } = await sb.from('users').select('id,name,phone,balance,active_referrals,free_tickets,has_bought_ticket,referral_code,referred_by,public_id').eq('role', 'user').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ users: data });
});

app.get('/api/admin/users/full', auth, adminOnly, async (req, res) => {
  const { data, error } = await sb.from('users').select('id,name,phone,balance,role,referral_code,active_referrals,free_tickets,has_bought_ticket,banned,password_plain,public_id').eq('role', 'user').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ users: data });
});

app.post('/api/admin/users/reset-password', auth, adminOnly, async (req, res) => {
  try {
    const { userId, newPassword } = req.body;
    if (!userId || !newPassword) return res.status(400).json({ error: 'Missing fields' });
    const clean = String(newPassword).trim();
    if (clean.length < 4) return res.status(400).json({ error: 'Password too short' });
    const hash = await bcrypt.hash(clean, 10);
    const { error } = await sb.from('users').update({ password_hash: hash, password_plain: clean }).eq('id', userId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users/ban', auth, adminOnly, async (req, res) => {
  try {
    const { userId, banned } = req.body;
    if (!userId) return res.status(400).json({ error: 'Missing userId' });
    const { error } = await sb.from('users').update({ banned: !!banned }).eq('id', userId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users/balance', auth, adminOnly, async (req, res) => {
  const { userId, amount } = req.body;
  const { data: user } = await sb.from('users').select('balance').eq('id', userId).single();
  if (!user) return res.status(404).json({ error: 'User not found' });
  const newBalance = Number(user.balance) + Number(amount);
  if (newBalance < 0) return res.status(400).json({ error: 'Balance cannot be negative' });
  const { error } = await sb.from('users').update({ balance: newBalance }).eq('id', userId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true, balance: newBalance });
});

app.post('/api/admin/tickets/assign', auth, adminOnly, async (req, res) => {
  try {
    const { name, phone, password, balance, numbers, useFreeTicket } = req.body;
    if (!name || !phone || !numbers?.length) return res.status(400).json({ error: 'Missing fields' });
    const cleanName = String(name).trim();
    const cleanPhone = String(phone).trim();
    let { data: user } = await sb.from('users').select('*').eq('phone', cleanPhone).maybeSingle();
    const isFirstPurchase = !user || !user.has_bought_ticket;
    if (!user) {
      if (!password) return res.status(400).json({ error: 'Password needed for new user' });
      const cleanPassword = String(password).trim();
      const hash = await bcrypt.hash(cleanPassword, 10);
      const newCode = await generateReferralCode();
      const { data: created, error } = await sb.from('users').insert({
        name: cleanName, phone: cleanPhone, password_hash: hash,
        password_plain: cleanPassword, role: 'user',
        balance: Math.max(0, Number(balance) || 0),
        referral_code: newCode, banned: false
      }).select().single();
      if (error) return res.status(500).json({ error: error.message });
      user = created;
    } else {
      const newBalance = Number(user.balance) + (Number(balance) || 0);
      if (newBalance < 0) return res.status(400).json({ error: 'Balance cannot be negative' });
      await sb.from('users').update({ name: cleanName, balance: newBalance }).eq('id', user.id);
      user.name = cleanName; user.balance = newBalance;
    }
    const settings = await getSettings();
    const { data: current } = await sb.from('tickets').select('*').eq('round_number', settings.round_number).in('number', numbers);
    const sold = (current || []).filter(t => t.user_id);
    if (sold.length) return res.status(400).json({ error: 'Some tickets are already sold' });
    let usedFreeTicket = false;
    if (useFreeTicket && (user.free_tickets || 0) > 0) {
      await sb.from('users').update({ free_tickets: user.free_tickets - 1 }).eq('id', user.id);
      user.free_tickets = user.free_tickets - 1;
      usedFreeTicket = true;
    }
    for (const n of numbers) {
      const existing = (current || []).find(t => t.number === n);
      const soldDate = new Date().toISOString();
      if (existing) {
        await sb.from('tickets').update({ user_id: user.id, user_name: cleanName, phone: cleanPhone, sold_date: soldDate, used_free_ticket: usedFreeTicket }).eq('id', existing.id);
      } else {
        await sb.from('tickets').insert({ number: n, user_id: user.id, user_name: cleanName, phone: cleanPhone, sold_date: soldDate, round_number: settings.round_number, used_free_ticket: usedFreeTicket });
      }
    }
    let referralMessage = null;
    if (isFirstPurchase) {
      await sb.from('users').update({ has_bought_ticket: true }).eq('id', user.id);
      if (user.referred_by) {
        const { data: referrer } = await sb.from('users').select('id,name,active_referrals,free_tickets').eq('id', user.referred_by).single();
        if (referrer) {
          const newActive = (referrer.active_referrals || 0) + 1;
          const goal = settings.referral_goal || 8;
          const reward = settings.referral_reward || 1;
          let newFree = referrer.free_tickets || 0;
          if (newActive % goal === 0) { newFree += reward; referralMessage = `🎁 ${referrer.name} earned ${reward} FREE ticket!`; }
          await sb.from('users').update({ active_referrals: newActive, free_tickets: newFree }).eq('id', referrer.id);
        }
      }
    }
    res.json({ user, numbers, usedFreeTicket, referralMessage });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/settings', auth, adminOnly, async (req, res) => {
  try {
    const { duration, winners, prize, ticketPrice, referralGoal, referralReward, prizes, salesDuration } = req.body;
    const update = {
      duration: Math.max(5, Number(duration) || 30),
      winner_count: Math.min(60, Math.max(1, Number(winners) || 1)),
      prize: Math.max(0, Number(prize) || 0),
      ticket_price: Math.max(0, Number(ticketPrice) || 0)
    };
    if (referralGoal !== undefined) update.referral_goal = Math.max(1, Number(referralGoal) || 8);
    if (referralReward !== undefined) update.referral_reward = Math.max(1, Number(referralReward) || 1);
    if (Array.isArray(prizes)) update.prizes = prizes.map(p => Math.max(0, Number(p) || 0));
    if (salesDuration !== undefined) update.sales_duration = Math.max(1, Number(salesDuration) || 120);
    const { error } = await sb.from('settings').update(update).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/tickets/count', auth, adminOnly, async (req, res) => {
  try {
    const count = Math.min(60, Math.max(2, Number(req.body.count) || 12));
    const settings = await getSettings();
    const { data: sold } = await sb.from('tickets').select('id').eq('round_number', settings.round_number).not('user_id', 'is', null);
    if (sold?.length) return res.status(400).json({ error: 'Reset round first' });
    await sb.from('tickets').delete().eq('round_number', settings.round_number);
    const rows = Array.from({ length: count }, (_, i) => ({ number: i + 1, round_number: settings.round_number }));
    const { error } = await sb.from('tickets').insert(rows);
    if (error) return res.status(500).json({ error: error.message });
    await sb.from('settings').update({ ticket_count: count, round_state: 'idle', winner_numbers: [], winners: [] }).eq('id', 1);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/tickets/reset-one', auth, adminOnly, async (req, res) => {
  try {
    const { number } = req.body;
    if (!number) return res.status(400).json({ error: 'Missing number' });
    const settings = await getSettings();
    const { error } = await sb.from('tickets').update({ user_id: null, user_name: null, phone: null, sold_date: null, used_free_ticket: false }).eq('round_number', settings.round_number).eq('number', number);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/start-sales', auth, adminOnly, async (req, res) => {
  try {
    const settings = await getSettings();
    if (settings.sales_state === 'open') return res.status(400).json({ error: 'Sales already open' });
    if (settings.round_state === 'spinning') return res.status(400).json({ error: 'Wheel is spinning' });
    const { error } = await sb.from('settings').update({ sales_state: 'open', sales_started_at: new Date().toISOString() }).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    notifyChannel(`🎡 <b>Wheel Sales Open!</b>\n\nRound #${settings.round_number}\nBuy tickets now!`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/close-sales', auth, adminOnly, async (req, res) => {
  try {
    const { error } = await sb.from('settings').update({ sales_state: 'closed' }).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/spin/start', auth, adminOnly, async (req, res) => {
  try {
    const settings = await getSettings();
    if (settings.round_state === 'spinning') return res.status(400).json({ error: 'Already spinning' });
    const { data: soldTickets } = await sb.from('tickets').select('*').eq('round_number', settings.round_number).not('user_id', 'is', null);
    if (!soldTickets?.length) return res.status(400).json({ error: 'No sold tickets yet' });
    const shuffled = [...soldTickets].sort(() => Math.random() - 0.5);
    const winnerNumbers = shuffled.slice(0, Math.min(settings.winner_count, shuffled.length)).map(t => t.number);
    const spins = Math.max(5, Math.round((settings.duration || 30) / 2));
    const targetRotation = 360 * spins + Math.floor(Math.random() * 360);
    const { error } = await sb.from('settings').update({
      round_state: 'spinning', spin_started_at: new Date().toISOString(),
      target_rotation: targetRotation, winner_numbers: winnerNumbers, winners: [],
      sales_state: 'closed', settlement_done: false
    }).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/spin/settle', async (req, res) => {
  try {
    const settings = await getSettings();
    if (settings.round_state !== 'spinning') return res.json({ ok: true });
    if (settings.settlement_done === true) return res.json({ ok: true });
    const started = new Date(settings.spin_started_at).getTime();
    if (Date.now() - started < settings.duration * 1000) return res.json({ ok: true });
    const winnerNumbers = settings.winner_numbers || [];
    const { data: tickets } = await sb.from('tickets').select('*').eq('round_number', settings.round_number).in('number', winnerNumbers);
    const prizes = Array.isArray(settings.prizes) ? settings.prizes : [];
    const winners = [];
    for (let i = 0; i < (tickets || []).length; i++) {
      const t = tickets[i];
      const { data: user } = await sb.from('users').select('*').eq('id', t.user_id).single();
      if (!user) continue;
      const thisPrize = prizes[i] !== undefined ? Number(prizes[i]) : Number(settings.prize);
      await sb.from('users').update({ balance: Number(user.balance) + thisPrize }).eq('id', user.id);
      winners.push({
        place: i + 1,
        ticket: t.number,
        name: user.name,
        public_id: user.public_id,
        public_code: publicUserId(user.public_id),
        phone_masked: maskPhone(user.phone),
        phone: user.phone,
        prize: thisPrize
      });
      if (user.telegram_id) {
        await sendTelegram(user.telegram_id, `🏆 <b>Congratulations!</b>\n\nYou won in Lucky Wheel Round #${settings.round_number}!\n\nPlace: <b>#${i + 1}</b>\nTicket: <b>#${t.number}</b>\nPrize: <b>${thisPrize} ETB</b>`);
      }
    }
    const { data: allSold } = await sb.from('tickets').select('*').eq('round_number', settings.round_number).not('user_id', 'is', null);
    await sb.from('rounds').insert({
      round_number: settings.round_number, winners,
      sold_tickets: (allSold || []).map(t => ({ number: t.number, name: t.user_name, phone: t.phone }))
    });
    await sb.from('settings').update({ round_state: 'finished', winners, settlement_done: true }).eq('id', 1);
    if (winners.length) {
      const winnerText = winners.map(w => `🏆 #${w.place} ${escapeTele(w.name)} — Ticket #${w.ticket} — ${w.prize} ETB`).join('\n');
      notifyAdmin(`🎡 <b>Round #${settings.round_number} Finished</b>\n\n${winnerText}`);
      notifyChannel(`🎡 <b>Round #${settings.round_number} Winners!</b>\n\n${winnerText}`);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/round/reset', auth, adminOnly, async (req, res) => {
  try {
    const settings = await getSettings();
    if (settings.round_state === 'spinning') return res.status(400).json({ error: 'Wait for wheel' });
    const nextRound = settings.round_number + 1;
    const rows = Array.from({ length: settings.ticket_count }, (_, i) => ({ number: i + 1, round_number: nextRound }));
    await sb.from('tickets').insert(rows);
    await sb.from('settings').update({
      round_number: nextRound, round_state: 'idle', spin_started_at: null,
      target_rotation: 0, winner_numbers: [], winners: [],
      sales_state: 'idle', sales_started_at: null, settlement_done: false
    }).eq('id', 1);
    await sb.from('live_viewers').delete().neq('id', 0);
    await sb.from('live_chat').delete().neq('id', 0);
    notifyAdmin(`🔄 <b>New Wheel Round Started</b> (#${nextRound})`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/rounds', auth, async (req, res) => {
  const { data, error } = await sb.from('rounds').select('*').order('id', { ascending: false }).limit(50);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ rounds: data });
});

app.post('/api/user/deposits', auth, async (req, res) => {
  try {
    if (req.user.role !== 'user') return res.status(403).json({ error: 'Users only' });
    const { method, amount, transactionId } = req.body;
    if (!method || !amount || !transactionId) return res.status(400).json({ error: 'All fields required' });
    if (!['cbe', 'boa'].includes(String(method).toLowerCase())) return res.status(400).json({ error: 'Invalid method' });
    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });
    const { data: user } = await sb.from('users').select('name,phone').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { error } = await sb.from('deposits').insert({
      user_id: req.user.id, user_name: user.name, phone: user.phone,
      method: String(method).toLowerCase(), amount: amt,
      transaction_id: String(transactionId).trim(), status: 'pending'
    });
    if (error) return res.status(500).json({ error: error.message });
    notifyAdmin(`💰 <b>New Deposit</b>\n\nUser: ${escapeTele(user.name)}\nPhone: ${escapeTele(user.phone)}\nAmount: ${amt} ETB`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/deposits', auth, async (req, res) => {
  if (req.user.role !== 'user') return res.json({ deposits: [] });
  const { data, error } = await sb.from('deposits').select('*').eq('user_id', req.user.id).order('id', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ deposits: data || [] });
});

app.post('/api/user/withdrawals', auth, async (req, res) => {
  try {
    if (req.user.role !== 'user') return res.status(403).json({ error: 'Users only' });
    const { method, amount, accountNumber } = req.body;
    if (!method || !amount || !accountNumber) return res.status(400).json({ error: 'All fields required' });
    if (!['cbe', 'boa'].includes(String(method).toLowerCase())) return res.status(400).json({ error: 'Invalid method' });
    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });
    const { data: user } = await sb.from('users').select('name,phone,balance').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (Number(user.balance) < amt) return res.status(400).json({ error: 'Insufficient balance' });
    const newBalance = Number(user.balance) - amt;
    await sb.from('users').update({ balance: newBalance }).eq('id', req.user.id);
    const { error } = await sb.from('withdrawals').insert({
      user_id: req.user.id, user_name: user.name, phone: user.phone,
      method: String(method).toLowerCase(), amount: amt,
      account_number: String(accountNumber).trim(), status: 'pending'
    });
    if (error) {
      await sb.from('users').update({ balance: user.balance }).eq('id', req.user.id);
      return res.status(500).json({ error: error.message });
    }
    notifyAdmin(`💸 <b>New Withdrawal</b>\n\nUser: ${escapeTele(user.name)}\nPhone: ${escapeTele(user.phone)}\nAmount: ${amt} ETB`);
    res.json({ ok: true, newBalance });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/withdrawals', auth, async (req, res) => {
  if (req.user.role !== 'user') return res.json({ withdrawals: [] });
  const { data, error } = await sb.from('withdrawals').select('*').eq('user_id', req.user.id).order('id', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ withdrawals: data || [] });
});

app.get('/api/admin/deposits', auth, adminOnly, async (req, res) => {
  const { data, error } = await sb.from('deposits').select('*').order('id', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ deposits: data || [] });
});

app.post('/api/admin/deposits/:id/decide', auth, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { action, comment } = req.body;
    if (!['approve', 'reject'].includes(action)) return res.status(400).json({ error: 'Invalid action' });
    const { data: dep } = await sb.from('deposits').select('*').eq('id', id).single();
    if (!dep) return res.status(404).json({ error: 'Deposit not found' });
    if (dep.status !== 'pending') return res.status(400).json({ error: 'Already processed' });
    if (action === 'approve') {
      const { data: user } = await sb.from('users').select('balance,telegram_id').eq('id', dep.user_id).single();
      if (!user) return res.status(404).json({ error: 'User not found' });
      await sb.from('users').update({ balance: Number(user.balance) + Number(dep.amount) }).eq('id', dep.user_id);
      if (user.telegram_id) {
        await sendTelegram(user.telegram_id, `✅ <b>Deposit Approved</b>\n\nAmount: <b>${dep.amount} ETB</b>\nNew balance: <b>${Number(user.balance) + Number(dep.amount)} ETB</b>`);
      }
    } else if (action === 'reject') {
      const { data: user } = await sb.from('users').select('telegram_id').eq('id', dep.user_id).single();
      if (user?.telegram_id) {
        await sendTelegram(user.telegram_id, `❌ <b>Deposit Rejected</b>\n\nAmount: <b>${dep.amount} ETB</b>\nReason: ${escapeTele(comment || 'No reason')}`);
      }
    }
    await sb.from('deposits').update({
      status: action === 'approve' ? 'approved' : 'rejected',
      admin_comment: comment || '', processed_at: new Date().toISOString()
    }).eq('id', id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/withdrawals', auth, adminOnly, async (req, res) => {
  const { data, error } = await sb.from('withdrawals').select('*').order('id', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ withdrawals: data || [] });
});

app.post('/api/admin/withdrawals/:id/decide', auth, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { action, comment } = req.body;
    if (!['approve', 'reject'].includes(action)) return res.status(400).json({ error: 'Invalid action' });
    const { data: w } = await sb.from('withdrawals').select('*').eq('id', id).single();
    if (!w) return res.status(404).json({ error: 'Withdrawal not found' });
    if (w.status !== 'pending') return res.status(400).json({ error: 'Already processed' });
    if (action === 'reject') {
      const { data: user } = await sb.from('users').select('balance,telegram_id').eq('id', w.user_id).single();
      if (user) {
        await sb.from('users').update({ balance: Number(user.balance) + Number(w.amount) }).eq('id', w.user_id);
        if (user.telegram_id) {
          await sendTelegram(user.telegram_id, `❌ <b>Withdrawal Rejected</b>\n\nAmount: <b>${w.amount} ETB</b> (returned)\nReason: ${escapeTele(comment || 'No reason')}`);
        }
      }
    } else if (action === 'approve') {
      const { data: user } = await sb.from('users').select('telegram_id').eq('id', w.user_id).single();
      if (user?.telegram_id) {
        await sendTelegram(user.telegram_id, `✅ <b>Withdrawal Approved</b>\n\nAmount: <b>${w.amount} ETB</b>\nMethod: ${w.method.toUpperCase()}\nAccount: ${escapeTele(w.account_number)}`);
      }
    }
    await sb.from('withdrawals').update({
      status: action === 'approve' ? 'approved' : 'rejected',
      admin_comment: comment || '', processed_at: new Date().toISOString()
    }).eq('id', id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/user/tickets/buy', auth, async (req, res) => {
  try {
    if (req.user.role !== 'user') return res.status(403).json({ error: 'Users only' });
    const { numbers, useFreeTicket } = req.body;
    if (!numbers?.length) return res.status(400).json({ error: 'Select at least one ticket' });
    const settings = await getSettings();
    if (settings.sales_state !== 'open') return res.status(400).json({ error: 'Ticket sales are not open right now.' });
    const { data: user } = await sb.from('users').select('*').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { data: current } = await sb.from('tickets').select('*').eq('round_number', settings.round_number).in('number', numbers);
    const sold = (current || []).filter(t => t.user_id);
    if (sold.length) return res.status(400).json({ error: 'Some tickets are already sold' });
    let usedFree = false;
    let cost = 0;
    if (useFreeTicket) {
      if ((user.free_tickets || 0) < 1) return res.status(400).json({ error: 'No free tickets' });
      if (numbers.length > 1) return res.status(400).json({ error: 'Free ticket only for 1' });
      usedFree = true;
    } else {
      cost = Number(settings.ticket_price) * numbers.length;
      if (Number(user.balance) < cost) return res.status(400).json({ error: 'Insufficient balance' });
    }
    const updates = {};
    if (usedFree) updates.free_tickets = (user.free_tickets || 0) - 1;
    else updates.balance = Number(user.balance) - cost;
    if (!user.has_bought_ticket) updates.has_bought_ticket = true;
    await sb.from('users').update(updates).eq('id', user.id);
    for (const n of numbers) {
      const existing = (current || []).find(t => t.number === n);
      const soldDate = new Date().toISOString();
      if (existing) {
        await sb.from('tickets').update({ user_id: user.id, user_name: user.name, phone: user.phone, sold_date: soldDate, used_free_ticket: usedFree }).eq('id', existing.id);
      } else {
        await sb.from('tickets').insert({ number: n, user_id: user.id, user_name: user.name, phone: user.phone, sold_date: soldDate, round_number: settings.round_number, used_free_ticket: usedFree });
      }
    }
    res.json({ ok: true, cost, usedFree });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============= NUMBER BETTING ============= */

function nbPublicSettings(s) {
  return {
    total_numbers: s.total_numbers,
    drawn_count: s.drawn_count,
    tickets_per_purchase: s.tickets_per_purchase,
    price_per_purchase: Number(s.price_per_purchase),
    draw_delay_seconds: s.draw_delay_seconds,
    round_duration_minutes: s.round_duration_minutes,
    winner_count: s.winner_count,
    prizes: s.prizes,
    sales_state: s.sales_state,
    round_state: s.round_state,
    round_number: s.round_number,
    sales_started_at: s.sales_started_at,
    drawing_started_at: s.drawing_started_at,
    winning_numbers: s.winning_numbers,
    winners: s.winners
  };
}

app.get('/api/nb/config', (req, res) => {
  getNbSettings().then(s => res.json(nbPublicSettings(s))).catch(e => res.status(500).json({ error: e.message }));
});

app.get('/api/nb/state', auth, async (req, res) => {
  try {
    const s = await getNbSettings();
    const tickets = await getNbTickets(s.round_number);
    const soldCount = tickets.filter(t => t.user_id).length;
    let myTickets = [];
    if (req.user.role !== 'admin') {
      myTickets = tickets.filter(t => String(t.user_id) === String(req.user.id)).map(t => ({ number: t.number, is_free: t.is_free }));
    }
    const enrichedWinners = (s.winners || []).map(w => ({
      ...w,
      public_code: w.public_code || publicUserId(w.public_id),
      phone_masked: w.phone_masked || maskPhone(w.phone)
    }));
    res.json({
      settings: { ...nbPublicSettings(s), winners: enrichedWinners },
      sold_count: soldCount,
      tickets: tickets.map(t => ({ number: t.number, user_id: t.user_id, user_name: t.user_name })),
      my_tickets: myTickets
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nb/buy', auth, async (req, res) => {
  try {
    if (req.user.role !== 'user') return res.status(403).json({ error: 'Users only' });
    const { numbers } = req.body;
    if (!Array.isArray(numbers) || !numbers.length) return res.status(400).json({ error: 'Select ticket numbers' });
    const s = await getNbSettings();
    if (s.sales_state !== 'open') return res.status(400).json({ error: 'Sales are not open right now' });
    if (numbers.length !== Number(s.tickets_per_purchase)) return res.status(400).json({ error: `You must pick exactly ${s.tickets_per_purchase} numbers` });
    const invalid = numbers.find(n => !Number.isInteger(n) || n < 1 || n > s.total_numbers);
    if (invalid !== undefined) return res.status(400).json({ error: 'Invalid number' });
    const uniq = new Set(numbers);
    if (uniq.size !== numbers.length) return res.status(400).json({ error: 'Numbers must be unique' });
    const { data: user } = await sb.from('users').select('*').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'User not found' });
    const price = Number(s.price_per_purchase);
    if (Number(user.balance) < price) return res.status(400).json({ error: 'Insufficient balance' });
    const existing = await getNbTickets(s.round_number);
    const taken = existing.filter(t => t.user_id && numbers.includes(t.number));
    if (taken.length) return res.status(400).json({ error: 'Some numbers already taken' });
    const batchId = crypto.randomUUID();
    const rows = numbers.map(n => ({
      round_number: s.round_number, number: n,
      user_id: user.id, user_name: user.name, phone: user.phone,
      batch_id: batchId, is_free: false
    }));
    const { error: insErr } = await sb.from('nb_tickets').insert(rows);
    if (insErr) return res.status(500).json({ error: insErr.message });
    await sb.from('users').update({ balance: Number(user.balance) - price }).eq('id', user.id);
    res.json({ ok: true, cost: price, numbers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/nb/my-tickets', auth, async (req, res) => {
  try {
    if (req.user.role === 'admin') return res.json({ tickets: [] });
    const s = await getNbSettings();
    const { data } = await sb.from('nb_tickets').select('*').eq('round_number', s.round_number).eq('user_id', req.user.id).order('number');
    res.json({ tickets: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/nb/rounds', auth, async (req, res) => {
  try {
    const { data, error } = await sb.from('nb_rounds').select('*').order('id', { ascending: false }).limit(50);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ rounds: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/nb/settings', auth, adminOnly, async (req, res) => {
  try {
    const { total_numbers, drawn_count, tickets_per_purchase, price_per_purchase, draw_delay_seconds, round_duration_minutes, winner_count, prizes } = req.body;
    const update = {};
    if (total_numbers !== undefined) update.total_numbers = Math.min(200, Math.max(10, Number(total_numbers) || 80));
    if (drawn_count !== undefined) update.drawn_count = Math.min(50, Math.max(1, Number(drawn_count) || 20));
    if (tickets_per_purchase !== undefined) update.tickets_per_purchase = Math.min(20, Math.max(1, Number(tickets_per_purchase) || 3));
    if (price_per_purchase !== undefined) update.price_per_purchase = Math.max(0, Number(price_per_purchase) || 0);
    if (draw_delay_seconds !== undefined) update.draw_delay_seconds = Math.min(30, Math.max(1, Number(draw_delay_seconds) || 2));
    if (round_duration_minutes !== undefined) update.round_duration_minutes = Math.min(120, Math.max(1, Number(round_duration_minutes) || 5));
    if (winner_count !== undefined) update.winner_count = Math.min(20, Math.max(1, Number(winner_count) || 3));
    if (Array.isArray(prizes)) update.prizes = prizes.map(p => Math.max(0, Number(p) || 0));
    const { error } = await sb.from('nb_settings').update(update).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/nb/start-sales', auth, adminOnly, async (req, res) => {
  try {
    const s = await getNbSettings();
    if (s.sales_state === 'open') return res.status(400).json({ error: 'Sales already open' });
    if (s.round_state === 'drawing') return res.status(400).json({ error: 'Drawing in progress' });
    const { error } = await sb.from('nb_settings').update({ sales_state: 'open', sales_started_at: new Date().toISOString() }).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    notifyChannel(`🎰 <b>Number Betting — Sales Open!</b>\n\nRound #${s.round_number}\n${s.tickets_per_purchase} tickets for ${s.price_per_purchase} ETB`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/nb/close-sales', auth, adminOnly, async (req, res) => {
  try {
    const { error } = await sb.from('nb_settings').update({ sales_state: 'closed' }).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/nb/draw', auth, adminOnly, async (req, res) => {
  try {
    const s = await getNbSettings();
    if (s.round_state === 'drawing') return res.status(400).json({ error: 'Already drawing' });
    const tickets = await getNbTickets(s.round_number);
    if (!tickets.some(t => t.user_id)) return res.status(400).json({ error: 'No tickets sold yet' });
    const all = Array.from({ length: s.total_numbers }, (_, i) => i + 1);
    const shuffled = all.sort(() => Math.random() - 0.5);
    const winning = shuffled.slice(0, s.drawn_count);
    const { error } = await sb.from('nb_settings').update({
      round_state: 'drawing', sales_state: 'closed',
      drawing_started_at: new Date().toISOString(),
      winning_numbers: winning, winners: [], settlement_done: false
    }).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    notifyChannel(`🎰 <b>Number Betting — Drawing!</b>\n\nRound #${s.round_number}`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/nb/settle', async (req, res) => {
  try {
    const s = await getNbSettings();
    if (s.round_state !== 'drawing') return res.json({ ok: true });
    if (s.settlement_done === true) return res.json({ ok: true });

    const started = new Date(s.drawing_started_at).getTime();
    const required = (s.drawn_count * s.draw_delay_seconds * 1000) + 1500;
    if (Date.now() - started < required) return res.json({ ok: true });

    const winning = s.winning_numbers || [];
    const tickets = await getNbTickets(s.round_number);
    const tpp = Number(s.tickets_per_purchase) || 3;

    // Group matched tickets per user
    const userMatched = {};
    for (const t of tickets) {
      if (!t.user_id) continue;
      if (!winning.includes(t.number)) continue;
      if (!userMatched[t.user_id]) userMatched[t.user_id] = { user_id: t.user_id, name: t.user_name, phone: t.phone, numbers: [] };
      userMatched[t.user_id].numbers.push(t.number);
    }

    // All users who participated (even with 0 matches)
    const allUsers = {};
    for (const t of tickets) {
      if (!t.user_id) continue;
      if (!allUsers[t.user_id]) allUsers[t.user_id] = { user_id: t.user_id, name: t.user_name, phone: t.phone, numbers: [] };
    }

    // Rank all participants by matches desc, ties broken alphabetically
    const ranked = Object.values(allUsers).map(u => ({
      ...u,
      matches: (userMatched[u.user_id]?.numbers || []).length,
      matched_numbers: userMatched[u.user_id]?.numbers || []
    })).sort((a, b) => {
      if (b.matches !== a.matches) return b.matches - a.matches;
      return String(a.name || '').localeCompare(String(b.name || ''));
    });

    const prizes = Array.isArray(s.prizes) ? s.prizes : [];
    const wantedWinners = Math.max(1, Number(s.winner_count) || 1);
    const winners = [];
    const usedUserIds = new Set();

    // For each place: prefer EXACT match count; fall back to highest matches remaining
    for (let place = 1; place <= wantedWinners; place++) {
      const idealMatches = tpp - (place - 1);

      // Try exact match first
      let chosen = ranked.find(u => !usedUserIds.has(u.user_id) && u.matches === idealMatches);

      // Fallback: highest matches among remaining
      if (!chosen) {
        chosen = ranked.find(u => !usedUserIds.has(u.user_id));
      }

      if (!chosen) break; // no more users

      usedUserIds.add(chosen.user_id);

      const prize = Number(prizes[place - 1] ?? 0);
      const shownCount = Math.max(0, chosen.matches - (place - 1));
      const shownNumbers = chosen.matched_numbers.slice(0, shownCount);

      const { data: dbUser } = await sb.from('users').select('balance,telegram_id,public_id').eq('id', chosen.user_id).single();

      winners.push({
        place,
        name: chosen.name,
        public_id: dbUser?.public_id ?? null,
        public_code: publicUserId(dbUser?.public_id),
        phone: chosen.phone,
        phone_masked: maskPhone(chosen.phone),
        matches: chosen.matches,
        shown_numbers: shownNumbers,
        prize
      });

      if (prize > 0 && dbUser) {
        await sb.from('users').update({ balance: Number(dbUser.balance) + prize }).eq('id', chosen.user_id);
        if (dbUser.telegram_id) {
          await sendTelegram(dbUser.telegram_id, `🏆 <b>Congratulations!</b>\n\nYou won in Number Betting Round #${s.round_number}!\n\nPlace: <b>#${place}</b>\nMatches: <b>${chosen.matches}</b>\nPrize: <b>${prize} ETB</b>\n\nYour numbers: ${shownNumbers.map(n => '#' + n).join(', ') || 'none'}`);
        }
      }
    }

    await sb.from('nb_rounds').insert({
      round_number: s.round_number,
      winning_numbers: winning,
      winners,
      sold_tickets: tickets.filter(t => t.user_id).map(t => ({ number: t.number, name: t.user_name, phone: t.phone }))
    });

    await sb.from('nb_settings').update({ round_state: 'finished', winners, settlement_done: true }).eq('id', 1);

    if (winners.length) {
      const txt = winners.map(w => `🏆 #${w.place} ${escapeTele(w.name)} (${w.public_code}) — ${w.matches} matches — ${w.prize} ETB`).join('\n');
      notifyAdmin(`🎰 <b>NB Round #${s.round_number} Finished</b>\n\n${txt}`);
      notifyChannel(`🎰 <b>NB Winners!</b>\n\n${txt}`);
    }

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/admin/nb/assign', auth, adminOnly, async (req, res) => {
  try {
    const { name, phone, password, balance, numbers } = req.body;
    if (!name || !phone || !Array.isArray(numbers) || !numbers.length) return res.status(400).json({ error: 'Missing fields' });
    const s = await getNbSettings();
    if (numbers.length !== Number(s.tickets_per_purchase)) return res.status(400).json({ error: `Pick exactly ${s.tickets_per_purchase} numbers` });
    const uniq = new Set(numbers);
    if (uniq.size !== numbers.length) return res.status(400).json({ error: 'Numbers must be unique' });
    const invalid = numbers.find(n => !Number.isInteger(n) || n < 1 || n > s.total_numbers);
    if (invalid !== undefined) return res.status(400).json({ error: 'Invalid number' });
    const cleanName = String(name).trim();
    const cleanPhone = String(phone).trim();
    let { data: user } = await sb.from('users').select('*').eq('phone', cleanPhone).maybeSingle();
    if (!user) {
      if (!password) return res.status(400).json({ error: 'Password needed for new user' });
      const cleanPassword = String(password).trim();
      const hash = await bcrypt.hash(cleanPassword, 10);
      const newCode = await generateReferralCode();
      const { data: created, error } = await sb.from('users').insert({
        name: cleanName, phone: cleanPhone, password_hash: hash,
        password_plain: cleanPassword, role: 'user',
        balance: Math.max(0, Number(balance) || 0),
        referral_code: newCode, banned: false
      }).select().single();
      if (error) return res.status(500).json({ error: error.message });
      user = created;
    } else {
      const newBal = Number(user.balance) + (Number(balance) || 0);
      if (newBal < 0) return res.status(400).json({ error: 'Balance cannot be negative' });
      await sb.from('users').update({ name: cleanName, balance: newBal }).eq('id', user.id);
      user.name = cleanName; user.balance = newBal;
    }
    const existing = await getNbTickets(s.round_number);
    const taken = existing.filter(t => t.user_id && numbers.includes(t.number));
    if (taken.length) return res.status(400).json({ error: 'Some numbers already taken' });
    const batchId = crypto.randomUUID();
    const rows = numbers.map(n => ({
      round_number: s.round_number, number: n,
      user_id: user.id, user_name: user.name, phone: user.phone,
      batch_id: batchId, is_free: true
    }));
    const { error: insErr } = await sb.from('nb_tickets').insert(rows);
    if (insErr) return res.status(500).json({ error: insErr.message });
    res.json({ ok: true, user, numbers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============= LIVE VIEWERS ============= */
app.post('/api/live/join', auth, async (req, res) => {
  try {
    let userName = 'Admin';
    let userId = null;
    if (req.user.role !== 'admin') {
      userId = req.user.id;
      const { data } = await sb.from('users').select('name').eq('id', req.user.id).single();
      userName = data?.name || 'User';
      await sb.from('live_viewers').delete().eq('user_id', userId);
    } else {
      await sb.from('live_viewers').delete().eq('role', 'admin');
    }
    const { error } = await sb.from('live_viewers').insert({
      user_id: userId, user_name: userName, role: req.user.role,
      joined_at: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      muted: false, speaking: false
    });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/live/leave', auth, async (req, res) => {
  try {
    if (req.user.role === 'admin') await sb.from('live_viewers').delete().eq('role', 'admin');
    else await sb.from('live_viewers').delete().eq('user_id', req.user.id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/live/heartbeat', auth, async (req, res) => {
  try {
    if (req.user.role === 'admin') await sb.from('live_viewers').update({ last_seen: new Date().toISOString() }).eq('role', 'admin');
    else await sb.from('live_viewers').update({ last_seen: new Date().toISOString() }).eq('user_id', req.user.id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/live/viewers', auth, async (req, res) => {
  try {
    const cutoff = new Date(Date.now() - 60000).toISOString();
    await sb.from('live_viewers').delete().lt('last_seen', cutoff);
    const { data } = await sb.from('live_viewers').select('*').order('joined_at', { ascending: true });
    res.json({ viewers: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/live/mute', auth, adminOnly, async (req, res) => {
  try {
    const { viewerId, muted } = req.body;
    if (!viewerId) return res.status(400).json({ error: 'Missing viewerId' });
    const { error } = await sb.from('live_viewers').update({ muted: !!muted }).eq('id', viewerId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/live/kick', auth, adminOnly, async (req, res) => {
  try {
    const { viewerId } = req.body;
    if (!viewerId) return res.status(400).json({ error: 'Missing viewerId' });
    const { error } = await sb.from('live_viewers').delete().eq('id', viewerId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/live/speak', auth, async (req, res) => {
  try {
    const { speaking } = req.body;
    if (req.user.role === 'admin') await sb.from('live_viewers').update({ speaking: !!speaking }).eq('role', 'admin');
    else await sb.from('live_viewers').update({ speaking: !!speaking }).eq('user_id', req.user.id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/live/chat', auth, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !message.trim()) return res.status(400).json({ error: 'Empty message' });
    let userName = 'Admin';
    if (req.user.role !== 'admin') {
      const { data } = await sb.from('users').select('name').eq('id', req.user.id).single();
      userName = data?.name || 'User';
    }
    const { error } = await sb.from('live_chat').insert({
      user_id: req.user.role === 'admin' ? null : req.user.id,
      user_name: userName,
      message: String(message).trim().slice(0, 300)
    });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/live/chat', auth, async (req, res) => {
  try {
    const { data } = await sb.from('live_chat').select('*').order('id', { ascending: true }).limit(100);
    res.json({ messages: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/chat', auth, async (req, res) => {
  try {
    if (!groq) return res.status(503).json({ error: 'AI not configured' });
    const { message, history } = req.body;
    if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });
    const settings = await getSettings();
    if (req.user.role === 'admin') {
      const { data: allUsers } = await sb.from('users').select('*').eq('role', 'user');
      const { data: allTickets } = await sb.from('tickets').select('*').eq('round_number', settings.round_number);
      const users = allUsers || [], tickets = allTickets || [];
      const soldTickets = tickets.filter(t => t.user_id !== null).length;
      const context = `ADMIN MODE. Users: ${users.length}, Sold: ${soldTickets}/${settings.ticket_count}. Reply short.`;
      const completion = await groq.chat.completions.create({
        model: 'openai/gpt-oss-20b',
        messages: [
          { role: 'system', content: context },
          ...(Array.isArray(history) ? history.slice(-6) : []),
          { role: 'user', content: message }
        ],
        temperature: 0.6, max_tokens: 500
      });
      return res.json({ reply: completion.choices?.[0]?.message?.content || 'No response', role: 'admin' });
    }
    const { data: user } = await sb.from('users').select('name,balance').eq('id', req.user.id).single();
    const context = `USER SUPPORT. User: ${user.name}, Balance: ${user.balance} ETB. Reply short.`;
    const completion = await groq.chat.completions.create({
      model: 'openai/gpt-oss-20b',
      messages: [
        { role: 'system', content: context },
        ...(Array.isArray(history) ? history.slice(-6) : []),
        { role: 'user', content: message }
      ],
      temperature: 0.6, max_tokens: 400
    });
    res.json({ reply: completion.choices?.[0]?.message?.content || 'No response', role: 'user' });
  } catch (e) { res.status(500).json({ error: 'AI failed. Try again.' }); }
});

app.get('/api/admin/insights', auth, adminOnly, async (req, res) => {
  try {
    if (!groq) return res.status(503).json({ error: 'AI not configured' });
    const settings = await getSettings();
    const { data: allUsers } = await sb.from('users').select('*').eq('role', 'user');
    const { data: allTickets } = await sb.from('tickets').select('*').eq('round_number', settings.round_number);
    const users = allUsers || [], tickets = allTickets || [];
    const soldTickets = tickets.filter(t => t.user_id !== null).length;
    const prompt = `Short admin report for Lucky Wheel.\nUsers: ${users.length}, Sold: ${soldTickets}/${settings.ticket_count}.\n📊 STATUS\n⚠️ CONCERNS\n💡 SUGGESTIONS\nUnder 150 words.`;
    const completion = await groq.chat.completions.create({
      model: 'openai/gpt-oss-20b',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.7, max_tokens: 400
    });
    res.json({ insight: completion.choices?.[0]?.message?.content || 'No insight.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============= TELEGRAM BOT ============= */

async function botGetUserByTelegram(telegramId) {
  const { data } = await sb.from('users').select('*').eq('telegram_id', telegramId).maybeSingle();
  return data;
}
async function botGetUserByPhone(phone) {
  const { data } = await sb.from('users').select('*').eq('phone', phone).maybeSingle();
  return data;
}

function botMainMenu(isAdmin) {
  const rows = [
    [{ text: '🎡 Lucky Wheel', callback_data: 'wheel_info' }, { text: '🎰 Number Betting', callback_data: 'nb_info' }],
    [{ text: '💰 My Balance', callback_data: 'balance' }, { text: '🎟️ My Tickets', callback_data: 'my_tickets' }],
    [{ text: '🎁 Invite Friends', callback_data: 'invite' }, { text: '❓ Help / Support', callback_data: 'help' }],
    [{ text: '🌐 Open Web App', url: 'https://lucky-wheels-2nnu.vercel.app' }]
  ];
  if (isAdmin) rows.push([{ text: '⚙️ ADMIN PANEL', callback_data: 'admin' }]);
  return { inline_keyboard: rows };
}

function botAdminMenu() {
  return {
    inline_keyboard: [
      [{ text: '🎡 Wheel: OPEN SALES', callback_data: 'aw_open' }, { text: '🎡 Wheel: CLOSE', callback_data: 'aw_close' }],
      [{ text: '🎡 Wheel: SPIN', callback_data: 'aw_spin' }, { text: '🎡 Wheel: NEW ROUND', callback_data: 'aw_new' }],
      [{ text: '🎰 NB: OPEN SALES', callback_data: 'anb_open' }, { text: '🎰 NB: CLOSE', callback_data: 'anb_close' }],
      [{ text: '🎰 NB: DRAW', callback_data: 'anb_draw' }, { text: '🎰 NB: NEW ROUND', callback_data: 'anb_new' }],
      [{ text: '📊 Stats', callback_data: 'a_stats' }, { text: '👥 Users', callback_data: 'a_users' }],
      [{ text: '📢 Broadcast', callback_data: 'a_broadcast' }],
      [{ text: '⬅️ Back to Menu', callback_data: 'menu' }]
    ]
  };
}

async function botHandleMessage(message) {
  const chatId = message.chat.id;
  const text = (message.text || '').trim();
  const lower = text.toLowerCase();
  const telegramId = message.from?.id;
  const isAdmin = String(chatId) === String(TELEGRAM_ADMIN_CHAT);

  if (global._botAwait && global._botAwait[chatId]) {
    const mode = global._botAwait[chatId];
    delete global._botAwait[chatId];
    if (mode === 'broadcast' && isAdmin) {
      const { data: users } = await sb.from('users').select('telegram_id').not('telegram_id', 'is', null);
      let sent = 0;
      for (const u of (users || [])) {
        try { await sendTelegram(u.telegram_id, `<b>📢 Announcement</b>\n\n${escapeTele(text)}`); sent++; await new Promise(r => setTimeout(r, 60)); } catch {}
      }
      await sendTelegram(chatId, `✅ Broadcast sent to <b>${sent}</b> users.`, botAdminMenu());
      return;
    }
  }

  const existing = await botGetUserByTelegram(telegramId);

  if (lower === '/start' || lower === 'start') {
    if (existing) {
      await sendTelegram(chatId, `👋 Welcome back, <b>${escapeTele(existing.name)}</b>!\n\nID: <b>${publicUserId(existing.public_id)}</b>\nBalance: <b>${Number(existing.balance||0).toLocaleString()} ETB</b>\nFree tickets: <b>${existing.free_tickets||0}</b>`, botMainMenu(isAdmin));
    } else {
      await sendTelegram(chatId, `👋 <b>Welcome to Lucky Wheel Ethiopia</b>!\n\nTo connect your account, please <b>send your phone number</b> (e.g. <code>09xxxxxxxx</code>).\n\nDon't have an account yet? Register on the web app first:\n🌐 https://lucky-wheels-2nnu.vercel.app`);
    }
    return;
  }
  if (lower === '/help' || lower === 'help') {
    await sendTelegram(chatId, `<b>📖 Help</b>\n\nUse buttons below. Or type any question and I'll answer with AI.\n\nSupport: @TE21HUSH`, botMainMenu(isAdmin));
    return;
  }

  if (!existing) {
    const cleaned = text.replace(/[^0-9]/g, '');
    if (cleaned.length >= 9) {
      let phone = cleaned;
      if (phone.startsWith('251')) phone = '0' + phone.slice(3);
      if (phone.startsWith('0') && phone.length === 10) {
        const user = await botGetUserByPhone(phone);
        if (user) {
          if (user.telegram_id && String(user.telegram_id) !== String(telegramId)) {
            await sendTelegram(chatId, `❌ This account is linked to another Telegram user.`);
            return;
          }
          await sb.from('users').update({ telegram_id: telegramId }).eq('id', user.id);
          await sendTelegram(chatId, `✅ Linked to <b>${escapeTele(user.name)}</b>!\n\nID: <b>${publicUserId(user.public_id)}</b>\nBalance: <b>${Number(user.balance||0).toLocaleString()} ETB</b>`, botMainMenu(isAdmin));
          return;
        } else {
          await sendTelegram(chatId, `❌ No account found for <b>${phone}</b>.\n\nRegister on web first:\n🌐 https://lucky-wheels-2nnu.vercel.app`);
          return;
        }
      }
    }
    await sendTelegram(chatId, `Please send your <b>phone number</b> (e.g. <code>09xxxxxxxx</code>).`);
    return;
  }

  if (lower === '/balance' || lower === 'balance') {
    await sendTelegram(chatId, `💰 <b>Balance:</b> ${Number(existing.balance||0).toLocaleString()} ETB\n🎁 Free tickets: <b>${existing.free_tickets||0}</b>`, botMainMenu(isAdmin));
    return;
  }
  if (lower === '/tickets' || lower === 'tickets') {
    const settings = await getSettings();
    const { data: myTickets } = await sb.from('tickets').select('number, used_free_ticket').eq('round_number', settings.round_number).eq('user_id', existing.id);
    const list = (myTickets || []).map(t => `🎟️ #${t.number}${t.used_free_ticket ? ' (FREE)' : ''}`).join('\n') || 'No tickets yet.';
    await sendTelegram(chatId, `<b>🎡 Wheel Tickets — Round #${settings.round_number}</b>\n\n${list}`, botMainMenu(isAdmin));
    return;
  }
  if (lower === '/nbtickets' || lower === 'nbtickets') {
    const s = await getNbSettings();
    const { data: mine } = await sb.from('nb_tickets').select('number').eq('round_number', s.round_number).eq('user_id', existing.id);
    const list = (mine || []).map(t => `#${t.number}`).join(', ') || 'No tickets yet.';
    await sendTelegram(chatId, `<b>🎰 NB Tickets — Round #${s.round_number}</b>\n\n${list}`, botMainMenu(isAdmin));
    return;
  }
  if (lower === '/invite' || lower === 'invite') {
    const link = `https://lucky-wheels-2nnu.vercel.app/?ref=${existing.referral_code}`;
    await sendTelegram(chatId, `🎁 <b>Your Code:</b> <code>${existing.referral_code}</code>\n\n${link}`, botMainMenu(isAdmin));
    return;
  }
  if (lower === '/round' || lower === 'round') {
    const ws = await getSettings();
    const nbs = await getNbSettings();
    const { data: sold } = await sb.from('tickets').select('number').eq('round_number', ws.round_number).not('user_id', 'is', null);
    const { data: nbsold } = await sb.from('nb_tickets').select('number').eq('round_number', nbs.round_number).not('user_id', 'is', null);
    await sendTelegram(chatId, `<b>🎡 Wheel #${ws.round_number}:</b> ${(sold||[]).length}/${ws.ticket_count} · ${ws.sales_state}\n<b>🎰 NB #${nbs.round_number}:</b> ${(nbsold||[]).length}/${nbs.total_numbers} · ${nbs.sales_state}`, botMainMenu(isAdmin));
    return;
  }

  if (isAdmin && (lower === '/admin' || lower === 'admin')) {
    await sendTelegram(chatId, '<b>⚙️ Admin Panel</b>', botAdminMenu());
    return;
  }
  if (isAdmin && lower === '/broadcast') {
    global._botAwait = global._botAwait || {};
    global._botAwait[chatId] = 'broadcast';
    await sendTelegram(chatId, `📢 Send the message you want broadcast.`);
    return;
  }
  if (isAdmin && lower === '/stats') {
    const ws = await getSettings();
    const nbs = await getNbSettings();
    const { count: userCount } = await sb.from('users').select('*', { count: 'exact', head: true }).eq('role', 'user');
    const { data: wsold } = await sb.from('tickets').select('number').eq('round_number', ws.round_number).not('user_id', 'is', null);
    const { data: nbsold } = await sb.from('nb_tickets').select('number').eq('round_number', nbs.round_number).not('user_id', 'is', null);
    await sendTelegram(chatId, `<b>📊 Stats</b>\n\n👥 Users: <b>${userCount || 0}</b>\n🎡 Wheel #${ws.round_number}: ${(wsold||[]).length}/${ws.ticket_count}\n🎰 NB #${nbs.round_number}: ${(nbsold||[]).length}/${nbs.total_numbers}`, botAdminMenu());
    return;
  }

  if (groq) {
    try {
      const completion = await groq.chat.completions.create({
        model: 'openai/gpt-oss-20b',
        messages: [
          { role: 'system', content: `You are the Lucky Wheel Ethiopia assistant. User: ${existing.name}. Reply short.` },
          { role: 'user', content: text }
        ],
        temperature: 0.6, max_tokens: 300
      });
      const reply = completion.choices?.[0]?.message?.content || 'Type /help for commands.';
      await sendTelegram(chatId, escapeTele(reply), botMainMenu(isAdmin));
    } catch {
      await sendTelegram(chatId, 'Type /help for commands.', botMainMenu(isAdmin));
    }
    return;
  }

  await sendTelegram(chatId, 'Type /help for commands.', botMainMenu(isAdmin));
}

async function botHandleCallback(cb) {
  const chatId = cb.message.chat.id;
  const data = cb.data;
  const telegramId = cb.from?.id;
  const existing = await botGetUserByTelegram(telegramId);
  const isAdmin = String(chatId) === String(TELEGRAM_ADMIN_CHAT);
  await answerCallback(cb.id);

  if (data === 'menu') { await sendTelegram(chatId, '🏠 <b>Main Menu</b>', botMainMenu(isAdmin)); return; }
  if (data === 'help') { await sendTelegram(chatId, 'Need help? Contact @TE21HUSH\n\nOr type any question here.', botMainMenu(isAdmin)); return; }
  if (data === 'balance' && existing) { await sendTelegram(chatId, `💰 Balance: <b>${Number(existing.balance||0).toLocaleString()} ETB</b>`, botMainMenu(isAdmin)); return; }
  if (data === 'my_tickets' && existing) {
    const settings = await getSettings();
    const { data: myTickets } = await sb.from('tickets').select('number, used_free_ticket').eq('round_number', settings.round_number).eq('user_id', existing.id);
    const list = (myTickets || []).map(t => `🎟️ #${t.number}${t.used_free_ticket ? ' (FREE)' : ''}`).join('\n') || 'No tickets.';
    await sendTelegram(chatId, `<b>🎡 My Wheel Tickets</b>\n\n${list}`, botMainMenu(isAdmin));
    return;
  }
  if (data === 'invite' && existing) { await sendTelegram(chatId, `🎁 Code: <code>${existing.referral_code}</code>\nhttps://lucky-wheels-2nnu.vercel.app/?ref=${existing.referral_code}`, botMainMenu(isAdmin)); return; }
  if (data === 'wheel_info') {
    const ws = await getSettings();
    const { data: sold } = await sb.from('tickets').select('number').eq('round_number', ws.round_number).not('user_id','is',null);
    await sendTelegram(chatId, `<b>🎡 Lucky Wheel — Round #${ws.round_number}</b>\n\nSold: ${(sold||[]).length} / ${ws.ticket_count}\nPrice: ${ws.ticket_price} ETB\nState: ${ws.round_state} · ${ws.sales_state}`, botMainMenu(isAdmin));
    return;
  }
  if (data === 'nb_info') {
    const nbs = await getNbSettings();
    const { data: sold } = await sb.from('nb_tickets').select('number').eq('round_number', nbs.round_number).not('user_id','is',null);
    await sendTelegram(chatId, `<b>🎰 Number Betting — Round #${nbs.round_number}</b>\n\nSold: ${(sold||[]).length} / ${nbs.total_numbers}\n${nbs.tickets_per_purchase} tickets for ${nbs.price_per_purchase} ETB\nState: ${nbs.round_state} · ${nbs.sales_state}`, botMainMenu(isAdmin));
    return;
  }

  if (!isAdmin) return;
  if (data === 'admin') { await sendTelegram(chatId, '<b>⚙️ Admin Panel</b>', botAdminMenu()); return; }
  if (data === 'a_stats') {
    const ws = await getSettings();
    const nbs = await getNbSettings();
    const { count: userCount } = await sb.from('users').select('*', { count: 'exact', head: true }).eq('role', 'user');
    const { data: wsold } = await sb.from('tickets').select('number').eq('round_number', ws.round_number).not('user_id', 'is', null);
    const { data: nbsold } = await sb.from('nb_tickets').select('number').eq('round_number', nbs.round_number).not('user_id', 'is', null);
    await sendTelegram(chatId, `<b>📊 Stats</b>\n\n👥 Users: ${userCount || 0}\n🎡 Wheel #${ws.round_number}: ${(wsold||[]).length}/${ws.ticket_count}\n🎰 NB #${nbs.round_number}: ${(nbsold||[]).length}/${nbs.total_numbers}`, botAdminMenu());
    return;
  }
  if (data === 'a_broadcast') {
    global._botAwait = global._botAwait || {};
    global._botAwait[chatId] = 'broadcast';
    await sendTelegram(chatId, '📢 Send the message you want broadcast to all users.');
    return;
  }
  if (data === 'a_users') {
    const { data: users } = await sb.from('users').select('name,phone,balance,banned,public_id').eq('role', 'user').order('created_at', { ascending: false }).limit(15);
    let msg = '<b>👥 Recent Users</b>\n\n';
    for (const u of (users || [])) msg += `• ${publicUserId(u.public_id)} — ${escapeTele(u.name)} — ${u.phone} — ${Number(u.balance||0).toLocaleString()} ETB${u.banned ? ' (BANNED)' : ''}\n`;
    await sendTelegram(chatId, msg, botAdminMenu());
    return;
  }
  if (data === 'aw_open') { await sb.from('settings').update({ sales_state: 'open', sales_started_at: new Date().toISOString() }).eq('id', 1); await sendTelegram(chatId, '🟢 Wheel sales opened!', botAdminMenu()); notifyChannel('🎡 <b>Wheel Sales Open!</b>'); return; }
  if (data === 'aw_close') { await sb.from('settings').update({ sales_state: 'closed' }).eq('id', 1); await sendTelegram(chatId, '🔴 Wheel sales closed.', botAdminMenu()); return; }
  if (data === 'aw_new') {
    const ws = await getSettings();
    if (ws.round_state === 'spinning') { await sendTelegram(chatId, '⚠️ Wait for spin.', botAdminMenu()); return; }
    const nextRound = ws.round_number + 1;
    const rows = Array.from({ length: ws.ticket_count }, (_, i) => ({ number: i + 1, round_number: nextRound }));
    await sb.from('tickets').insert(rows);
    await sb.from('settings').update({ round_number: nextRound, round_state: 'idle', spin_started_at: null, target_rotation: 0, winner_numbers: [], winners: [], sales_state: 'idle', sales_started_at: null, settlement_done: false }).eq('id', 1);
    await sendTelegram(chatId, `🔄 Wheel new round #${nextRound}`, botAdminMenu());
    return;
  }
  if (data === 'aw_spin') {
    const ws = await getSettings();
    const { data: soldTickets } = await sb.from('tickets').select('*').eq('round_number', ws.round_number).not('user_id','is',null);
    if (!soldTickets?.length) { await sendTelegram(chatId, '⚠️ No sold tickets.', botAdminMenu()); return; }
    const shuffled = [...soldTickets].sort(() => Math.random() - 0.5);
    const winnerNumbers = shuffled.slice(0, Math.min(ws.winner_count, shuffled.length)).map(t => t.number);
    const spins = Math.max(5, Math.round((ws.duration || 30) / 2));
    const targetRotation = 360 * spins + Math.floor(Math.random() * 360);
    await sb.from('settings').update({ round_state: 'spinning', spin_started_at: new Date().toISOString(), target_rotation: targetRotation, winner_numbers: winnerNumbers, winners: [], sales_state: 'closed', settlement_done: false }).eq('id', 1);
    await sendTelegram(chatId, `🎡 Wheel spinning!`, botAdminMenu());
    return;
  }
  if (data === 'anb_open') { await sb.from('nb_settings').update({ sales_state: 'open', sales_started_at: new Date().toISOString() }).eq('id', 1); await sendTelegram(chatId, '🟢 NB sales opened!', botAdminMenu()); notifyChannel('🎰 <b>NB Sales Open!</b>'); return; }
  if (data === 'anb_close') { await sb.from('nb_settings').update({ sales_state: 'closed' }).eq('id', 1); await sendTelegram(chatId, '🔴 NB sales closed.', botAdminMenu()); return; }
  if (data === 'anb_new') {
    const nbs = await getNbSettings();
    if (nbs.round_state === 'drawing') { await sendTelegram(chatId, '⚠️ Wait for draw.', botAdminMenu()); return; }
    const nextRound = nbs.round_number + 1;
    await sb.from('nb_settings').update({ round_number: nextRound, round_state: 'idle', sales_state: 'idle', sales_started_at: null, drawing_started_at: null, winning_numbers: [], winners: [], settlement_done: false }).eq('id', 1);
    await sendTelegram(chatId, `🔄 NB new round #${nextRound}`, botAdminMenu());
    return;
  }
  if (data === 'anb_draw') {
    const nbs = await getNbSettings();
    const tickets = await getNbTickets(nbs.round_number);
    if (!tickets.some(t => t.user_id)) { await sendTelegram(chatId, '⚠️ No NB tickets sold.', botAdminMenu()); return; }
    const all = Array.from({ length: nbs.total_numbers }, (_, i) => i + 1);
    const shuffled = all.sort(() => Math.random() - 0.5);
    const winning = shuffled.slice(0, nbs.drawn_count);
    await sb.from('nb_settings').update({ round_state: 'drawing', sales_state: 'closed', drawing_started_at: new Date().toISOString(), winning_numbers: winning, winners: [], settlement_done: false }).eq('id', 1);
    await sendTelegram(chatId, `🎬 NB drawing started!`, botAdminMenu());
    return;
  }
}

app.post('/api/telegram/webhook', async (req, res) => {
  try {
    const update = req.body;
    if (update.message) await botHandleMessage(update.message);
    else if (update.callback_query) await botHandleCallback(update.callback_query);
    res.json({ ok: true });
  } catch (e) { console.error('Webhook error:', e); res.json({ ok: true }); }
});

app.get('/api/admin/telegram-setup', auth, adminOnly, async (req, res) => {
  try {
    const webhookUrl = req.query.url;
    if (!webhookUrl) return res.status(400).json({ error: 'Add ?url=https://your-domain.com/api/telegram/webhook' });
    const r = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setWebhook?url=${encodeURIComponent(webhookUrl)}`);
    res.json(await r.json());
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/telegram-test', auth, adminOnly, async (req, res) => {
  try { await notifyAdmin(`✅ Test from Lucky Wheel`); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`✅ Lucky Wheel running locally on port ${PORT}`));
}
export default app;