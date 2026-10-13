import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
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

const JWT_SECRET     = process.env.JWT_SECRET;
const ADMIN_PHONE    = process.env.ADMIN_PHONE;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_RESET_CODE = process.env.ADMIN_RESET_CODE || '100510';

const groq = process.env.GROQ_API_KEY ? new Groq({ apiKey: process.env.GROQ_API_KEY }) : null;

const TELEGRAM_BOT_TOKEN     = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_ADMIN_CHAT    = process.env.TELEGRAM_ADMIN_CHAT;
const TELEGRAM_CHANNEL       = process.env.TELEGRAM_CHANNEL || '@Lucky21_Wheel';
const TELEGRAM_BOT_USERNAME  = process.env.TELEGRAM_BOT_USERNAME || 'Numbers_Betting_bot';

async function sendTelegram(chatId, message) {
  if (!TELEGRAM_BOT_TOKEN || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: 'HTML', disable_web_page_preview: true })
    });
  } catch (e) { console.error('Telegram send error:', e.message); }
}

async function notifyAdmin(message) { return sendTelegram(TELEGRAM_ADMIN_CHAT, message); }
async function notifyChannel(message) { return sendTelegram(TELEGRAM_CHANNEL, message); }

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
  const { data, error } = await sb.from('tickets')
    .select('*').eq('round_number', settings.round_number).order('number');
  if (error) throw error;
  return data;
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
      const { data: referrer } = await sb.from('users')
        .select('id').eq('referral_code', String(referralCode).trim().toUpperCase()).maybeSingle();
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

    notifyAdmin(`👤 <b>New User Registered</b>\n\nName: ${cleanName}\nPhone: ${cleanPhone}\nReferral code: ${myCode}`);
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
      const { data } = await sb.from('users')
        .select('id,name,phone,balance,role,referral_code,active_referrals,free_tickets,has_bought_ticket')
        .eq('id', req.user.id).single();
      me = data;
    }
    res.json({ settings, tickets, me });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/referrals', auth, async (req, res) => {
  try {
    if (req.user.role === 'admin') return res.json({ referrals: [], activeCount: 0 });
    const { data } = await sb.from('users')
      .select('id,name,phone,has_bought_ticket,created_at')
      .eq('referred_by', req.user.id).order('created_at', { ascending: false });
    const referrals = data || [];
    const activeCount = referrals.filter(r => r.has_bought_ticket).length;
    res.json({ referrals, activeCount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { data, error } = await sb.from('users')
    .select('id,name,phone,balance,active_referrals,free_tickets,has_bought_ticket,referral_code,referred_by')
    .eq('role', 'user').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ users: data });
});

app.get('/api/admin/users/full', auth, adminOnly, async (req, res) => {
  const { data, error } = await sb.from('users')
    .select('id,name,phone,balance,role,referral_code,active_referrals,free_tickets,has_bought_ticket,banned,password_plain')
    .eq('role', 'user').order('created_at');
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
    const { data: current } = await sb.from('tickets')
      .select('*').eq('round_number', settings.round_number).in('number', numbers);

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
        await sb.from('tickets').update({
          user_id: user.id, user_name: cleanName, phone: cleanPhone, sold_date: soldDate, used_free_ticket: usedFreeTicket
        }).eq('id', existing.id);
      } else {
        await sb.from('tickets').insert({
          number: n, user_id: user.id, user_name: cleanName, phone: cleanPhone,
          sold_date: soldDate, round_number: settings.round_number, used_free_ticket: usedFreeTicket
        });
      }
    }

    let referralMessage = null;
    if (isFirstPurchase) {
      await sb.from('users').update({ has_bought_ticket: true }).eq('id', user.id);
      if (user.referred_by) {
        const { data: referrer } = await sb.from('users')
          .select('id,name,active_referrals,free_tickets').eq('id', user.referred_by).single();
        if (referrer) {
          const newActive = (referrer.active_referrals || 0) + 1;
          const goal = settings.referral_goal || 8;
          const reward = settings.referral_reward || 1;
          let newFree = referrer.free_tickets || 0;
          if (newActive % goal === 0) {
            newFree += reward;
            referralMessage = `🎁 ${referrer.name} earned ${reward} FREE ticket!`;
          }
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
    const { data: sold } = await sb.from('tickets')
      .select('id').eq('round_number', settings.round_number).not('user_id', 'is', null);
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
    const { error } = await sb.from('tickets')
      .update({ user_id: null, user_name: null, phone: null, sold_date: null, used_free_ticket: false })
      .eq('round_number', settings.round_number).eq('number', number);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/start-sales', auth, adminOnly, async (req, res) => {
  try {
    const settings = await getSettings();
    if (settings.sales_state === 'open') return res.status(400).json({ error: 'Sales already open' });
    if (settings.round_state === 'spinning') return res.status(400).json({ error: 'Wheel is spinning' });

    const { error } = await sb.from('settings').update({
      sales_state: 'open',
      sales_started_at: new Date().toISOString()
    }).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });

    notifyChannel(`🎡 <b>Sales Open!</b>\n\nRound #${settings.round_number}\nBuy tickets now!`);
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

    const { data: soldTickets } = await sb.from('tickets')
      .select('*').eq('round_number', settings.round_number).not('user_id', 'is', null);
    if (!soldTickets?.length) return res.status(400).json({ error: 'No sold tickets yet' });

    const shuffled = [...soldTickets].sort(() => Math.random() - 0.5);
    const winnerNumbers = shuffled.slice(0, Math.min(settings.winner_count, shuffled.length)).map(t => t.number);
    const targetRotation = 360 * 30 + Math.floor(Math.random() * 360);

    const { error } = await sb.from('settings').update({
      round_state: 'spinning', spin_started_at: new Date().toISOString(),
      target_rotation: targetRotation, winner_numbers: winnerNumbers, winners: [],
      sales_state: 'closed'
    }).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/spin/settle', async (req, res) => {
  try {
    const settings = await getSettings();
    if (settings.round_state !== 'spinning') return res.json({ ok: true });

    const started = new Date(settings.spin_started_at).getTime();
    if (Date.now() - started < settings.duration * 1000) return res.json({ ok: true });

    const winnerNumbers = settings.winner_numbers || [];
    const { data: tickets } = await sb.from('tickets')
      .select('*').eq('round_number', settings.round_number).in('number', winnerNumbers);

    const prizes = Array.isArray(settings.prizes) ? settings.prizes : [];
    const winners = [];

    for (let i = 0; i < (tickets || []).length; i++) {
      const t = tickets[i];
      const { data: user } = await sb.from('users').select('*').eq('id', t.user_id).single();
      if (!user) continue;
      const thisPrize = prizes[i] !== undefined ? Number(prizes[i]) : Number(settings.prize);
      await sb.from('users').update({ balance: Number(user.balance) + thisPrize }).eq('id', user.id);
      winners.push({ place: i + 1, ticket: t.number, name: user.name, phone: user.phone, prize: thisPrize });
    }

    const { data: allSold } = await sb.from('tickets')
      .select('*').eq('round_number', settings.round_number).not('user_id', 'is', null);
    await sb.from('rounds').insert({
      round_number: settings.round_number, winners,
      sold_tickets: (allSold || []).map(t => ({ number: t.number, name: t.user_name, phone: t.phone }))
    });

    await sb.from('settings').update({ round_state: 'finished', winners }).eq('id', 1);

    if (winners.length) {
      const winnerText = winners.map(w => `🏆 #${w.place} ${w.name} — Ticket #${w.ticket} — ${w.prize} ETB`).join('\n');
      notifyAdmin(`🎡 <b>Round #${settings.round_number} Completed</b>\n\nWinners:\n${winnerText}`);
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
      sales_state: 'idle', sales_started_at: null
    }).eq('id', 1);

    await sb.from('live_viewers').delete().neq('id', 0);
    await sb.from('live_chat').delete().neq('id', 0);

    notifyAdmin(`🔄 <b>New Round Started</b> (#${nextRound})`);
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

    notifyAdmin(`💰 <b>New Deposit</b>\n\nUser: ${user.name}\nAmount: ${amt} ETB`);
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

    notifyAdmin(`💸 <b>New Withdrawal</b>\n\nUser: ${user.name}\nAmount: ${amt} ETB`);
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
      const { data: user } = await sb.from('users').select('balance').eq('id', dep.user_id).single();
      if (!user) return res.status(404).json({ error: 'User not found' });
      await sb.from('users').update({ balance: Number(user.balance) + Number(dep.amount) }).eq('id', dep.user_id);
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
      const { data: user } = await sb.from('users').select('balance').eq('id', w.user_id).single();
      if (user) {
        await sb.from('users').update({ balance: Number(user.balance) + Number(w.amount) }).eq('id', w.user_id);
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

    const { data: current } = await sb.from('tickets')
      .select('*').eq('round_number', settings.round_number).in('number', numbers);

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
        await sb.from('tickets').update({
          user_id: user.id, user_name: user.name, phone: user.phone,
          sold_date: soldDate, used_free_ticket: usedFree
        }).eq('id', existing.id);
      } else {
        await sb.from('tickets').insert({
          number: n, user_id: user.id, user_name: user.name, phone: user.phone,
          sold_date: soldDate, round_number: settings.round_number, used_free_ticket: usedFree
        });
      }
    }

    res.json({ ok: true, cost, usedFree });
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
    if (req.user.role === 'admin') {
      await sb.from('live_viewers').update({ last_seen: new Date().toISOString() }).eq('role', 'admin');
    } else {
      await sb.from('live_viewers').update({ last_seen: new Date().toISOString() }).eq('user_id', req.user.id);
    }
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
    if (req.user.role === 'admin') {
      await sb.from('live_viewers').update({ speaking: !!speaking }).eq('role', 'admin');
    } else {
      await sb.from('live_viewers').update({ speaking: !!speaking }).eq('user_id', req.user.id);
    }
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

/* ============= AI CHAT ============= */
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

      const context = `ADMIN MODE. Users: ${users.length}, Sold: ${soldTickets}/${settings.ticket_count}. Reply in English/Amharic, short.`;

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

    const { data: user } = await sb.from('users')
      .select('name,phone,balance,referral_code,active_referrals,free_tickets')
      .eq('id', req.user.id).single();

    const context = `USER SUPPORT. User: ${user.name}, Balance: ${user.balance} ETB. Never reveal others' data. Reply short.`;

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
  } catch (e) {
    console.error('AI error:', e);
    res.status(500).json({ error: 'AI failed. Try again.' });
  }
});

app.get('/api/admin/insights', auth, adminOnly, async (req, res) => {
  try {
    if (!groq) return res.status(503).json({ error: 'AI not configured' });
    const settings = await getSettings();
    const { data: allUsers } = await sb.from('users').select('*').eq('role', 'user');
    const { data: allTickets } = await sb.from('tickets').select('*').eq('round_number', settings.round_number);
    const users = allUsers || [], tickets = allTickets || [];
    const soldTickets = tickets.filter(t => t.user_id !== null).length;

    const prompt = `Give short admin report for Lucky Wheel.\nUsers: ${users.length}, Sold: ${soldTickets}/${settings.ticket_count}.\n📊 STATUS\n⚠️ CONCERNS\n💡 SUGGESTIONS\nUnder 150 words.`;

    const completion = await groq.chat.completions.create({
      model: 'openai/gpt-oss-20b',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.7, max_tokens: 400
    });
    res.json({ insight: completion.choices?.[0]?.message?.content || 'No insight.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============= TELEGRAM WEBHOOK ============= */
app.post('/api/telegram/webhook', async (req, res) => {
  try {
    const update = req.body;
    const message = update?.message;
    if (!message) return res.json({ ok: true });

    const chatId = message.chat.id;
    const text = (message.text || '').trim().toLowerCase();
    const firstName = message.from?.first_name || 'friend';

    let reply = '';
    if (text === '/start') {
      reply = `👋 Welcome, ${firstName}!\n\n🎡 Lucky Wheel Ethiopia\n\nPlay: https://lucky-wheels-one.vercel.app\n\n📢 ${TELEGRAM_CHANNEL}`;
    } else if (text === '/help') {
      reply = `Commands: /start /play /balance /support`;
    } else if (text === '/play') {
      reply = `🎡 Play: https://lucky-wheels-one.vercel.app`;
    } else if (text === '/support') {
      reply = `📞 Contact admin: 0928151586`;
    } else {
      reply = `Type /help for commands.`;
    }

    await sendTelegram(chatId, reply);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: true }); }
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
  try {
    await notifyAdmin(`✅ Test from Lucky Wheel`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`✅ Lucky Wheel running locally on port ${PORT}`));
}
export default app;