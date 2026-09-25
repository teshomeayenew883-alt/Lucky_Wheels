import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

/* ============= STATIC FILES ============= */
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ============= SUPABASE ============= */
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
  console.error('❌ Missing SUPABASE_URL or SUPABASE_SERVICE_KEY env vars');
}

const sb = createClient(
  process.env.SUPABASE_URL || 'https://placeholder.supabase.co',
  process.env.SUPABASE_SERVICE_KEY || 'placeholder'
);

const JWT_SECRET     = process.env.JWT_SECRET;
const ADMIN_PHONE    = process.env.ADMIN_PHONE;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

/* ============= HELPERS ============= */

function sign(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
}

async function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Admin only' });
  next();
}

async function getSettings() {
  const { data, error } = await sb.from('settings').select('*').eq('id', 1).single();
  if (error) throw error;
  return data;
}

/* ✅ FIXED: only return tickets of CURRENT round */
async function getTickets() {
  const settings = await getSettings();
  const { data, error } = await sb.from('tickets')
    .select('*')
    .eq('round_number', settings.round_number)
    .order('number');
  if (error) throw error;
  return data;
}

async function generateReferralCode() {
  const letters = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const digits  = '23456789';
  for (let attempt = 0; attempt < 10; attempt++) {
    let code = '';
    for (let i = 0; i < 3; i++) code += letters[Math.floor(Math.random() * letters.length)];
    for (let i = 0; i < 4; i++) code += digits[Math.floor(Math.random() * digits.length)];
    const { data } = await sb.from('users').select('id').eq('referral_code', code).maybeSingle();
    if (!data) return code;
  }
  throw new Error('Could not generate referral code');
}

/* ============= CONFIG ============= */

app.get('/api/config', (req, res) => {
  res.json({
    supabaseUrl: process.env.SUPABASE_URL,
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY
  });
});

/* ============= AUTH ============= */

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, password, referralCode } = req.body;
    if (!name || !phone || !password) return res.status(400).json({ error: 'Please fill all fields' });

    const cleanName     = String(name).trim();
    const cleanPhone    = String(phone).trim();
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
      name: cleanName,
      phone: cleanPhone,
      password_hash: hash,
      password_plain: cleanPassword,
      role: 'user',
      balance: 0,
      referral_code: myCode,
      referred_by: referredBy,
      banned: false
    });

    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true, referral_code: myCode, referred: !!referredBy });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'Phone and password required' });

    const cleanPhone    = String(phone).trim();
    const cleanPassword = String(password).trim();

    if (cleanPhone === ADMIN_PHONE && cleanPassword === ADMIN_PASSWORD) {
      const token = sign({ id: 'ADMIN', role: 'admin', phone: cleanPhone });
      return res.json({ token, role: 'admin' });
    }

    const { data: user, error } = await sb.from('users').select('*').eq('phone', cleanPhone).maybeSingle();
    if (error || !user) return res.status(401).json({ error: 'Invalid phone number or password' });

    if (user.banned) return res.status(403).json({ error: 'Your account has been banned. Contact admin.' });

    const ok = await bcrypt.compare(cleanPassword, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid phone number or password' });

    const token = sign({ id: user.id, role: user.role, phone: user.phone });
    res.json({ token, role: user.role });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============= STATE ============= */

app.get('/api/state', auth, async (req, res) => {
  try {
    const settings = await getSettings();
    const tickets  = await getTickets();
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

/* ============= REFERRALS ============= */

app.get('/api/referrals', auth, async (req, res) => {
  try {
    if (req.user.role === 'admin') return res.json({ referrals: [], activeCount: 0 });
    const { data } = await sb.from('users')
      .select('id,name,phone,has_bought_ticket,created_at')
      .eq('referred_by', req.user.id).order('created_at', { ascending: false });
    const referrals = data || [];
    const activeCount = referrals.filter(r => r.has_bought_ticket).length;
    res.json({ referrals, activeCount });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============= ADMIN: USERS ============= */

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
    if (clean.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
    const hash = await bcrypt.hash(clean, 10);
    const { error } = await sb.from('users')
      .update({ password_hash: hash, password_plain: clean }).eq('id', userId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/users/ban', auth, adminOnly, async (req, res) => {
  try {
    const { userId, banned } = req.body;
    if (!userId) return res.status(400).json({ error: 'Missing userId' });
    const { error } = await sb.from('users')
      .update({ banned: !!banned }).eq('id', userId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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

/* ============= ADMIN: ASSIGN TICKETS ============= */

app.post('/api/admin/tickets/assign', auth, adminOnly, async (req, res) => {
  try {
    const { name, phone, password, balance, numbers, useFreeTicket } = req.body;
    if (!name || !phone || !numbers?.length) return res.status(400).json({ error: 'Missing fields' });

    const cleanName  = String(name).trim();
    const cleanPhone = String(phone).trim();

    let { data: user } = await sb.from('users').select('*').eq('phone', cleanPhone).maybeSingle();
    const isFirstPurchase = !user || !user.has_bought_ticket;

    if (!user) {
      if (!password) return res.status(400).json({ error: 'Password needed for new user' });
      const cleanPassword = String(password).trim();
      const hash = await bcrypt.hash(cleanPassword, 10);
      const newCode = await generateReferralCode();
      const { data: created, error } = await sb.from('users').insert({
        name: cleanName,
        phone: cleanPhone,
        password_hash: hash,
        password_plain: cleanPassword,
        role: 'user',
        balance: Math.max(0, Number(balance) || 0),
        referral_code: newCode,
        banned: false
      }).select().single();
      if (error) return res.status(500).json({ error: error.message });
      user = created;
    } else {
      const newBalance = Number(user.balance) + (Number(balance) || 0);
      if (newBalance < 0) return res.status(400).json({ error: 'Balance cannot be negative' });
      await sb.from('users').update({ name: cleanName, balance: newBalance }).eq('id', user.id);
      user.name = cleanName;
      user.balance = newBalance;
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
            referralMessage = `🎁 ${referrer.name} earned ${reward} FREE ticket for reaching ${goal} active referrals!`;
          }
          await sb.from('users').update({ active_referrals: newActive, free_tickets: newFree }).eq('id', referrer.id);
        }
      }
    }

    res.json({ user, numbers, usedFreeTicket, referralMessage });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============= ADMIN: SETTINGS ============= */

app.post('/api/admin/settings', auth, adminOnly, async (req, res) => {
  try {
    const { duration, winners, prize, ticketPrice, referralGoal, referralReward, prizes } = req.body;
    const update = {
      duration: Math.max(5, Number(duration) || 60),
      winner_count: Math.min(60, Math.max(1, Number(winners) || 1)),
      prize: Math.max(0, Number(prize) || 0),
      ticket_price: Math.max(0, Number(ticketPrice) || 0)
    };
    if (referralGoal !== undefined) update.referral_goal = Math.max(1, Number(referralGoal) || 8);
    if (referralReward !== undefined) update.referral_reward = Math.max(1, Number(referralReward) || 1);
    if (Array.isArray(prizes)) update.prizes = prizes.map(p => Math.max(0, Number(p) || 0));

    const { error } = await sb.from('settings').update(update).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============= ADMIN: TICKET COUNT ============= */

app.post('/api/admin/tickets/count', auth, adminOnly, async (req, res) => {
  try {
    const count = Math.min(60, Math.max(2, Number(req.body.count) || 12));
    const settings = await getSettings();
    const { data: sold } = await sb.from('tickets')
      .select('id').eq('round_number', settings.round_number).not('user_id', 'is', null);
    if (sold?.length) return res.status(400).json({ error: 'Reset the round before changing the ticket count' });

    await sb.from('tickets').delete().eq('round_number', settings.round_number);
    const rows = Array.from({ length: count }, (_, i) => ({ number: i + 1, round_number: settings.round_number }));
    const { error } = await sb.from('tickets').insert(rows);
    if (error) return res.status(500).json({ error: error.message });

    await sb.from('settings').update({
      ticket_count: count, round_state: 'idle', winner_numbers: [], winners: []
    }).eq('id', 1);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ✅ NEW: ADMIN: RESET A SINGLE TICKET */
app.post('/api/admin/tickets/reset-one', auth, adminOnly, async (req, res) => {
  try {
    const { number } = req.body;
    if (!number) return res.status(400).json({ error: 'Missing ticket number' });
    const settings = await getSettings();
    const { error } = await sb.from('tickets')
      .update({
        user_id: null, user_name: null, phone: null,
        sold_date: null, used_free_ticket: false
      })
      .eq('round_number', settings.round_number)
      .eq('number', number);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============= ADMIN: SPIN ============= */

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
      target_rotation: targetRotation, winner_numbers: winnerNumbers, winners: []
    }).eq('id', 1);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
      winners.push({
        place: i + 1,
        ticket: t.number,
        name: user.name,
        phone: user.phone,
        prize: thisPrize
      });
    }

    const { data: allSold } = await sb.from('tickets')
      .select('*').eq('round_number', settings.round_number).not('user_id', 'is', null);
    await sb.from('rounds').insert({
      round_number: settings.round_number, winners,
      sold_tickets: (allSold || []).map(t => ({ number: t.number, name: t.user_name, phone: t.phone }))
    });

    await sb.from('settings').update({ round_state: 'finished', winners }).eq('id', 1);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/round/reset', auth, adminOnly, async (req, res) => {
  try {
    const settings = await getSettings();
    if (settings.round_state === 'spinning') return res.status(400).json({ error: 'Wait for the wheel to finish' });

    const nextRound = settings.round_number + 1;
    const rows = Array.from({ length: settings.ticket_count }, (_, i) => ({ number: i + 1, round_number: nextRound }));
    await sb.from('tickets').insert(rows);

    await sb.from('settings').update({
      round_number: nextRound, round_state: 'idle', spin_started_at: null,
      target_rotation: 0, winner_numbers: [], winners: []
    }).eq('id', 1);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/rounds', auth, async (req, res) => {
  const { data, error } = await sb.from('rounds').select('*').order('id', { ascending: false }).limit(50);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ rounds: data });
});

/* ============= DEPOSITS ============= */

app.post('/api/user/deposits', auth, async (req, res) => {
  try {
    if (req.user.role !== 'user') return res.status(403).json({ error: 'Users only' });
    const { method, amount, transactionId } = req.body;
    if (!method || !amount || !transactionId)
      return res.status(400).json({ error: 'All fields required' });
    if (!['cbe', 'boa'].includes(String(method).toLowerCase()))
      return res.status(400).json({ error: 'Invalid method' });
    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0)
      return res.status(400).json({ error: 'Invalid amount' });

    const { data: user } = await sb.from('users').select('name,phone').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { error } = await sb.from('deposits').insert({
      user_id: req.user.id,
      user_name: user.name,
      phone: user.phone,
      method: String(method).toLowerCase(),
      amount: amt,
      transaction_id: String(transactionId).trim(),
      status: 'pending'
    });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/user/deposits', auth, async (req, res) => {
  if (req.user.role !== 'user') return res.json({ deposits: [] });
  const { data, error } = await sb.from('deposits')
    .select('*').eq('user_id', req.user.id).order('id', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ deposits: data || [] });
});

/* ============= WITHDRAWALS ============= */

app.post('/api/user/withdrawals', auth, async (req, res) => {
  try {
    if (req.user.role !== 'user') return res.status(403).json({ error: 'Users only' });
    const { method, amount, accountNumber } = req.body;
    if (!method || !amount || !accountNumber)
      return res.status(400).json({ error: 'All fields required' });
    if (!['cbe', 'boa'].includes(String(method).toLowerCase()))
      return res.status(400).json({ error: 'Invalid method' });

    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0)
      return res.status(400).json({ error: 'Invalid amount' });

    const { data: user } = await sb.from('users').select('name,phone,balance').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (Number(user.balance) < amt)
      return res.status(400).json({ error: 'Insufficient balance' });

    const newBalance = Number(user.balance) - amt;
    await sb.from('users').update({ balance: newBalance }).eq('id', req.user.id);

    const { error } = await sb.from('withdrawals').insert({
      user_id: req.user.id,
      user_name: user.name,
      phone: user.phone,
      method: String(method).toLowerCase(),
      amount: amt,
      account_number: String(accountNumber).trim(),
      status: 'pending'
    });

    if (error) {
      await sb.from('users').update({ balance: user.balance }).eq('id', req.user.id);
      return res.status(500).json({ error: error.message });
    }

    res.json({ ok: true, newBalance });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/user/withdrawals', auth, async (req, res) => {
  if (req.user.role !== 'user') return res.json({ withdrawals: [] });
  const { data, error } = await sb.from('withdrawals')
    .select('*').eq('user_id', req.user.id).order('id', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ withdrawals: data || [] });
});

/* ============= ADMIN: MANAGE REQUESTS ============= */

app.get('/api/admin/deposits', auth, adminOnly, async (req, res) => {
  const { data, error } = await sb.from('deposits').select('*').order('id', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ deposits: data || [] });
});

app.post('/api/admin/deposits/:id/decide', auth, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { action, comment } = req.body;
    if (!['approve', 'reject'].includes(action))
      return res.status(400).json({ error: 'Invalid action' });

    const { data: dep } = await sb.from('deposits').select('*').eq('id', id).single();
    if (!dep) return res.status(404).json({ error: 'Deposit not found' });
    if (dep.status !== 'pending') return res.status(400).json({ error: 'Already processed' });

    if (action === 'approve') {
      const { data: user } = await sb.from('users').select('balance').eq('id', dep.user_id).single();
      if (!user) return res.status(404).json({ error: 'User not found' });
      await sb.from('users').update({
        balance: Number(user.balance) + Number(dep.amount)
      }).eq('id', dep.user_id);
    }

    await sb.from('deposits').update({
      status: action === 'approve' ? 'approved' : 'rejected',
      admin_comment: comment || '',
      processed_at: new Date().toISOString()
    }).eq('id', id);

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
    if (!['approve', 'reject'].includes(action))
      return res.status(400).json({ error: 'Invalid action' });

    const { data: w } = await sb.from('withdrawals').select('*').eq('id', id).single();
    if (!w) return res.status(404).json({ error: 'Withdrawal not found' });
    if (w.status !== 'pending') return res.status(400).json({ error: 'Already processed' });

    if (action === 'reject') {
      const { data: user } = await sb.from('users').select('balance').eq('id', w.user_id).single();
      if (user) {
        await sb.from('users').update({
          balance: Number(user.balance) + Number(w.amount)
        }).eq('id', w.user_id);
      }
    }

    await sb.from('withdrawals').update({
      status: action === 'approve' ? 'approved' : 'rejected',
      admin_comment: comment || '',
      processed_at: new Date().toISOString()
    }).eq('id', id);

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============= USER: BUY TICKETS ============= */

app.post('/api/user/tickets/buy', auth, async (req, res) => {
  try {
    if (req.user.role !== 'user') return res.status(403).json({ error: 'Users only' });
    const { numbers, useFreeTicket } = req.body;
    if (!numbers?.length) return res.status(400).json({ error: 'Select at least one ticket' });

    const settings = await getSettings();
    const { data: user } = await sb.from('users').select('*').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { data: current } = await sb.from('tickets')
      .select('*').eq('round_number', settings.round_number).in('number', numbers);

    const sold = (current || []).filter(t => t.user_id);
    if (sold.length) return res.status(400).json({ error: 'Some tickets are already sold' });

    let usedFree = false;
    let cost = 0;

    if (useFreeTicket) {
      if ((user.free_tickets || 0) < 1)
        return res.status(400).json({ error: 'No free tickets available' });
      if (numbers.length > 1)
        return res.status(400).json({ error: 'Free ticket can only be used for 1 ticket at a time' });
      usedFree = true;
    } else {
      cost = Number(settings.ticket_price) * numbers.length;
      if (Number(user.balance) < cost)
        return res.status(400).json({ error: 'Insufficient balance. Please deposit first.' });
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

    let referralMessage = null;
    if (!user.has_bought_ticket && user.referred_by) {
      const { data: referrer } = await sb.from('users')
        .select('id,name,active_referrals,free_tickets').eq('id', user.referred_by).single();
      if (referrer) {
        const newActive = (referrer.active_referrals || 0) + 1;
        const goal = settings.referral_goal || 8;
        const reward = settings.referral_reward || 1;
        let newFree = referrer.free_tickets || 0;
        if (newActive % goal === 0) {
          newFree += reward;
          referralMessage = `🎁 ${referrer.name} earned ${reward} FREE ticket for reaching ${goal} active referrals!`;
        }
        await sb.from('users').update({ active_referrals: newActive, free_tickets: newFree }).eq('id', referrer.id);
      }
    }

    res.json({ ok: true, cost, usedFree, referralMessage });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============= BOOT ============= */

const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`✅ Lucky Wheel running locally on port ${PORT}`));
}

export default app;