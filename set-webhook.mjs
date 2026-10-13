import dotenv from 'dotenv';
import fs from 'fs';

dotenv.config();

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const WEBHOOK_URL = 'https://lucky-wheels-2nnu.vercel.app/api/telegram/webhook';

if (!TOKEN) {
  console.error('❌ TELEGRAM_BOT_TOKEN not found in .env');
  process.exit(1);
}

console.log('🔧 Setting webhook for bot...\n');

// Step 1: delete any old webhook
const delRes = await fetch(`https://api.telegram.org/bot${TOKEN}/deleteWebhook?drop_pending_updates=true`);
const delJson = await delRes.json();
console.log('1. Delete old webhook:', delJson.ok ? '✅ OK' : '⚠️ ' + JSON.stringify(delJson));

// Step 2: set the new webhook
const setRes = await fetch(`https://api.telegram.org/bot${TOKEN}/setWebhook?url=${encodeURIComponent(WEBHOOK_URL)}`);
const setJson = await setRes.json();
console.log('2. Set new webhook:  ', setJson.ok ? '✅ OK' : '❌ ' + JSON.stringify(setJson));

// Step 3: verify
const infoRes = await fetch(`https://api.telegram.org/bot${TOKEN}/getWebhookInfo`);
const infoJson = await infoRes.json();
console.log('\n📋 Webhook info:');
console.log('   URL:             ', infoJson.result?.url || '(none)');
console.log('   Pending updates: ', infoJson.result?.pending_update_count || 0);
console.log('   Last error:      ', infoJson.result?.last_error_message || '(none)');

console.log('\n✅ Done. Now test the bot in Telegram by sending /start');