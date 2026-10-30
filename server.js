const express = require("express");
const crypto  = require("crypto");

const {
  DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID, REDIRECT_URI, HMAC_SECRET, PORT = 3000,
} = process.env;

for (const [k, v] of Object.entries({
  DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID, REDIRECT_URI, HMAC_SECRET,
})) {
  if (!v) { console.error(`FILL: missing env ${k}`); process.exit(1); }
}

const app = express();

app.get("/health", (_req, res) => res.status(200).json({ ok: true }));

// ---------- signing ----------
function signKey(userId) {
  const payload = Buffer.from(String(userId)).toString("base64url");
  const sig = crypto.createHmac("sha256", HMAC_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function verifyKey(key) {
  if (typeof key !== "string" || !key.includes(".")) return null;
  const [payload, sig] = key.split(".");
  const expect = crypto.createHmac("sha256", HMAC_SECRET).update(payload).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { return Buffer.from(payload, "base64url").toString("utf8"); } catch { return null; }
}

// ---------- member cache ----------
const cache = new Map();
const CACHE_TTL = 8000;

async function getGuildMember(userId) {
  const now = Date.now();
  const hit = cache.get(userId);
  if (hit && hit.expires > now) return hit;

  const r = await fetch(
    `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`,
    { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
  );

  if (r.status === 404) {
    const out = { member: false, expires: now + CACHE_TTL };
    cache.set(userId, out);
    return out;
  }
  if (!r.ok) throw new Error(`guild check ${r.status}`);

  const data = await r.json();
  const out = {
    member: true,
    username: data.user?.username || null,
    globalName: data.user?.global_name || null,
    expires: now + CACHE_TTL,
  };
  cache.set(userId, out);
  return out;
}

// ---------- OAuth ----------
async function exchangeCode(code) {
  const body = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    client_secret: DISCORD_CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
  });
  const r = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!r.ok) throw new Error(`token ${r.status}`);
  return r.json();
}

async function fetchUserId(token) {
  const r = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error(`user ${r.status}`);
  return r.json();
}

// ---------- routes ----------
app.get("/auth", (_req, res) => {
  const p = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "identify guilds",
  });
  res.redirect(`https://discord.com/oauth2/authorize?${p}`);
});

app.get("/auth/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("no code");
  try {
    const token = await exchangeCode(code);
    const user = await fetchUserId(token.access_token);

    const r = await fetch(
      `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}`,
      { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
    );
    const isMember = r.ok;
    cache.set(user.id, { member: isMember, expires: Date.now() + CACHE_TTL });

    if (!isMember) {
      return res.status(403).send(`
        <body style="font-family:sans-serif;background:#121214;color:#fff;text-align:center;padding:80px">
          <h2 style="color:#ef1c25">✕ أنت لست عضوًا في السيرفر</h2>
          <p>ادخل السيرفر أولاً ثم أعد المحاولة.</p>
        </body>`);
    }

    const key = signKey(user.id);
    res.send(`
      <body style="font-family:sans-serif;background:#121214;color:#fff;text-align:center;padding:80px">
        <h2>✓ تم التحقق</h2>
        <p>انسخ المفتاح والصقه في السكربت:</p>
        <pre style="display:inline-block;background:#1e1e22;padding:16px 24px;border-radius:8px;border:1px solid #ef1c25;font-size:15px">${key}</pre>
      </body>`);
  } catch (e) {
    console.error(e);
    res.status(500).send("verification failed");
  }
});

app.get("/check", async (req, res) => {
  const userId = verifyKey(req.query.key);
  if (!userId) return res.json({ ok: false, reason: "bad_key", message: "المفتاح غير صالح" });

  try {
    const m = await getGuildMember(userId);
    if (!m.member) return res.json({ ok: false, reason: "left_guild", message: "لم تعد عضوًا في السيرفر" });
    return res.json({
      ok: true,
      user: { username: m.username, globalName: m.globalName },
    });
  } catch (e) {
    console.error(e);
    return res.json({ ok: false, reason: "backend_error", message: "خطأ مؤقت" });
  }
});

app.listen(PORT, () => console.log(`guard on :${PORT}`));
