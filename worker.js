// ============ HELPERS ============

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i/2] = parseInt(hex.substr(i,2), 16);
  return bytes.buffer;
}
function b64url(input) {
  let str = typeof input === "string" ? input : bufToBase64(input);
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function bufToBase64(buf) {
  let binary = "";
  const bytes = new Uint8Array(buf);
  for (let b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
function b64urlToBuf(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return { hash: bufToHex(derived), salt: bufToHex(salt) };
}

async function signToken(payload, secret) {
  const enc = new TextEncoder();
  const header = { alg: "HS256", typ: "JWT" };
  const headerB64 = b64url(bufToBase64(enc.encode(JSON.stringify(header))));
  const payloadB64 = b64url(bufToBase64(enc.encode(JSON.stringify(payload))));
  const data = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  const sigB64 = b64url(bufToBase64(sig));
  return `${data}.${sigB64}`;
}

async function verifyToken(token, secret) {
  try {
    const [headerB64, payloadB64, sigB64] = token.split(".");
    const enc = new TextEncoder();
    const data = `${headerB64}.${payloadB64}`;
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, b64urlToBuf(sigB64), enc.encode(data));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBuf(payloadB64)));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

async function getUserFromRequest(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  const payload = await verifyToken(token, env.JWT_SECRET);
  if (!payload) return null;
  return payload.uid;
}

// ============ MAIN HANDLER ============

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (!path.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    try {
      // ---------- REGISTER ----------
      if (path === "/api/register" && request.method === "POST") {
        const body = await request.json();
        const email = (body.email || "").trim().toLowerCase();
        const nama = (body.nama || "").trim();
        const password = body.password || "";
        if (!email || !nama || password.length < 6) {
          return json({ error: "Email, nama wajib diisi, dan password minimal 6 karakter." }, 400);
        }
        const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
        if (existing) return json({ error: "Email sudah terdaftar." }, 400);

        const { hash, salt } = await hashPassword(password);
        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO users (id, email, nama, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        ).bind(id, email, nama, hash, salt, new Date().toISOString()).run();

        const token = await signToken({ uid: id, exp: Math.floor(Date.now()/1000) + 60*60*24*30 }, env.JWT_SECRET);
        return json({ token, nama, email });
      }

      // ---------- LOGIN ----------
      if (path === "/api/login" && request.method === "POST") {
        const body = await request.json();
        const email = (body.email || "").trim().toLowerCase();
        const password = body.password || "";
        const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        if (!user) return json({ error: "Email atau password salah." }, 401);
        const { hash } = await hashPassword(password, user.password_salt);
        if (hash !== user.password_hash) return json({ error: "Email atau password salah." }, 401);

        const token = await signToken({ uid: user.id, exp: Math.floor(Date.now()/1000) + 60*60*24*30 }, env.JWT_SECRET);
        return json({ token, nama: user.nama, email: user.email });
      }

      // ---------- ME ----------
      if (path === "/api/me" && request.method === "GET") {
        const uid = await getUserFromRequest(request, env);
        if (!uid) return json({ error: "Unauthorized" }, 401);
        const user = await env.DB.prepare("SELECT id, email, nama FROM users WHERE id = ?").bind(uid).first();
        if (!user) return json({ error: "User tidak ditemukan" }, 404);
        return json(user);
      }

      // ---------- CHANGE PASSWORD ----------
      if (path === "/api/change-password" && request.method === "POST") {
        const uid = await getUserFromRequest(request, env);
        if (!uid) return json({ error: "Unauthorized" }, 401);
        const body = await request.json();
        const { passwordLama, passwordBaru } = body;
        if (!passwordBaru || passwordBaru.length < 6) return json({ error: "Password baru minimal 6 karakter." }, 400);
        const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(uid).first();
        const { hash: hashLama } = await hashPassword(passwordLama, user.password_salt);
        if (hashLama !== user.password_hash) return json({ error: "Password lama salah." }, 400);
        const { hash, salt } = await hashPassword(passwordBaru);
        await env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?").bind(hash, salt, uid).run();
        return json({ ok: true });
      }

      // ---------- EDIT PROFILE (nama) ----------
      if (path === "/api/profile" && request.method === "POST") {
        const uid = await getUserFromRequest(request, env);
        if (!uid) return json({ error: "Unauthorized" }, 401);
        const body = await request.json();
        const nama = (body.nama || "").trim();
        if (!nama) return json({ error: "Nama tidak boleh kosong." }, 400);
        await env.DB.prepare("UPDATE users SET nama = ? WHERE id = ?").bind(nama, uid).run();
        return json({ ok: true, nama });
      }

      // ---------- TRANSACTIONS: LIST + CREATE ----------
      if (path === "/api/transactions" && request.method === "GET") {
        const uid = await getUserFromRequest(request, env);
        if (!uid) return json({ error: "Unauthorized" }, 401);
        const { results } = await env.DB.prepare(
          "SELECT * FROM transactions WHERE user_id = ? ORDER BY tanggal DESC"
        ).bind(uid).all();
        return json(results);
      }

      if (path === "/api/transactions" && request.method === "POST") {
        const uid = await getUserFromRequest(request, env);
        if (!uid) return json({ error: "Unauthorized" }, 401);
        const body = await request.json();
        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO transactions (id, user_id, tipe, jumlah, kategori, catatan, tanggal, created_at) VALUES (?,?,?,?,?,?,?,?)"
        ).bind(id, uid, body.tipe, body.jumlah, body.kategori, body.catatan || "", body.tanggal, new Date().toISOString()).run();
        return json({ id, ok: true });
      }

      // ---------- TRANSACTIONS: DELETE ----------
      const trxMatch = path.match(/^\/api\/transactions\/([a-f0-9-]+)$/);
      if (trxMatch && request.method === "DELETE") {
        const uid = await getUserFromRequest(request, env);
        if (!uid) return json({ error: "Unauthorized" }, 401);
        await env.DB.prepare("DELETE FROM transactions WHERE id = ? AND user_id = ?").bind(trxMatch[1], uid).run();
        return json({ ok: true });
      }

      // ---------- UTANG: LIST + CREATE ----------
      if (path === "/api/utang" && request.method === "GET") {
        const uid = await getUserFromRequest(request, env);
        if (!uid) return json({ error: "Unauthorized" }, 401);
        const { results } = await env.DB.prepare(
          "SELECT * FROM utang WHERE user_id = ? ORDER BY lunas ASC, tanggal DESC"
        ).bind(uid).all();
        return json(results);
      }

      if (path === "/api/utang" && request.method === "POST") {
        const uid = await getUserFromRequest(request, env);
        if (!uid) return json({ error: "Unauthorized" }, 401);
        const body = await request.json();
        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO utang (id, user_id, tipe, nama, jumlah, catatan, tanggal, lunas, created_at) VALUES (?,?,?,?,?,?,?,0,?)"
        ).bind(id, uid, body.tipe, body.nama, body.jumlah, body.catatan || "", body.tanggal, new Date().toISOString()).run();
        return json({ id, ok: true });
      }

      // ---------- UTANG: TOGGLE LUNAS ----------
      const utangLunasMatch = path.match(/^\/api\/utang\/([a-f0-9-]+)\/lunas$/);
      if (utangLunasMatch && request.method === "PATCH") {
        const uid = await getUserFromRequest(request, env);
        if (!uid) return json({ error: "Unauthorized" }, 401);
        const row = await env.DB.prepare("SELECT lunas FROM utang WHERE id = ? AND user_id = ?").bind(utangLunasMatch[1], uid).first();
        if (!row) return json({ error: "Tidak ditemukan" }, 404);
        const newVal = row.lunas ? 0 : 1;
        await env.DB.prepare("UPDATE utang SET lunas = ? WHERE id = ? AND user_id = ?").bind(newVal, utangLunasMatch[1], uid).run();
        return json({ ok: true, lunas: !!newVal });
      }

      // ---------- UTANG: DELETE ----------
      const utangDelMatch = path.match(/^\/api\/utang\/([a-f0-9-]+)$/);
      if (utangDelMatch && request.method === "DELETE") {
        const uid = await getUserFromRequest(request, env);
        if (!uid) return json({ error: "Unauthorized" }, 401);
        await env.DB.prepare("DELETE FROM utang WHERE id = ? AND user_id = ?").bind(utangDelMatch[1], uid).run();
        return json({ ok: true });
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      return json({ error: "Server error: " + err.message }, 500);
    }
  }
};
