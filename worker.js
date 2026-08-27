// DOMPETKU v3.1 FINAL
// Fitur: login, transaksi, kategori, budget, akun, transfer antar akun,
// hutang/piutang, jatuh tempo, perpanjang tempo + riwayat.

function json(data, status=200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {"Content-Type":"application/json"}
  });
}

function hex(buf) {
  return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function fromHex(s) {
  const a=new Uint8Array(s.length/2);
  for(let i=0;i<s.length;i+=2)a[i/2]=parseInt(s.slice(i,i+2),16);
  return a.buffer;
}
function b64(buf) {
  let s=""; for(const b of new Uint8Array(buf)) s+=String.fromCharCode(b);
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function unb64(s) {
  s=s.replace(/-/g,"+").replace(/_/g,"/");
  while(s.length%4)s+="=";
  const x=atob(s), a=new Uint8Array(x.length);
  for(let i=0;i<x.length;i++)a[i]=x.charCodeAt(i);
  return a.buffer;
}
function secret(env) {
  if(!env.JWT_SECRET || String(env.JWT_SECRET).length < 16)
    throw new Error("JWT_SECRET belum diset atau terlalu pendek. Isi Secret JWT_SECRET di Cloudflare.");
  return String(env.JWT_SECRET);
}
async function passwordHash(password,saltHex) {
  const enc=new TextEncoder();
  const salt=saltHex?fromHex(saltHex):crypto.getRandomValues(new Uint8Array(16)).buffer;
  const km=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits(
    {name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},km,256);
  return {hash:hex(bits),salt:hex(salt)};
}
async function jwt(payload,env) {
  const enc=new TextEncoder(), s=secret(env);
  const h=b64(enc.encode(JSON.stringify({alg:"HS256",typ:"JWT"})));
  const p=b64(enc.encode(JSON.stringify(payload))), data=h+"."+p;
  const key=await crypto.subtle.importKey("raw",enc.encode(s),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const sig=await crypto.subtle.sign("HMAC",key,enc.encode(data));
  return data+"."+b64(sig);
}
async function verify(token,env) {
  try {
    const [h,p,sig]=token.split("."), enc=new TextEncoder();
    if(!h||!p||!sig)return null;
    const key=await crypto.subtle.importKey("raw",enc.encode(secret(env)),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
    if(!await crypto.subtle.verify("HMAC",key,unb64(sig),enc.encode(h+"."+p)))return null;
    const data=JSON.parse(new TextDecoder().decode(unb64(p)));
    if(data.exp && Date.now()/1000>data.exp)return null;
    return data;
  } catch { return null; }
}
async function uid(request,env) {
  const a=request.headers.get("Authorization")||"";
  if(!a.startsWith("Bearer "))return null;
  const p=await verify(a.slice(7),env);
  return p?.uid||null;
}
function id(){return crypto.randomUUID();}
function today(){return new Date().toISOString().slice(0,10);}

export default {
  async fetch(request,env) {
    const u=new URL(request.url), path=u.pathname;
    if(!path.startsWith("/api/")) return env.ASSETS.fetch(request);

    try {
      // AUTH
      if(path==="/api/register" && request.method==="POST"){
        const b=await request.json(), email=(b.email||"").trim().toLowerCase(), nama=(b.nama||"").trim(), pass=b.password||"";
        if(!email||!nama||pass.length<6)return json({error:"Email, nama dan password minimal 6 karakter wajib diisi."},400);
        if(await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first())
          return json({error:"Email sudah terdaftar."},400);
        const ph=await passwordHash(pass), userId=id(), now=new Date().toISOString();
        await env.DB.prepare("INSERT INTO users(id,email,nama,password_hash,password_salt,created_at) VALUES(?,?,?,?,?,?)")
          .bind(userId,email,nama,ph.hash,ph.salt,now).run();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO akun(id,user_id,nama,tipe,created_at) VALUES(?,?,?,?,?)").bind(id(),userId,"Tunai","cash",now),
          env.DB.prepare("INSERT INTO akun(id,user_id,nama,tipe,created_at) VALUES(?,?,?,?,?)").bind(id(),userId,"Bank","bank",now),
          env.DB.prepare("INSERT INTO akun(id,user_id,nama,tipe,created_at) VALUES(?,?,?,?,?)").bind(id(),userId,"E-Wallet","ewallet",now)
        ]);
        return json({token:await jwt({uid:userId,exp:Math.floor(Date.now()/1000)+2592000},env),nama,email});
      }

      if(path==="/api/login" && request.method==="POST"){
        const b=await request.json(), email=(b.email||"").trim().toLowerCase(), pass=b.password||"";
        const user=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
        if(!user)return json({error:"Email atau password salah."},401);
        const ph=await passwordHash(pass,user.password_salt);
        if(ph.hash!==user.password_hash)return json({error:"Email atau password salah."},401);
        return json({token:await jwt({uid:user.id,exp:Math.floor(Date.now()/1000)+2592000},env),nama:user.nama,email:user.email});
      }

      const userId=await uid(request,env);
      if(!userId)return json({error:"Unauthorized"},401);

      if(path==="/api/me" && request.method==="GET")
        return json(await env.DB.prepare("SELECT id,email,nama FROM users WHERE id=?").bind(userId).first());

      if(path==="/api/profile" && request.method==="POST"){
        const b=await request.json(), nama=(b.nama||"").trim();
        if(!nama)return json({error:"Nama tidak boleh kosong."},400);
        await env.DB.prepare("UPDATE users SET nama=? WHERE id=?").bind(nama,userId).run();
        return json({ok:true,nama});
      }

      if(path==="/api/change-password" && request.method==="POST"){
        const b=await request.json(), user=await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(userId).first();
        const old=await passwordHash(b.passwordLama||"",user.password_salt);
        if(old.hash!==user.password_hash)return json({error:"Password lama salah."},400);
        if((b.passwordBaru||"").length<6)return json({error:"Password baru minimal 6 karakter."},400);
        const ph=await passwordHash(b.passwordBaru);
        await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=? WHERE id=?").bind(ph.hash,ph.salt,userId).run();
        return json({ok:true});
      }

      // TRANSACTIONS
      if(path==="/api/transactions" && request.method==="GET")
        return json((await env.DB.prepare("SELECT * FROM transactions WHERE user_id=? ORDER BY tanggal DESC,created_at DESC").bind(userId).all()).results);

      if(path==="/api/transactions" && request.method==="POST"){
        const b=await request.json(), n=Number(b.jumlah);
        if(!["masuk","keluar"].includes(b.tipe)||!Number.isFinite(n)||n<=0)return json({error:"Data transaksi tidak valid."},400);
        if(b.akunId){
          const a=await env.DB.prepare("SELECT id FROM akun WHERE id=? AND user_id=?").bind(b.akunId,userId).first();
          if(!a)return json({error:"Akun tidak ditemukan."},404);
        }
        const x=id();
        await env.DB.prepare("INSERT INTO transactions(id,user_id,tipe,jumlah,kategori,catatan,tanggal,created_at,akun_id) VALUES(?,?,?,?,?,?,?,?,?)")
          .bind(x,userId,b.tipe,n,b.kategori||"Lainnya",b.catatan||"",b.tanggal||today(),new Date().toISOString(),b.akunId||null).run();
        return json({id:x,ok:true});
      }

      let m=path.match(/^\/api\/transactions\/([a-f0-9-]+)$/);
      if(m && request.method==="DELETE"){
        await env.DB.prepare("DELETE FROM transactions WHERE id=? AND user_id=?").bind(m[1],userId).run();
        return json({ok:true});
      }

      // CATEGORIES
      if(path==="/api/categories" && request.method==="GET")
        return json((await env.DB.prepare("SELECT * FROM categories WHERE user_id=? ORDER BY nama").bind(userId).all()).results);
      if(path==="/api/categories" && request.method==="POST"){
        const b=await request.json(), n=(b.nama||"").trim();
        if(!n||!["masuk","keluar"].includes(b.tipe))return json({error:"Kategori tidak valid."},400);
        const x=id(); await env.DB.prepare("INSERT INTO categories(id,user_id,tipe,nama,created_at) VALUES(?,?,?,?,?)").bind(x,userId,b.tipe,n,new Date().toISOString()).run();
        return json({id:x,ok:true});
      }
      m=path.match(/^\/api\/categories\/([a-f0-9-]+)$/);
      if(m&&request.method==="DELETE"){await env.DB.prepare("DELETE FROM categories WHERE id=? AND user_id=?").bind(m[1],userId).run();return json({ok:true});}

      // BUDGET
      if(path==="/api/budgets"&&request.method==="GET"){
        const b=await env.DB.prepare("SELECT * FROM budgets WHERE user_id=? AND bulan=? AND tahun=?")
          .bind(userId,Number(u.searchParams.get("bulan")),Number(u.searchParams.get("tahun"))).all();
        return json(b.results);
      }
      if(path==="/api/budgets"&&request.method==="POST"){
        const b=await request.json(), n=Number(b.limit_amount);
        if(!b.kategori||!n||n<=0)return json({error:"Data budget tidak valid."},400);
        const old=await env.DB.prepare("SELECT id FROM budgets WHERE user_id=? AND kategori=? AND bulan=? AND tahun=?")
          .bind(userId,b.kategori,b.bulan,b.tahun).first();
        if(old)await env.DB.prepare("UPDATE budgets SET limit_amount=? WHERE id=?").bind(n,old.id).run();
        else await env.DB.prepare("INSERT INTO budgets(id,user_id,kategori,bulan,tahun,limit_amount) VALUES(?,?,?,?,?,?)").bind(id(),userId,b.kategori,b.bulan,b.tahun,n).run();
        return json({ok:true});
      }

      // ACCOUNTS
      if(path==="/api/akun"&&request.method==="GET")
        return json((await env.DB.prepare("SELECT * FROM akun WHERE user_id=? ORDER BY created_at").bind(userId).all()).results);
      if(path==="/api/akun"&&request.method==="POST"){
        const b=await request.json(), n=(b.nama||"").trim();
        if(!n||!["cash","bank","ewallet","lainnya"].includes(b.tipe))return json({error:"Data akun tidak valid."},400);
        const x=id(); await env.DB.prepare("INSERT INTO akun(id,user_id,nama,tipe,created_at) VALUES(?,?,?,?,?)").bind(x,userId,n,b.tipe,new Date().toISOString()).run();
        return json({id:x,ok:true});
      }
      m=path.match(/^\/api\/akun\/([a-f0-9-]+)$/);
      if(m&&request.method==="DELETE"){
        const a=await env.DB.prepare("SELECT id FROM akun WHERE id=? AND user_id=?").bind(m[1],userId).first();
        if(!a)return json({error:"Akun tidak ditemukan."},404);
        await env.DB.prepare("DELETE FROM akun WHERE id=? AND user_id=?").bind(m[1],userId).run();
        return json({ok:true});
      }

      // TRANSFER
      if(path==="/api/transfer"&&request.method==="GET")
        return json((await env.DB.prepare(`
          SELECT t.*,a.nama akun_asal,b.nama akun_tujuan
          FROM transfer t LEFT JOIN akun a ON a.id=t.akun_asal_id LEFT JOIN akun b ON b.id=t.akun_tujuan_id
          WHERE t.user_id=? ORDER BY t.tanggal DESC,t.created_at DESC
        `).bind(userId).all()).results);

      if(path==="/api/transfer"&&request.method==="POST"){
        const b=await request.json(), n=Number(b.jumlah);
        if(!b.akunAsalId||!b.akunTujuanId||b.akunAsalId===b.akunTujuanId||!n||n<=0)return json({error:"Transfer tidak valid."},400);
        const a=await env.DB.prepare("SELECT id FROM akun WHERE id IN (?,?) AND user_id=?").bind(b.akunAsalId,b.akunTujuanId,userId).all();
        if(a.results.length!==2)return json({error:"Akun tidak ditemukan."},404);
        const x=id();
        await env.DB.prepare("INSERT INTO transfer(id,user_id,akun_asal_id,akun_tujuan_id,jumlah,catatan,tanggal,created_at) VALUES(?,?,?,?,?,?,?,?)")
          .bind(x,userId,b.akunAsalId,b.akunTujuanId,n,b.catatan||"",b.tanggal||today(),new Date().toISOString()).run();
        return json({id:x,ok:true});
      }
      m=path.match(/^\/api\/transfer\/([a-f0-9-]+)$/);
      if(m&&request.method==="DELETE"){await env.DB.prepare("DELETE FROM transfer WHERE id=? AND user_id=?").bind(m[1],userId).run();return json({ok:true});}

      // UTANG / PIUTANG
      if(path==="/api/utang"&&request.method==="GET")
        return json((await env.DB.prepare("SELECT * FROM utang WHERE user_id=? ORDER BY lunas ASC,tanggal DESC").bind(userId).all()).results);

      if(path==="/api/utang"&&request.method==="POST"){
        const b=await request.json(), n=Number(b.jumlah);
        if(!["utang","piutang"].includes(b.tipe)||!b.nama||!n||n<=0)return json({error:"Data hutang/piutang tidak valid."},400);
        const x=id();
        await env.DB.prepare("INSERT INTO utang(id,user_id,tipe,nama,jumlah,catatan,tanggal,jatuh_tempo,lunas,created_at) VALUES(?,?,?,?,?,?,?,?,0,?)")
          .bind(x,userId,b.tipe,b.nama.trim(),n,b.catatan||"",b.tanggal||today(),b.jatuhTempo||null,new Date().toISOString()).run();
        return json({id:x,ok:true});
      }

      m=path.match(/^\/api\/utang\/([a-f0-9-]+)\/lunas$/);
      if(m&&request.method==="PATCH"){
        const r=await env.DB.prepare("SELECT lunas FROM utang WHERE id=? AND user_id=?").bind(m[1],userId).first();
        if(!r)return json({error:"Tidak ditemukan."},404);
        const v=r.lunas?0:1;
        await env.DB.prepare("UPDATE utang SET lunas=? WHERE id=? AND user_id=?").bind(v,m[1],userId).run();
        return json({ok:true,lunas:!!v});
      }

      m=path.match(/^\/api\/utang\/([a-f0-9-]+)\/perpanjang-tempo$/);
      if(m&&request.method==="PATCH"){
        const b=await request.json(), baru=b.jatuhTempoBaru;
        if(!baru)return json({error:"Jatuh tempo baru wajib diisi."},400);
        const r=await env.DB.prepare("SELECT id,jatuh_tempo,lunas FROM utang WHERE id=? AND user_id=?").bind(m[1],userId).first();
        if(!r)return json({error:"Data tidak ditemukan."},404);
        if(r.lunas)return json({error:"Data sudah lunas."},400);
        await env.DB.batch([
          env.DB.prepare("UPDATE utang SET jatuh_tempo=? WHERE id=? AND user_id=?").bind(baru,m[1],userId),
          env.DB.prepare("INSERT INTO utang_tempo_history(id,utang_id,user_id,tempo_lama,tempo_baru,alasan,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(id(),m[1],userId,r.jatuh_tempo||null,baru,b.alasan||"",new Date().toISOString())
        ]);
        return json({ok:true,jatuh_tempo:baru});
      }

      m=path.match(/^\/api\/utang\/([a-f0-9-]+)\/riwayat-tempo$/);
      if(m&&request.method==="GET")
        return json((await env.DB.prepare("SELECT * FROM utang_tempo_history WHERE utang_id=? AND user_id=? ORDER BY created_at DESC").bind(m[1],userId).all()).results);

      m=path.match(/^\/api\/utang\/([a-f0-9-]+)$/);
      if(m&&request.method==="DELETE"){await env.DB.prepare("DELETE FROM utang WHERE id=? AND user_id=?").bind(m[1],userId).run();return json({ok:true});}

      return json({error:"Not found"},404);
    } catch(e) {
      return json({error:"Server error: "+e.message},500);
    }
  }
};
