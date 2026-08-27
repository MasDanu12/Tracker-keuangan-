export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;
    const headers = request.headers;

    // Inisialisasi Database D1
    const db = env.TRACKER_KEUANGAN_DB;

    // === FUNGSI BANTUAN: Verifikasi Token JWT ===
    function verifikasiToken(token) {
      try {
        const [headerB64, payloadB64, sigB64] = token.split('.');
        if (!headerB64 || !payloadB64 || !sigB64) throw new Error('Format token salah');
        const payload = JSON.parse(atob(payloadB64));
        if (!payload.sub || !payload.exp || Date.now() >= payload.exp * 1000) throw new Error('Token kadaluarsa');
        return payload;
      } catch {
        throw new Error('Token tidak sah');
      }
    }

    // === FUNGSI BANTUAN: Hash & Verifikasi Kata Sandi ===
    async function hashKataSandi(sandi) {
      const encoder = new TextEncoder();
      const data = encoder.encode(sandi + env.JWT_SECRET);
      const hash = await crypto.subtle.digest('SHA-256', data);
      return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    async function verifikasiKataSandi(sandi, hashTersimpan) {
      return await hashKataSandi(sandi) === hashTersimpan;
    }

    // === FUNGSI BANTUAN: Buat Token JWT ===
    function buatToken(penggunaId, durasiJam = 24) {
      const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=+$/, '');
      const masaKadaluarsa = Math.floor(Date.now() / 1000) + (durasiJam * 3600);
      const payload = btoa(JSON.stringify({ sub: penggunaId, exp: masaKadaluarsa })).replace(/=+$/, '');
      const tandaTangan = btoa(env.JWT_SECRET).replace(/=+$/, '');
      return `${header}.${payload}.${tandaTangan}`;
    }

    // ============ RUTE YANG SUDAH ADA ============
    // Daftar Pengguna
    if (pathname === '/api/daftar' && method === 'POST') {
      try {
        const { nama, email, sandi } = await request.json();
        if (!nama || !email || !sandi) return Response.json({error: 'Lengkapi semua kolom'}, {status:400});
        
        const ada = await db.prepare('SELECT id FROM pengguna WHERE email = ?').bind(email).first();
        if (ada) return Response.json({error: 'Email sudah terdaftar'}, {status:409});

        const hash = await hashKataSandi(sandi);
        const { success } = await db.prepare(
          'INSERT INTO pengguna (nama, email, kata_sandi) VALUES (?, ?, ?)'
        ).bind(nama, email, hash).run();

        if (!success) return Response.json({error: 'Gagal mendaftar'}, {status:500});
        const penggunaBaru = await db.prepare('SELECT * FROM pengguna WHERE email = ?').bind(email).first();
        
        // Buat rekening bawaan
        const jenisRekening = ['Tunai', 'Bank', 'E-Wallet'];
        for (const namaRek of jenisRekening) {
          await db.prepare(
            'INSERT INTO rekening (pengguna_id, nama, saldo) VALUES (?, ?, 0)'
          ).bind(penggunaBaru.id, namaRek).run();
        }

        return Response.json({sukses:true, token: buatToken(penggunaBaru.id)});
      } catch (e) {
        return Response.json({error: e.message}, {status:500});
      }
    }

    // Masuk / Login
    if (pathname === '/api/masuk' && method === 'POST') {
      try {
        const { email, sandi } = await request.json();
        const user = await db.prepare('SELECT * FROM pengguna WHERE email = ?').bind(email).first();
        if (!user) return Response.json({error: 'Email atau kata sandi salah'}, {status:404});
        if (!(await verifikasiKataSandi(sandi, user.kata_sandi))) {
          return Response.json({error: 'Email atau kata sandi salah'}, {status:403});
        }
        return Response.json({sukses:true, token: buatToken(user.id), nama: user.nama});
      } catch (e) {
        return Response.json({error: e.message}, {status:500});
      }
    }

    // Ambil Data Ringkasan
    if (pathname === '/api/ringkasan' && method === 'GET') {
      try {
        const payload = verifikasiToken(headers.get('Authorization').replace('Bearer ', ''));
        const saldo = await db.prepare('SELECT SUM(saldo) AS total FROM rekening WHERE pengguna_id = ?').bind(payload.sub).first();
        const bulanIni = new Date().toISOString().slice(0,7);
        const pemasukan = await db.prepare(`SELECT SUM(jumlah) AS total FROM transaksi WHERE pengguna_id = ? AND jenis='masuk' AND tanggal LIKE ?`)
          .bind(payload.sub, `${bulanIni}%`).first();
        const pengeluaran = await db.prepare(`SELECT SUM(jumlah) AS total FROM transaksi WHERE pengguna_id = ? AND jenis='keluar' AND tanggal LIKE ?`)
          .bind(payload.sub, `${bulanIni}%`).first();
        return Response.json({
          saldo: saldo.total || 0,
          pemasukan: pemasukan.total || 0,
          pengeluaran: pengeluaran.total || 0
        });
      } catch { return Response.json({error: 'Akses ditolak'}, {status:401}); }
    }

    // CRUD Transaksi, Rekening, Kategori, Utang, Anggaran...
    if (pathname.startsWith('/api/transaksi') && method === 'GET') {
      try {
        const payload = verifikasiToken(headers.get('Authorization').replace('Bearer ', ''));
        const hasil = await db.prepare(`SELECT t.*, k.nama AS nama_kategori, r.nama AS nama_rekening 
          FROM transaksi t 
          LEFT JOIN kategori k ON t.kategori_id = k.id 
          LEFT JOIN rekening r ON t.rekening_id = r.id 
          WHERE t.pengguna_id = ? ORDER BY tanggal DESC`).bind(payload.sub).all();
        return Response.json(hasil.results);
      } catch { return Response.json({error: 'Akses ditolak'}, {status:401}); }
    }
    if (pathname === '/api/transaksi' && method === 'POST') {
      try {
        const payload = verifikasiToken(headers.get('Authorization').replace('Bearer ', ''));
        const { jenis, jumlah, tanggal, keterangan, kategori_id, rekening_id } = await request.json();
        await db.prepare(`INSERT INTO transaksi (pengguna_id, jenis, jumlah, tanggal, keterangan, kategori_id, rekening_id) 
          VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(payload.sub, jenis, jumlah, tanggal, keterangan, kategori_id||null, rekening_id).run();
        // Perbarui saldo rekening
        const tanda = jenis === 'masuk' ? '+' : '-';
        await db.prepare(`UPDATE rekening SET saldo = saldo ${tanda} ? WHERE id = ? AND pengguna_id = ?`)
          .bind(jumlah, rekening_id, payload.sub).run();
        return Response.json({sukses:true});
      } catch { return Response.json({error: 'Gagal simpan'}, {status:400}); }
    }
    if (pathname === '/api/rekening' && method === 'GET') {
      try {
        const payload = verifikasiToken(headers.get('Authorization').replace('Bearer ', ''));
        const hasil = await db.prepare('SELECT * FROM rekening WHERE pengguna_id = ?').bind(payload.sub).all();
        return Response.json(hasil.results);
      } catch { return Response.json({error: 'Akses ditolak'}, {status:401}); }
    }
    if (pathname === '/api/kategori' && method === 'GET') {
      try {
        const payload = verifikasiToken(headers.get('Authorization').replace('Bearer ', ''));
        const jenis = url.searchParams.get('jenis') || 'keluar';
        const hasil = await db.prepare('SELECT * FROM kategori WHERE pengguna_id = ? AND jenis = ?')
          .bind(payload.sub, jenis).all();
        return Response.json(hasil.results);
      } catch { return Response.json({error: 'Akses ditolak'}, {status:401}); }
    }
    if (pathname === '/api/utang' && method === 'GET') {
      try {
        const payload = verifikasiToken(headers.get('Authorization').replace('Bearer ', ''));
        const hasil = await db.prepare('SELECT * FROM utang WHERE pengguna_id = ? ORDER BY dibuat_pada DESC').bind(payload.sub).all();
        return Response.json(hasil.results);
      } catch { return Response.json({error: 'Akses ditolak'}, {status:401}); }
    }
    if (pathname === '/api/utang' && method === 'POST') {
      try {
        const payload = verifikasiToken(headers.get('Authorization').replace('Bearer ', ''));
        const { nama, jumlah, catatan, lunas } = await request.json();
        await db.prepare(`INSERT INTO utang (pengguna_id, nama, jumlah, catatan, lunas) VALUES (?, ?, ?, ?, ?)`)
          .bind(payload.sub, nama, jumlah, catatan||'', lunas?1:0).run();
        return Response.json({sukses:true});
      } catch { return Response.json({error: 'Gagal simpan utang'}, {status:400}); }
    }
    if (pathname.startsWith('/api/utang/') && method === 'PATCH') {
      try {
        const payload = verifikasiToken(headers.get('Authorization').replace('Bearer ', ''));
        const id = pathname.split('/').pop();
        const { lunas } = await request.json();
        await db.prepare('UPDATE utang SET lunas = ? WHERE id = ? AND pengguna_id = ?').bind(lunas, id, payload.sub).run();
        return Response.json({sukses:true});
      } catch { return Response.json({error: 'Gagal perbarui'}, {status:400}); }
    }
    if (pathname === '/api/anggaran' && method === 'GET') {
      try {
        const payload = verifikasiToken(headers.get('Authorization').replace('Bearer ', ''));
        const hasil = await db.prepare('SELECT * FROM anggaran WHERE pengguna_id = ?').bind(payload.sub).all();
        return Response.json(hasil.results);
      } catch { return Response.json({error: 'Akses ditolak'}, {status:401}); }
    }
    if (pathname === '/api/anggaran' && method === 'POST') {
      try {
        const payload = verifikasiToken(headers.get('Authorization').replace('Bearer ', ''));
        const { batas_bulanan } = await request.json();
        await db.prepare('REPLACE INTO anggaran (pengguna_id, batas_bulanan) VALUES (?, ?)')
          .bind(payload.sub, batas_bulanan).run();
        return Response.json({sukses:true});
      } catch { return Response.json({error: 'Gagal simpan anggaran'}, {status:400}); }
    }

    // ============ ✅ RUTE BARU: RISET DATA ============
    if (pathname === '/api/verifikasi-riset' && method === 'POST') {
      try {
        const authHeader = headers.get('Authorization');
        if (!authHeader) throw new Error('Token hilang');
        const token = authHeader.replace('Bearer ', '');
        const payload = verifikasiToken(token);

        const { sandi } = await request.json();
        if (!sandi) return Response.json({error:'Isi kata sandi'}, {status:400});

        const user = await db
          .prepare('SELECT kata_sandi FROM pengguna WHERE id = ?')
          .bind(payload.sub)
          .first();

        if (!user) return Response.json({error:'Pengguna tidak ditemukan'}, {status:404});

        const cocok = await verifikasiKataSandi(sandi, user.kata_sandi);
        if (!cocok) return Response.json({error:'Kata sandi salah'}, {status:403});

        const transaksi = await db.prepare(`
          SELECT * FROM transaksi 
          WHERE pengguna_id = ? 
          ORDER BY tanggal DESC
        `).bind(payload.sub).all();

        return Response.json({ data: transaksi.results }, {status:200});
      } catch {
        return Response.json({error: 'Akses ditolak'}, {status:401});
      }
    }

    // Sajikan halaman utama
    if (pathname === '/' || pathname === '/index.html') {
      return env.ASSETS.fetch(request);
    }

    return new Response(JSON.stringify({halaman: 'tidak ditemukan'}), {status:404});
  }
          }
