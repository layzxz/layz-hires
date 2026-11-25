# 🎵 Layz Hi-Res

Custom audio streaming addon untuk **BitChord** yang mendukung pemutaran **Hi-Res Lossless (24-bit FLAC)**, **Lossless (16-bit FLAC)**, **Dolby Atmos**, serta **High/Low AAC** dengan pembaruan token otomatis dan antarmuka status bergaya *Liquid Glass*.

---

## ✨ Fitur Utama

- **Multi-Quality Audio Tiers** — Mendukung pilihan kualitas langsung dari UI BitChord:
  - `Hi-Res Lossless (24-bit)` — FLAC hingga 24-bit / 192 kHz (DASH)
  - `Lossless (16-bit)` — FLAC 16-bit / 44.1 kHz
  - `Dolby Atmos` — E-AC-3 JOC / AC-4 dengan pencarian otomatis versi Atmos
  - `High · 320 kbps` & `Low · 128 kbps` — AAC
- **Auto-Refresh Token** — Memperbarui access token secara otomatis menggunakan `TIDAL_REFRESH_TOKEN` tanpa perlu restart server.
- **ISRC & Track Search** — Pencarian lagu akurat berbasis judul/artis maupun kode ISRC.
- **Liquid Glass Dashboard** — Halaman depan (`/`) dengan indikator *Server Online*, pengukuran *latency* real-time (`/ping`), *uptime*, dan penghitung pengguna aktif.
- **BitChord Auth Ready** — Mendukung verifikasi JWT/JWKS BitChord (`off`, `log`, atau `enforce`).

---

## 🚀 Cara Pasang di BitChord

1. Buka aplikasi **BitChord** → masuk ke menu **Sources / Addons**.
2. Tambahkan URL manifest berikut:
   ```text
   [https://layyyz.web.id/manifest.json](https://layyyz.web.id/manifest.json)
   ```
3. Aktifkan **Layz Hi-Res** dan pilih kualitas audio yang diinginkan lewat menu dropdown kualitas.

---

## 🛠️ Self-Hosting

### 1. Clone & Install
```bash
git clone [https://github.com/layzxz/lz-addon.git](https://github.com/layzxz/lz-addon.git)
cd lz-addon
npm install
```

### 2. Environment Variables
Buat file `.env` (untuk lokal) atau atur di dashboard **Environment** (jika deploy di Render):

| Variable | Wajib | Default | Keterangan |
| :--- | :---: | :--- | :--- |
| `TIDAL_REFRESH_TOKEN` | ✅ | - | Refresh token OAuth2 untuk auto-refresh |
| `TIDAL_CLIENT_ID` | ❌ | `6BDSRdpK9hqEBTgU` | Client ID OAuth2 |
| `TIDAL_COUNTRY_CODE` | ❌ | `SG` | Kode negara katalog (misal `SG`, `ID`, `US`) |
| `PUBLIC_URL` | ✅ | `http://localhost:8080` | Domain publik server (untuk URL manifest DASH) |
| `ALLOW_DASH_HIRES` | ❌ | `true` | Aktifkan streaming Hi-Res 24-bit via DASH |
| `AUTH_MODE` | ❌ | `off` | Mode verifikasi BitChord (`off` / `log` / `enforce`) |
| `BITCHORD_AUTH_ISSUER` | ❌ | `https://bitchord-auth.kushagrasingh.in` | Issuer JWKS untuk autentikasi BitChord |
| `PORT` | ❌ | `8080` | Port server Express |

### 3. Jalankan Server
```bash
node server.js
```

---

## 📡 API Endpoints

| Endpoint | Deskripsi |
| :--- | :--- |
| `GET /` | Halaman dashboard status *Liquid Glass* |
| `GET /manifest.json` | Manifest addon dan konfigurasi dropdown kualitas untuk BitChord |
| `GET /ping` | Cek status server, *uptime*, dan jumlah pengguna aktif |
| `GET /search?q=...` | Pencarian track berdasarkan kata kunci |
| `GET /isrc/:code` | Pencarian track berdasarkan kode ISRC |
| `GET /stream/:id?quality=...` | Mengambil URL stream audio (`hires`, `lossless`, `atmos`, `high`, `low`) |
