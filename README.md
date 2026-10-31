# Zero Trust Security — Sistem Nilai

Contoh implementasi praktikum menggunakan Node.js, Express, JWT, dan SQLite. Semua komponen berjalan di satu komputer.

## Persyaratan
- Node.js 18 atau lebih baru (disarankan versi LTS)
- Postman atau curl

## Instalasi
```bash
npm install
```

Salin `.env.example` menjadi `.env`, lalu ganti `JWT_SECRET`, `GATEWAY_SECRET`, dan `SERVICE_CLIENT_SECRET` dengan secret acak yang kuat. Pastikan file `.env` tidak diunggah ke repository.

Buat database dan data awal:
```bash
npm run init-db
```

Jalankan tiga terminal terpisah dari folder proyek:
```bash
npm run gateway
npm run nilai
npm run transkrip
```

- Gateway: http://localhost:3000
- Service Nilai: http://localhost:3001 (akses langsung ditolak tanpa gateway secret)
- Service Transkrip: http://localhost:3002 (akses langsung ditolak tanpa gateway secret)

## Akun demo
Password seluruh akun demo: `Demo123!`
- Admin: `admin`
- Dosen 1: `dosen1`
- Dosen 2: `dosen2`
- Mahasiswa 1: `mhs1`
- Mahasiswa 2: `mhs2`
- Mahasiswa 3: `mhs3`

Device ID seed:
- `admin` → `DEV-ADMIN-01`
- `dosen1` → `DEV-DOSEN-01`
- `dosen2` → `DEV-DOSEN-02`
- `mhs1` → `DEV-MHS-01`
- `mhs2` → `DEV-MHS-02`
- `mhs3` → `DEV-MHS-03`

**Data akun di atas hanya untuk demo lokal.** Ganti password dan secret sebelum dipakai di lingkungan nyata.

## Alur pengujian
Semua endpoint pengguna diakses melalui Gateway. Untuk endpoint yang membutuhkan autentikasi, login dahulu dan gunakan `accessToken` sebagai `Authorization: Bearer <token>`, serta kirim `X-Device-ID` sesuai device akun.

### 1. Login
`POST http://localhost:3000/auth/login`
```json
{
  "username": "mhs1",
  "password": "Demo123!",
  "deviceId": "DEV-MHS-01"
}
```

### 2. Refresh dan logout
- `POST /auth/refresh` body: `{"refreshToken":"..."}`
- `POST /auth/logout` body: `{"refreshToken":"..."}`

### 3. Minta token service
`POST http://localhost:3000/auth/service`
```json
{
  "clientId": "service-nilai",
  "clientSecret": "nilai-service-demo-secret"
}
```
Gunakan token hasilnya sebagai Bearer token untuk `POST /transkrip/sinkron`. Endpoint ini hanya menerima token ber-role `service`.

### 4. Endpoint nilai
- `GET http://localhost:3000/nilai` — mahasiswa melihat nilai milik sendiri; dosen melihat nilai di kelas yang diampu.
- `PUT http://localhost:3000/nilai/1` — dosen dapat mengubah nilai sebelum final, hanya pada kelas yang diampu dan selama jam akses.
  Header: `Authorization: Bearer <token>`, `X-Device-ID: DEV-DOSEN-01`
  Body contoh: `{"nilai":90}`.
- `POST http://localhost:3000/kelas/1/finalisasi` — dosen pemilik kelas dapat finalisasi pada jam akses.

### 5. Endpoint transkrip
- `GET http://localhost:3000/transkrip/2024001` — mahasiswa hanya NIM sendiri; admin boleh semua NIM.
- `POST http://localhost:3000/transkrip/sinkron` — hanya token service. Body contoh: `{"kelasId":1}`.

### 6. Uji penolakan
- Login `mhs1`, lalu coba GET transkrip NIM `2024002` → harus ditolak.
- Gunakan device ID yang tidak terdaftar → harus ditolak.
- Panggil `http://localhost:3001/nilai` langsung tanpa `X-Gateway-Secret` → harus ditolak.
- Coba PUT/finalisasi oleh mahasiswa → harus ditolak.
- Coba sinkronisasi transkrip menggunakan token user → harus ditolak.

## Catatan implementasi
- Gateway menjadi titik pemeriksaan kebijakan dan audit log.
- Kedua service memeriksa `X-Gateway-Secret` dan memverifikasi JWT yang diteruskan.
- Policy memeriksa kepemilikan kelas/NIM dari database.
- Jam akses diatur di `.env` (default 07.00–21.00).
- Audit log disimpan pada tabel `audit_logs`.
- Ini adalah proyek praktikum/demo, bukan konfigurasi produksi yang sudah diaudit.

## Endpoint kesehatan
`GET http://localhost:3000/health`
