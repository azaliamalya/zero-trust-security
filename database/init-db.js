const bcrypt = require('bcryptjs');
const db = require('./db');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','dosen','mahasiswa')),
  nim TEXT UNIQUE,
  full_name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  UNIQUE(user_id, device_id)
);
CREATE TABLE IF NOT EXISTS classes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  class_name TEXT NOT NULL,
  course_name TEXT NOT NULL,
  lecturer_id INTEGER NOT NULL REFERENCES users(id),
  is_final INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS grades (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  class_id INTEGER NOT NULL REFERENCES classes(id),
  student_id INTEGER NOT NULL REFERENCES users(id),
  grade REAL NOT NULL CHECK(grade >= 0 AND grade <= 100),
  UNIQUE(class_id, student_id)
);
CREATE TABLE IF NOT EXISTS transcripts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL REFERENCES users(id),
  class_id INTEGER NOT NULL REFERENCES classes(id),
  grade REAL NOT NULL,
  synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(student_id, class_id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  subject TEXT,
  endpoint TEXT NOT NULL,
  device_id TEXT,
  decision TEXT NOT NULL,
  reason TEXT NOT NULL
);
`);

const insertUser = db.prepare('INSERT OR IGNORE INTO users (username,password_hash,role,nim,full_name) VALUES (?,?,?,?,?)');
const passwordHash = bcrypt.hashSync('Demo123!', 10);
const users = [
  ['admin', passwordHash, 'admin', null, 'Administrator Demo'],
  ['dosen1', passwordHash, 'dosen', null, 'Dosen Informatika 1'],
  ['dosen2', passwordHash, 'dosen', null, 'Dosen Informatika 2'],
  ['mhs1', passwordHash, 'mahasiswa', '2024001', 'Mahasiswa 1'],
  ['mhs2', passwordHash, 'mahasiswa', '2024002', 'Mahasiswa 2'],
  ['mhs3', passwordHash, 'mahasiswa', '2024003', 'Mahasiswa 3']
];
const tx = db.transaction(() => {
  users.forEach(u => insertUser.run(...u));
  const userId = username => db.prepare('SELECT id FROM users WHERE username=?').get(username).id;
  const insertDevice = db.prepare('INSERT OR IGNORE INTO devices (user_id,device_id) VALUES (?,?)');
  [
    ['admin','DEV-ADMIN-01'], ['dosen1','DEV-DOSEN-01'], ['dosen2','DEV-DOSEN-02'],
    ['mhs1','DEV-MHS-01'], ['mhs2','DEV-MHS-02'], ['mhs3','DEV-MHS-03']
  ].forEach(([u,d]) => insertDevice.run(userId(u), d));
  const insertClass = db.prepare('INSERT INTO classes (id,class_name,course_name,lecturer_id,is_final) VALUES (?,?,?,?,0) ON CONFLICT(id) DO NOTHING');
  insertClass.run(1,'IF-A','Keamanan Informasi',userId('dosen1'));
  insertClass.run(2,'IF-B','Komputasi Awan',userId('dosen2'));
  const insertGrade = db.prepare('INSERT OR IGNORE INTO grades (class_id,student_id,grade) VALUES (?,?,?)');
  [[1,'mhs1',85],[1,'mhs2',88],[1,'mhs3',90],[2,'mhs1',80],[2,'mhs2',82],[2,'mhs3',87]]
    .forEach(([c,u,g]) => insertGrade.run(c,userId(u),g));
});
tx();
console.log('Database siap. Akun demo menggunakan password: Demo123!');
db.close();
