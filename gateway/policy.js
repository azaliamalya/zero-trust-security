const { db } = require('./common');

function deviceIsRegistered(userId, deviceId) {
  return !!db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?').get(userId, deviceId);
}
function canReadGrades(user) {
  return ['mahasiswa', 'dosen'].includes(user.role);
}
function canReadTranscript(user, nim) {
  if (user.role === 'admin') return true;
  if (user.role !== 'mahasiswa') return false;
  const own = db.prepare('SELECT nim FROM users WHERE id=?').get(user.id);
  return !!own && own.nim === nim;
}
function canEditGrade(user, gradeId) {
  if (user.role !== 'dosen') return { allow: false, reason: 'Hanya dosen yang boleh mengubah nilai' };
  const row = db.prepare(`SELECT c.lecturer_id,c.is_final FROM grades g
                          JOIN classes c ON c.id=g.class_id WHERE g.id=?`).get(gradeId);
  if (!row) return { allow: false, reason: 'Nilai tidak ditemukan' };
  if (row.lecturer_id !== user.id) return { allow: false, reason: 'Kelas bukan kelas yang diampu dosen' };
  if (row.is_final) return { allow: false, reason: 'Nilai sudah final' };
  return { allow: true, reason: 'Dosen pengampu dan nilai belum final' };
}
function canFinalizeClass(user, classId) {
  if (user.role !== 'dosen') return { allow: false, reason: 'Hanya dosen yang boleh finalisasi' };
  const row = db.prepare('SELECT lecturer_id,is_final FROM classes WHERE id=?').get(classId);
  if (!row) return { allow: false, reason: 'Kelas tidak ditemukan' };
  if (row.lecturer_id !== user.id) return { allow: false, reason: 'Kelas bukan kelas yang diampu dosen' };
  if (row.is_final) return { allow: false, reason: 'Kelas sudah final' };
  return { allow: true, reason: 'Dosen pengampu dan kelas belum final' };
}
function withinAccessHours() {
  const start = Number(process.env.ACCESS_START_HOUR ?? 7);
  const end = Number(process.env.ACCESS_END_HOUR ?? 21);
  const hour = new Date().getHours();
  return hour >= start && hour < end;
}
module.exports = { deviceIsRegistered, canReadGrades, canReadTranscript, canEditGrade, canFinalizeClass, withinAccessHours };
