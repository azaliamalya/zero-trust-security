const bcrypt = require('bcryptjs');
const { db, signToken, hashToken } = require('./common');

function issueAccessToken(user) {
  return signToken({ sub: String(user.id), role: user.role }, `${Number(process.env.ACCESS_TOKEN_MINUTES || 10)}m`);
}
function createRefreshToken(userId) {
  const token = require('crypto').randomBytes(48).toString('hex');
  const expires = new Date(Date.now() + Number(process.env.REFRESH_TOKEN_DAYS || 1) * 86400000).toISOString();
  db.prepare('INSERT INTO refresh_tokens(user_id,token_hash,expires_at) VALUES (?,?,?)')
    .run(userId, hashToken(token), expires);
  return token;
}
function login(username, password, deviceId) {
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) return { error: 'Kredensial tidak valid' };
  const device = db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?').get(user.id, deviceId);
  if (!device) return { error: 'Device tidak terdaftar untuk pengguna ini' };
  return {
    user: { id: user.id, username: user.username, role: user.role, nim: user.nim, full_name: user.full_name },
    accessToken: issueAccessToken(user),
    refreshToken: createRefreshToken(user.id)
  };
}
function refresh(refreshToken) {
  if (!refreshToken) return { error: 'Refresh token wajib diisi' };
  const row = db.prepare(`SELECT rt.*,u.id,u.username,u.role,u.nim,u.full_name FROM refresh_tokens rt
                          JOIN users u ON u.id=rt.user_id WHERE rt.token_hash=?`)
    .get(hashToken(refreshToken));
  if (!row || row.revoked_at || new Date(row.expires_at) <= new Date()) return { error: 'Refresh token tidak valid, kedaluwarsa, atau dicabut' };
  return { accessToken: issueAccessToken(row), user: { id: row.id, username: row.username, role: row.role, nim: row.nim } };
}
function logout(refreshToken) {
  if (!refreshToken) return false;
  const result = db.prepare(`UPDATE refresh_tokens SET revoked_at=CURRENT_TIMESTAMP
                             WHERE token_hash=? AND revoked_at IS NULL`).run(hashToken(refreshToken));
  return result.changes > 0;
}
module.exports = { login, refresh, logout, issueAccessToken };
