const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../database/db');

function secret(name, fallback) {
  return process.env[name] || fallback;
}
function signToken(payload, expiresIn) {
  return jwt.sign(payload, secret('JWT_SECRET', 'local-demo-change-this-jwt-secret'), { expiresIn });
}
function verifyToken(token) {
  return jwt.verify(token, secret('JWT_SECRET', 'local-demo-change-this-jwt-secret'));
}
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function audit(subject, endpoint, deviceId, decision, reason) {
  db.prepare(`INSERT INTO audit_logs(subject,endpoint,device_id,decision,reason)
              VALUES (?,?,?,?,?)`).run(subject || 'anonymous', endpoint, deviceId || null, decision, reason);
}
module.exports = { db, signToken, verifyToken, safeEqual, hashToken, audit };
