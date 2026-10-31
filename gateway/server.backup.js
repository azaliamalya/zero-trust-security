
require('dotenv').config();

const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const jwt = require('jsonwebtoken');
const { db, verifyToken, safeEqual, audit } = require('./common');
const { login, refresh, logout } = require('./auth');
const policy = require('./policy');

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT_GATEWAY || 3000);
const JWT_SECRET =
  process.env.JWT_SECRET || 'local-demo-change-this-jwt-secret';
const GATEWAY_SECRET =
  process.env.GATEWAY_SECRET || 'local-demo-change-this-gateway-secret';

// Health check
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'gateway' });
});

// Login pengguna
app.post('/auth/login', (req, res) => {
  const { username, password, deviceId } = req.body || {};
  const result = login(username, password, deviceId);

  if (result.error) {
    audit(
      username || 'anonymous',
      '/auth/login',
      deviceId,
      'deny',
      result.error
    );
    return res.status(401).json({ error: result.error });
  }

  audit(
    username,
    '/auth/login',
    deviceId,
    'allow',
    'Kredensial valid dan device terdaftar'
  );

  res.json(result);
});

// Refresh access token
app.post('/auth/refresh', (req, res) => {
  const result = refresh(req.body?.refreshToken);

  if (result.error) {
    audit(
      'anonymous',
      '/auth/refresh',
      null,
      'deny',
      result.error
    );
    return res.status(401).json({ error: result.error });
  }

  audit(
    String(result.user.id),
    '/auth/refresh',
    null,
    'allow',
    'Refresh token valid'
  );

  res.json(result);
});

// Logout dan pencabutan refresh token
app.post('/auth/logout', (req, res) => {
  const ok = logout(req.body?.refreshToken);

  audit(
    'anonymous',
    '/auth/logout',
    null,
    ok ? 'allow' : 'deny',
    ok ? 'Refresh token dicabut' : 'Refresh token tidak valid'
  );

  res.status(ok ? 200 : 401).json(
    ok
      ? { message: 'Logout berhasil; refresh token dicabut' }
      : { error: 'Refresh token tidak valid' }
  );
});

// Penerbitan token service
app.post('/auth/service', (req, res) => {
  const valid =
    req.body?.clientId ===
      (process.env.SERVICE_CLIENT_ID || 'service-nilai') &&
    safeEqual(
      req.body?.clientSecret || '',
      process.env.SERVICE_CLIENT_SECRET || 'nilai-service-demo-secret'
    );

  if (!valid) {
    audit(
      req.body?.clientId || 'unknown',
      '/auth/service',
      null,
      'deny',
      'Client ID/secret tidak valid'
    );

    return res.status(401).json({
      error: 'Client ID atau secret tidak valid'
    });
  }

  const token = jwt.sign(
    { sub: 'service-nilai', role: 'service' },
    JWT_SECRET,
    {
      expiresIn: `${Number(
        process.env.SERVICE_TOKEN_MINUTES || 5
      )}m`
    }
  );

  audit(
    'service-nilai',
    '/auth/service',
    null,
    'allow',
    'Kredensial service valid'
  );

  res.json({
    accessToken: token,
    tokenType: 'Bearer',
    expiresInMinutes: Number(process.env.SERVICE_TOKEN_MINUTES || 5)
  });
});

// Autentikasi token dan perangkat
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : '';

  if (!token) {
    audit(
      'anonymous',
      req.originalUrl,
      req.headers['x-device-id'],
      'deny',
      'Bearer token tidak ada'
    );

    return res.status(401).json({
      error: 'Bearer token wajib diisi'
    });
  }

  try {
    const payload = verifyToken(token);

    if (payload.role === 'service') {
      if (payload.sub !== 'service-nilai') {
        throw new Error('Token service tidak dikenal');
      }

      req.auth = {
        id: null,
        username: null,
        role: 'service',
        sub: payload.sub,
        token
      };

      return next();
    }

    const user = db.prepare(
      'SELECT id, username, role, nim, full_name FROM users WHERE id = ?'
    ).get(Number(payload.sub));

    if (!user || user.role !== payload.role) {
      throw new Error('Pengguna/token tidak valid');
    }

    const deviceId = req.headers['x-device-id'];

    if (!deviceId || !policy.deviceIsRegistered(user.id, deviceId)) {
      audit(
        user.username,
        req.originalUrl,
        deviceId,
        'deny',
        'Device tidak terdaftar'
      );

      return res.status(403).json({
        error: 'Device tidak terdaftar untuk pengguna ini'
      });
    }

    req.auth = {
      ...user,
      sub: String(user.id),
      token
    };

    next();
  } catch (_error) {
    audit(
      'unknown',
      req.originalUrl,
      req.headers['x-device-id'],
      'deny',
      'Token tidak valid atau kedaluwarsa'
    );

    return res.status(401).json({
      error: 'Token tidak valid atau kedaluwarsa'
    });
  }
}

// Pemeriksaan kebijakan akses
function routePolicy(req, res, next) {
  const u = req.auth;
  const path = req.originalUrl.split('?')[0];
  const method = req.method;

  let result = {
    allow: true,
    reason: 'Request diteruskan ke policy endpoint/service'
  };

  if (path === '/nilai' && method === 'GET') {
    result = policy.canReadGrades(u)
      ? { allow: true, reason: 'Role boleh membaca nilai' }
      : { allow: false, reason: 'Role tidak boleh membaca nilai' };

  } else if (path.startsWith('/nilai/') && method === 'PUT') {
    result = policy.canEditGrade(
      u,
      Number(path.split('/')[2])
    );

    if (result.allow && !policy.withinAccessHours()) {
      result = {
        allow: false,
        reason: 'Di luar jam akses yang diizinkan'
      };
    }

  } else if (
    path.startsWith('/kelas/') &&
    path.endsWith('/finalisasi') &&
    method === 'POST'
  ) {
    result = policy.canFinalizeClass(
      u,
      Number(path.split('/')[2])
    );

    if (result.allow && !policy.withinAccessHours()) {
      result = {
        allow: false,
        reason: 'Di luar jam akses yang diizinkan'
      };
    }

  } else if (
    path.startsWith('/transkrip/') &&
    method === 'GET'
  ) {
    const nim = path.split('/')[2];

    result = policy.canReadTranscript(u, nim)
      ? { allow: true, reason: 'Kepemilikan transkrip valid' }
      : {
          allow: false,
          reason: 'Role atau kepemilikan transkrip tidak sesuai'
        };

  } else if (
    path === '/transkrip/sinkron' &&
    method === 'POST'
  ) {
    result = u.role === 'service'
      ? { allow: true, reason: 'Token service valid' }
      : {
          allow: false,
          reason: 'Sinkronisasi hanya untuk token service'
        };
  }

  audit(
    u.username || u.sub,
    req.originalUrl,
    req.headers['x-device-id'],
    result.allow ? 'allow' : 'deny',
    result.reason
  );

  if (!result.allow) {
    return res.status(403).json({
      error: 'Akses ditolak',
      reason: result.reason
    });
  }

  next();
}

// Proxy ke service internal
function proxy(target, prefix) {
  return createProxyMiddleware({
    target,
    changeOrigin: true,

    pathRewrite: (path) => `${prefix}${path}`,

    on: {
      proxyReq(proxyReq, req) {
        proxyReq.setHeader('X-Gateway-Secret', GATEWAY_SECRET);

        if (req.headers.authorization) {
          proxyReq.setHeader(
            'Authorization',
            req.headers.authorization
          );
        }

        proxyReq.setHeader(
          'X-Auth-Context',
          Buffer.from(
            JSON.stringify({
              id: req.auth.id,
              username: req.auth.username,
              role: req.auth.role,
              nim: req.auth.nim,
              sub: req.auth.sub
            })
          ).toString('base64')
        );

        // Teruskan kembali body JSON yang sudah dibaca Express
        if (
          req.body &&
          Object.keys(req.body).length > 0 &&
          !['GET', 'HEAD'].includes(req.method)
        ) {
          const bodyData = JSON.stringify(req.body);

          proxyReq.setHeader('Content-Type', 'application/json');
          proxyReq.setHeader(
            'Content-Length',
            Buffer.byteLength(bodyData)
          );

          proxyReq.write(bodyData);
        }
      },

      error(err, _req, res) {
        if (!res.headersSent) {
          res.status(502).json({
            error: 'Service tidak tersedia',
            detail: err.message
          });
        }
      }
    }
  });
}

// Routing ke Service Nilai dan Service Transkrip
app.use(
  '/nilai',
  authenticate,
  routePolicy,
  proxy(
    `http://127.0.0.1:${process.env.PORT_NILAI || 3001}`,
    '/nilai'
  )
);

app.use(
  '/kelas',
  authenticate,
  routePolicy,
  proxy(
    `http://127.0.0.1:${process.env.PORT_NILAI || 3001}`,
    '/kelas'
  )
);

app.use(
  '/transkrip',
  authenticate,
  routePolicy,
  proxy(
    `http://127.0.0.1:${process.env.PORT_TRANSKRIP || 3002}`,
    '/transkrip'
  )
);

// Audit log khusus admin dengan device terdaftar
app.get('/audit', (req, res) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : '';

  try {
    if (!token) {
      return res.status(401).json({
        error: 'Bearer token wajib diisi'
      });
    }

    const payload = verifyToken(token);

    const user = db.prepare(
      'SELECT * FROM users WHERE id = ?'
    ).get(Number(payload.sub));

    const device = req.headers['x-device-id'];

    if (
      !user ||
      user.role !== 'admin' ||
      !policy.deviceIsRegistered(user.id, device)
    ) {
      return res.status(403).json({
        error: 'Khusus admin dengan device terdaftar'
      });
    }

    return res.json(
      db.prepare(
        'SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100'
      ).all()
    );
  } catch (_error) {
    return res.status(401).json({
      error: 'Token tidak valid'
    });
  }
});

app.listen(PORT, () => {
  console.log(`API Gateway berjalan di http://localhost:${PORT}`);
});
