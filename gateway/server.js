
require('dotenv').config();

const express = require('express');
const {
  createProxyMiddleware,
  fixRequestBody
} = require('http-proxy-middleware');
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

// ==================================================
// HEALTH CHECK
// ==================================================
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'gateway' });
});

// ==================================================
// LOGIN PENGGUNA
// ==================================================
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

// ==================================================
// REFRESH ACCESS TOKEN
// ==================================================
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

// ==================================================
// LOGOUT DAN PENCABUTAN REFRESH TOKEN
// ==================================================
app.post('/auth/logout', (req, res) => {
  const ok = logout(req.body?.refreshToken);

  audit(
    'anonymous',
    '/auth/logout',
    null,
    ok ? 'allow' : 'deny',
    ok ? 'Refresh token dicabut' : 'Refresh token tidak valid'
  );

  return res.status(ok ? 200 : 401).json(
    ok
      ? { message: 'Logout berhasil; refresh token dicabut' }
      : { error: 'Refresh token tidak valid' }
  );
});

// ==================================================
// PENERBITAN TOKEN SERVICE
// ==================================================
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
    expiresInMinutes: Number(
      process.env.SERVICE_TOKEN_MINUTES || 5
    )
  });
});

// ==================================================
// AUTENTIKASI TOKEN DAN PERANGKAT
// ==================================================
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

    // Autentikasi service-to-service
    if (payload.role === 'service') {
      if (payload.sub !== 'service-nilai') {
        throw new Error('Token service tidak dikenal');
      }

      req.auth = {
        id: null,
        username: null,
        role: 'service',
        nim: null,
        sub: payload.sub,
        token
      };

      return next();
    }

    // Autentikasi pengguna biasa
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

    return next();
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

// ==================================================
// PEMERIKSAAN KEBIJAKAN AKSES
// ==================================================
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

  return next();
}

// ==================================================
// PROXY KE SERVICE INTERNAL
// ==================================================
function proxy(target, prefix) {
  return createProxyMiddleware({
    target,
    changeOrigin: true,

    pathRewrite: (path) => `${prefix}${path}`,

    on: {
      proxyReq(proxyReq, req) {
        // Secret internal Gateway
        proxyReq.setHeader(
          'X-Gateway-Secret',
          GATEWAY_SECRET
        );

        // Teruskan Authorization Bearer
        if (req.headers.authorization) {
          proxyReq.setHeader(
            'Authorization',
            req.headers.authorization
          );
        }

        // Teruskan konteks autentikasi
        const authContext = {
          id: req.auth.id,
          username: req.auth.username,
          role: req.auth.role,
          nim: req.auth.nim,
          sub: req.auth.sub
        };

        proxyReq.setHeader(
          'X-Auth-Context',
          Buffer.from(JSON.stringify(authContext)).toString('base64')
        );

        // Perbaiki body yang sudah dibaca express.json()
        fixRequestBody(proxyReq, req);
      },

      error(err, _req, res) {
        console.error('Proxy error:', err.message);

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

// ==================================================
// ROUTING KE SERVICE NILAI DAN TRANSKRIP
// ==================================================
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

// ==================================================
// AUDIT LOG KHUSUS ADMIN
// ==================================================
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

// ==================================================
// MENJALANKAN API GATEWAY
// ==================================================
app.listen(PORT, () => {
  console.log(`API Gateway berjalan di http://localhost:${PORT}`);
});
