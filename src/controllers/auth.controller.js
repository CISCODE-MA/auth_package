const passport = require('../config/passport.config');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const jwksClient = require('jwks-rsa');
const axios = require('axios'); // ← for Google code/idToken exchange
const User = require('../models/user.model');
const Client = require('../models/client.model');
const Role = require('../models/role.model');
const getMillisecondsFromExpiry = require('../utils/helper').getMillisecondsFromExpiry;

/* ──────────────────────────────────────────────────────────────────────────────
 * Microsoft ID token verification (for MSAL mobile token exchange)
 * ─────────────────────────────────────────────────────────────────────────── */
const TENANT_ID = process.env.MICROSOFT_TENANT_ID || 'common';
const MSAL_MOBILE_CLIENT_ID = process.env.MSAL_MOBILE_CLIENT_ID; // MUST equal msal_config.json client_id

const msJwks = jwksClient({
  jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
});

function verifyMicrosoftIdToken(idToken) {
  return new Promise((resolve, reject) => {
    const getKey = (header, cb) => {
      msJwks
        .getSigningKey(header.kid)
        .then((k) => cb(null, k.getPublicKey()))
        .catch(cb);
    };

    jwt.verify(
      idToken,
      getKey,
      { algorithms: ['RS256'], audience: MSAL_MOBILE_CLIENT_ID },
      (err, payload) => (err ? reject(err) : resolve(payload))
    );
  });
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Helpers
 * ─────────────────────────────────────────────────────────────────────────── */

// Issue tokens + cookie + JSON (for pure web flows)
async function issueTokensAndRespond(principal, res) {
  const roleDocs = await Role.find({ _id: { $in: principal.roles } })
    .select('name permissions -_id')
    .lean();

  const roles = roleDocs.map((r) => r.name);
  const permissions = Array.from(new Set(roleDocs.flatMap((r) => r.permissions)));

  const accessTTL = process.env.JWT_ACCESS_TOKEN_EXPIRES_IN || '15m';
  const refreshTTL = process.env.JWT_REFRESH_TOKEN_EXPIRES_IN || '7d';

  const payload = {
    id: principal._id,
    email: principal.email,
    tenantId: principal.tenantId, // may be undefined for Clients; that's fine
    roles,
    permissions,
  };

  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: accessTTL });
  const refreshToken = jwt.sign({ id: principal._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: refreshTTL });

  // persist refresh token
  principal.refreshToken = refreshToken;
  try {
    await principal.save();
  } catch (e) {
    console.error('❌ Error saving refreshToken:', e);
  }

  const isProd = process.env.NODE_ENV === 'production';
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
    maxAge: getMillisecondsFromExpiry(refreshTTL),
  });

  return res.status(200).json({ accessToken, refreshToken });
}

// Decide mobile deep link vs web JSON/cookie (for OAuth callbacks)
async function respondWebOrMobile(req, res, principal) {
  const roleDocs = await Role.find({ _id: { $in: principal.roles } })
    .select('name permissions -_id')
    .lean();

  const roles = roleDocs.map((r) => r.name);
  const permissions = Array.from(new Set(roleDocs.flatMap((r) => r.permissions)));

  const accessTTL = process.env.JWT_ACCESS_TOKEN_EXPIRES_IN || '15m';
  const refreshTTL = process.env.JWT_REFRESH_TOKEN_EXPIRES_IN || '7d';

  const payload = {
    id: principal._id,
    email: principal.email,
    tenantId: principal.tenantId,
    roles,
    permissions,
  };

  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: accessTTL });
  const refreshToken = jwt.sign({ id: principal._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: refreshTTL });

  // always persist the refresh token in DB
  principal.refreshToken = refreshToken;
  try { await principal.save(); } catch (e) { console.error('❌ Saving refreshToken failed:', e); }

  // try to decode deep link from state
  let mobileRedirect;
  if (req.query.state) {
    try {
      const decoded = JSON.parse(Buffer.from(req.query.state, 'base64url').toString('utf8'));
      mobileRedirect = decoded.redirect; // e.g. restosoft://auth/google/callback
    } catch (_) {}
  }

  if (mobileRedirect) {
    // MOBILE: redirect back to app with tokens as query params
    const url = new URL(mobileRedirect);
    url.searchParams.set('accessToken', accessToken);
    url.searchParams.set('refreshToken', refreshToken);
    return res.redirect(302, url.toString());
  }

  // WEB: set cookie + return JSON
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
    maxAge: getMillisecondsFromExpiry(refreshTTL),
  });

  return res.status(200).json({ accessToken, refreshToken });
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Client Registration
 * ─────────────────────────────────────────────────────────────────────────── */
const registerClient = async (req, res) => {
  try {
    const { email, password, name, roles = [] } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    if (await Client.findOne({ email })) {
      return res.status(409).json({ message: 'Email already in use.' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);
    const client = new Client({ email, password: hashed, name, roles });
    await client.save();
    return res.status(201).json({
      id: client._id,
      email: client.email,
      name: client.name,
      roles: client.roles,
    });
  } catch (err) {
    console.error('❌ registerClient error:', err);
    return res.status(500).json({ message: 'Server error.' });
  }
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Client Login (local)
 * ─────────────────────────────────────────────────────────────────────────── */
const clientLogin = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    const client = await Client.findOne({ email })
      .select('+password')
      .populate('roles', 'name permissions');
    if (!client) {
      return res.status(400).json({ message: 'Incorrect email.' });
    }
    const match = await bcrypt.compare(password, client.password);
    if (!match) {
      return res.status(400).json({ message: 'Incorrect password.' });
    }

    return issueTokensAndRespond(client, res);
  } catch (err) {
    console.error('❌ clientLogin error:', err);
    return res.status(500).json({ message: 'Server error.' });
  }
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Local Login (Users)
 * ─────────────────────────────────────────────────────────────────────────── */
const localLogin = (req, res, next) => {
  passport.authenticate('local', { session: false }, async (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(400).json({ message: info?.message || 'Invalid credentials.' });

    try {
      return issueTokensAndRespond(user, res);
    } catch (e) {
      console.error('❌ localLogin error:', e);
      return res.status(500).json({ message: 'Server error.' });
    }
  })(req, res, next);
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Microsoft (Users) — OAuth start/callback
 * ─────────────────────────────────────────────────────────────────────────── */
const microsoftLogin = (req, res, next) => {
  const redirect = req.query.redirect;
  const state = redirect ? Buffer.from(JSON.stringify({ redirect }), 'utf8').toString('base64url') : undefined;

  return passport.authenticate('azure_ad_oauth2', {
    session: false,
    state,
  })(req, res, next);
};

const microsoftCallback = (req, res, next) => {
  passport.authenticate('azure_ad_oauth2', { session: false }, async (err, user) => {
    if (err) return next(err);
    if (!user) return res.status(400).json({ message: 'Microsoft authentication failed.' });
    return respondWebOrMobile(req, res, user);
  })(req, res, next);
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Microsoft ID Token → Local JWTs (MSAL mobile token exchange)
 * POST /api/auth/microsoft/exchange  { idToken }
 * ─────────────────────────────────────────────────────────────────────────── */
const microsoftExchange = async (req, res) => {
  try {
    if (!MSAL_MOBILE_CLIENT_ID) {
      console.error('❌ MSAL_MOBILE_CLIENT_ID is not set in environment.');
      return res.status(500).json({ message: 'Server misconfiguration.' });
    }

    const { idToken } = req.body || {};
    if (!idToken) {
      return res.status(400).json({ message: 'idToken is required.' });
    }

    let ms;
    try {
      ms = await verifyMicrosoftIdToken(idToken);
    } catch (e) {
      console.error('❌ ID token verify failed:', e.message || e);
      return res.status(401).json({ message: 'Invalid Microsoft ID token.' });
    }

    const email = ms.preferred_username || ms.email;
    const name = ms.name;
    const tid = ms.tid;

    if (TENANT_ID && TENANT_ID !== 'common' && tid && tid !== TENANT_ID) {
      return res.status(401).json({ message: 'Tenant mismatch.' });
    }
    if (!email) {
      return res.status(400).json({ message: 'Email claim missing in Microsoft ID token.' });
    }

    const microsoftId = ms.oid || ms.sub;
    let user = await User.findOne({ email });

    if (!user) {
      user = new User({
        email,
        name,
        tenantId: tid || TENANT_ID,
        microsoftId,
        roles: [],
        status: 'active',
      });
      await user.save();
    } else {
      let changed = false;
      if (!user.microsoftId) { user.microsoftId = microsoftId; changed = true; }
      if (!user.tenantId)    { user.tenantId    = tid || TENANT_ID; changed = true; }
      if (changed) await user.save();
    }

    return issueTokensAndRespond(user, res);
  } catch (e) {
    console.error('💥 microsoftExchange error:', e);
    return res.status(500).json({ message: 'Server error.' });
  }
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Google OAuth — Users & Clients (browser redirect flow)
 * ─────────────────────────────────────────────────────────────────────────── */
const googleUserLogin = (req, res, next) => {
  const redirect = req.query.redirect;
  const state = redirect ? Buffer.from(JSON.stringify({ redirect }), 'utf8').toString('base64url') : undefined;
  return passport.authenticate('google-user', { session: false, scope: ['profile', 'email'], state })(req, res, next);
};

const googleUserCallback = (req, res, next) => {
  passport.authenticate('google-user', { session: false }, async (err, user) => {
    if (err) return next(err);
    if (!user) return res.status(400).json({ message: 'Google authentication failed.' });
    return respondWebOrMobile(req, res, user);
  })(req, res, next);
};

const googleClientLogin = (req, res, next) => {
  const redirect = req.query.redirect;
  const state = redirect ? Buffer.from(JSON.stringify({ redirect }), 'utf8').toString('base64url') : undefined;
  return passport.authenticate('google-client', { session: false, scope: ['profile', 'email'], state })(req, res, next);
};

const googleClientCallback = (req, res, next) => {
  passport.authenticate('google-client', { session: false }, async (err, client) => {
    if (err) return next(err);
    if (!client) return res.status(400).json({ message: 'Google authentication failed.' });
    return respondWebOrMobile(req, res, client);
  })(req, res, next);
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Google Token Exchange (mobile-friendly)
 * POST /api/auth/google/exchange
 * Body:
 *   - Preferred: { code: "<serverAuthCode>", type: "user"|"client" }
 *   - Optional:  { idToken: "<google id_token>", type: "user"|"client" }
 * ─────────────────────────────────────────────────────────────────────────── */
const googleExchange = async (req, res) => {
  try {
    let { code, idToken, type = 'user' } = req.body || {};
    if (!['user', 'client'].includes(type)) {
      return res.status(400).json({ message: 'invalid type; must be "user" or "client"' });
    }

    let email, name, googleId;

    if (code) {
      // Exchange server auth code for tokens using "postmessage" (for installed apps)
      const tokenResp = await axios.post('https://oauth2.googleapis.com/token', {
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: 'postmessage',
        grant_type: 'authorization_code',
      });

      const { access_token } = tokenResp.data || {};
      if (!access_token) {
        return res.status(401).json({ message: 'Failed to exchange code with Google.' });
      }

      // Get profile with access token
      const profileResp = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${access_token}` },
      });
      email = profileResp.data?.email;
      name = profileResp.data?.name || profileResp.data?.given_name || '';
      googleId = profileResp.data?.id;
    } else if (idToken) {
      // Verify ID token via Google tokeninfo endpoint
      const verifyResp = await axios.get('https://oauth2.googleapis.com/tokeninfo', {
        params: { id_token: idToken },
      });
      email = verifyResp.data?.email;
      name = verifyResp.data?.name || '';
      googleId = verifyResp.data?.sub;
    } else {
      return res.status(400).json({ message: 'code or idToken is required' });
    }

    if (!email) return res.status(400).json({ message: 'Google profile missing email.' });

    const Model = type === 'user' ? User : Client;

    // Find or create principal
    let principal = await Model.findOne({ $or: [{ email }, { googleId }] });
    if (!principal) {
      principal = new Model(
        type === 'user'
          ? { email, name, googleId, tenantId: process.env.DEFAULT_TENANT_ID, roles: [], status: 'active' }
          : { email, name, googleId, roles: [] }
      );
      await principal.save();
    } else if (!principal.googleId) {
      principal.googleId = googleId;
      if (type === 'user' && !principal.tenantId) principal.tenantId = process.env.DEFAULT_TENANT_ID;
      await principal.save();
    }

    // Issue your tokens and cookie (JSON response, mobile-friendly)
    const roleDocs = await Role.find({ _id: { $in: principal.roles } })
      .select('name permissions -_id').lean();
    const roles = roleDocs.map((r) => r.name);
    const permissions = Array.from(new Set(roleDocs.flatMap((r) => r.permissions)));
    const accessTTL  = process.env.JWT_ACCESS_TOKEN_EXPIRES_IN  || '15m';
    const refreshTTL = process.env.JWT_REFRESH_TOKEN_EXPIRES_IN || '7d';

    const payload = { id: principal._id, email: principal.email, tenantId: principal.tenantId, roles, permissions };
    const accessToken  = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: accessTTL });
    const refreshToken = jwt.sign({ id: principal._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: refreshTTL });

    principal.refreshToken = refreshToken;
    try { await principal.save(); } catch (e) { console.error('❌ Saving refreshToken failed:', e); }

    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      path: '/',
      maxAge: getMillisecondsFromExpiry(refreshTTL),
    });

    return res.status(200).json({ accessToken, refreshToken });
  } catch (err) {
    console.error('❌ googleExchange error:', err?.response?.data || err.message || err);
    return res.status(500).json({ message: 'Server error during Google exchange.' });
  }
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Facebook OAuth — Users & Clients
 * ─────────────────────────────────────────────────────────────────────────── */
const facebookUserLogin = (req, res, next) => {
  const redirect = req.query.redirect;
  const state = redirect ? Buffer.from(JSON.stringify({ redirect }), 'utf8').toString('base64url') : undefined;
  return passport.authenticate('facebook-user', { session: false, scope: ['email'], state })(req, res, next);
};

const facebookUserCallback = (req, res, next) => {
  passport.authenticate('facebook-user', { session: false }, async (err, user) => {
    if (err) return next(err);
    if (!user) return res.status(400).json({ message: 'Facebook authentication failed.' });
    return respondWebOrMobile(req, res, user);
  })(req, res, next);
};

const facebookClientLogin = (req, res, next) => {
  const redirect = req.query.redirect;
  const state = redirect ? Buffer.from(JSON.stringify({ redirect }), 'utf8').toString('base64url') : undefined;
  return passport.authenticate('facebook-client', { session: false, scope: ['email'], state })(req, res, next);
};

const facebookClientCallback = (req, res, next) => {
  passport.authenticate('facebook-client', { session: false }, async (err, client) => {
    if (err) return next(err);
    if (!client) return res.status(400).json({ message: 'Facebook authentication failed.' });
    return respondWebOrMobile(req, res, client);
  })(req, res, next);
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Microsoft (Clients) — OAuth start/callback
 * ─────────────────────────────────────────────────────────────────────────── */
const microsoftClientLogin = (req, res, next) => {
  const redirect = req.query.redirect;
  const state = redirect ? Buffer.from(JSON.stringify({ redirect }), 'utf8').toString('base64url') : undefined;
  return passport.authenticate('azure_ad_oauth2_client', { session: false, state })(req, res, next);
};

const microsoftClientCallback = (req, res, next) => {
  passport.authenticate('azure_ad_oauth2_client', { session: false }, async (err, client) => {
    if (err) return next(err);
    if (!client) return res.status(400).json({ message: 'Microsoft authentication failed.' });
    return respondWebOrMobile(req, res, client);
  })(req, res, next);
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Refresh Token → new Access Token (supports User or Client)
 * ─────────────────────────────────────────────────────────────────────────── */
const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: 'Refresh token missing.' });
    }

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (err) {
      const msg = err.name === 'TokenExpiredError' ? 'Refresh token expired.' : 'Invalid refresh token.';
      return res.status(401).json({ message: msg });
    }

    // Try User first; if not found, try Client
    let principal = await User.findById(decoded.id);
    let principalType = 'user';
    if (!principal) {
      principal = await Client.findById(decoded.id);
      principalType = 'client';
    }
    if (!principal) return res.status(401).json({ message: 'Account not found.' });

    if (principal.refreshToken !== refreshToken) {
      return res.status(401).json({ message: 'Refresh token mismatch.' });
    }

    const roleDocs = await Role.find({ _id: { $in: principal.roles } })
      .select('name permissions -_id').lean();
    const roles = roleDocs.map((r) => r.name);
    const permissions = Array.from(new Set(roleDocs.flatMap((r) => r.permissions)));

    const payload = {
      id: principal._id,
      email: principal.email,
      tenantId: principal.tenantId, // undefined for Client is fine
      roles,
      permissions,
    };

    const accessTokenExpiresIn = process.env.JWT_ACCESS_TOKEN_EXPIRES_IN || '15m';
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: accessTokenExpiresIn });

    return res.status(200).json({ accessToken, type: principalType });
  } catch (error) {
    console.error('💥 [Refresh] Unexpected error:', error);
    return res.status(500).json({ message: 'Server error during token refresh.' });
  }
};

module.exports = {
  // Local + registration
  localLogin,
  registerClient,
  clientLogin,

  // Microsoft (Users)
  microsoftLogin,
  microsoftCallback,
  microsoftExchange,

  // Microsoft (Clients)
  microsoftClientLogin,
  microsoftClientCallback,

  // Google (browser)
  googleUserLogin,
  googleUserCallback,
  googleClientLogin,
  googleClientCallback,

  // Google (mobile exchange)
  googleExchange,

  // Facebook
  facebookUserLogin,
  facebookUserCallback,
  facebookClientLogin,
  facebookClientCallback,

  // Refresh
  refreshToken,
};
