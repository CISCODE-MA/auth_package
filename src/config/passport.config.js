const passport         = require('passport');
const LocalStrategy    = require('passport-local').Strategy;
const AzureStrategy    = require('passport-azure-ad-oauth2').Strategy;
const GoogleStrategy   = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const bcrypt           = require('bcryptjs');
const jwtDecode        = require('jsonwebtoken').decode;
const User             = require('../models/user.model');
const Client           = require('../models/client.model');
require('dotenv').config();

/* ── Lockout settings for local login ───────────────────── */
const MAX_FAILED    = parseInt(process.env.MAX_FAILED_LOGIN_ATTEMPTS, 10) || 3;
const LOCK_TIME_MIN = parseInt(process.env.ACCOUNT_LOCK_TIME_MINUTES, 10) || 15;
const LOCK_TIME_MS  = LOCK_TIME_MIN * 60 * 1000;

/* ── Default tenant for staff created via Google/Facebook ─ */
const DEFAULT_TENANT_ID = process.env.DEFAULT_TENANT_ID || 'social-staff';

/* ── Local (email/password) for staff ───────────────────── */
passport.use(
  new LocalStrategy(
    { usernameField: 'email', passwordField: 'password', passReqToCallback: true },
    async (req, email, password, done) => {
      try {
        const query = { email };
        if (req.body.tenantId) query.tenantId = String(req.body.tenantId).trim();

        const user = await User.findOne(query);
        if (!user) return done(null, false, { message: 'Incorrect email (or tenant).' });

        if (user.lockUntil && user.lockUntil > Date.now()) {
          return done(null, false, { message: `Account locked until ${new Date(user.lockUntil).toLocaleString()}.` });
        }

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) {
          user.failedLoginAttempts += 1;
          if (user.failedLoginAttempts >= MAX_FAILED) user.lockUntil = Date.now() + LOCK_TIME_MS;
          await user.save();
          return done(null, false, { message: 'Incorrect password.' });
        }

        user.failedLoginAttempts = 0;
        user.lockUntil = undefined;
        await user.save();

        return done(null, user);
      } catch (err) { return done(err); }
    }
  )
);

/* ── Microsoft (Users) ──────────────────────────────────── */
passport.use(
  new AzureStrategy(
    {
      clientID:     process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      callbackURL:  process.env.MICROSOFT_CALLBACK_URL, // e.g. /api/auth/microsoft/callback
    },
    async (_at, _rt, params, _profile, done) => {
      try {
        const decoded     = jwtDecode(params.id_token);
        const microsoftId = decoded.oid;
        const email       = decoded.preferred_username;
        const name        = decoded.name;
        const tenantId    = decoded.tid;

        let user = await User.findOne({ $or: [{ microsoftId }, { email }] });
        if (!user) {
          user = new User({ email, name, tenantId, microsoftId, roles: [], status: 'active' });
          await user.save();
        } else {
          let changed = false;
          if (!user.microsoftId) { user.microsoftId = microsoftId; changed = true; }
          if (!user.tenantId)    { user.tenantId    = tenantId;    changed = true; }
          if (changed) await user.save();
        }
        return done(null, user);
      } catch (err) { return done(err); }
    }
  )
);

/* ── Microsoft (Clients) ────────────────────────────────── */
passport.use(
  'azure_ad_oauth2_client',
  new AzureStrategy(
    {
      clientID:     process.env.MICROSOFT_CLIENT_ID_CLIENT     || process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET_CLIENT || process.env.MICROSOFT_CLIENT_SECRET,
      callbackURL:  process.env.MICROSOFT_CALLBACK_URL_CLIENT, // e.g. /api/auth/client/microsoft/callback
    },
    async (_at, _rt, params, _profile, done) => {
      try {
        const decoded     = jwtDecode(params.id_token);
        const microsoftId = decoded.oid;
        const email       = decoded.preferred_username;
        const name        = decoded.name;

        let client = await Client.findOne({ $or: [{ microsoftId }, { email }] });
        if (!client) {
          client = new Client({ email, name, microsoftId, roles: [] });
          // No password for OAuth clients by schema
          await client.save();
        } else if (!client.microsoftId) {
          client.microsoftId = microsoftId;
          await client.save();
        }
        return done(null, client);
      } catch (err) { return done(err); }
    }
  )
);

/* ── Google (Users) ─────────────────────────────────────── */
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_CALLBACK_URL_USER) {
  passport.use(
    'google-user',
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL_USER
      },
      async (_at, _rt, profile, done) => {
        try {
          const email = profile.emails && profile.emails[0]?.value;
          if (!email) return done(null, false);

          let user = await User.findOne({ email });
          if (!user) {
            user = new User({
              email,
              name: profile.displayName,
              tenantId: DEFAULT_TENANT_ID,
              googleId: profile.id,
              roles: [],
              status: 'active'
            });
            await user.save();
          } else {
            let changed = false;
            if (!user.googleId) { user.googleId = profile.id; changed = true; }
            if (!user.tenantId) { user.tenantId = DEFAULT_TENANT_ID; changed = true; }
            if (changed) await user.save();
          }
          return done(null, user);
        } catch (err) { return done(err); }
      }
    )
  );
}

/* ── Google (Clients) ───────────────────────────────────── */
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_CALLBACK_URL_CLIENT) {
  passport.use(
    'google-client',
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL_CLIENT
      },
      async (_at, _rt, profile, done) => {
        try {
          const email = profile.emails && profile.emails[0]?.value;
          if (!email) return done(null, false);

          let client = await Client.findOne({ email });
          if (!client) {
            client = new Client({
              email,
              name: profile.displayName,
              googleId: profile.id,
              roles: []
            });
            await client.save();
          } else if (!client.googleId) {
            client.googleId = profile.id;
            await client.save();
          }
          return done(null, client);
        } catch (err) { return done(err); }
      }
    )
  );
}

/* ── Facebook (Users) ───────────────────────────────────── */
if (process.env.FB_CLIENT_ID && process.env.FB_CLIENT_SECRET && process.env.FB_CALLBACK_URL_USER) {
  passport.use(
    'facebook-user',
    new FacebookStrategy(
      {
        clientID: process.env.FB_CLIENT_ID,
        clientSecret: process.env.FB_CLIENT_SECRET,
        callbackURL: process.env.FB_CALLBACK_URL_USER,
        profileFields: ['id', 'displayName', 'emails']
      },
      async (_at, _rt, profile, done) => {
        try {
          const email = profile.emails && profile.emails[0]?.value;
          if (!email) return done(null, false);

          let user = await User.findOne({ email });
          if (!user) {
            user = new User({
              email,
              name: profile.displayName,
              tenantId: DEFAULT_TENANT_ID,
              facebookId: profile.id,
              roles: [],
              status: 'active'
            });
            await user.save();
          } else {
            let changed = false;
            if (!user.facebookId) { user.facebookId = profile.id; changed = true; }
            if (!user.tenantId)   { user.tenantId   = DEFAULT_TENANT_ID; changed = true; }
            if (changed) await user.save();
          }
          return done(null, user);
        } catch (err) { return done(err); }
      }
    )
  );
}

/* ── Facebook (Clients) ─────────────────────────────────── */
if (process.env.FB_CLIENT_ID && process.env.FB_CLIENT_SECRET && process.env.FB_CALLBACK_URL_CLIENT) {
  passport.use(
    'facebook-client',
    new FacebookStrategy(
      {
        clientID: process.env.FB_CLIENT_ID,
        clientSecret: process.env.FB_CLIENT_SECRET,
        callbackURL: process.env.FB_CALLBACK_URL_CLIENT,
        profileFields: ['id', 'displayName', 'emails']
      },
      async (_at, _rt, profile, done) => {
        try {
          const email = profile.emails && profile.emails[0]?.value;
          if (!email) return done(null, false);

          let client = await Client.findOne({ email });
          if (!client) {
            client = new Client({
              email,
              name: profile.displayName,
              facebookId: profile.id,
              roles: []
            });
            await client.save();
          } else if (!client.facebookId) {
            client.facebookId = profile.id;
            await client.save();
          }
          return done(null, client);
        } catch (err) { return done(err); }
      }
    )
  );
}

/* ── Sessions (only if you use them) ────────────────────── */
passport.serializeUser((principal, done) => done(null, principal.id));
passport.deserializeUser(async (id, done) => {
  try {
    // Try Users, then Clients
    let principal = await User.findById(id);
    if (!principal) principal = await Client.findById(id);
    done(null, principal);
  } catch (err) {
    done(err);
  }
});

module.exports = passport;
