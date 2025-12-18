const express = require('express');
const router = express.Router();

const auth = require('../controllers/auth.controller');
const passwordReset = require('../controllers/passwordReset.controller');

/* ────────────────────────────────────────────────────────────────────────────
 * Client registration & login (client credentials)
 * ────────────────────────────────────────────────────────────────────────── */
router.post('/clients/register', auth.registerClient);
router.post('/clients/login',    auth.clientLogin);

/* ────────────────────────────────────────────────────────────────────────────
 * User login (local credentials)
 * ────────────────────────────────────────────────────────────────────────── */
router.post('/login', auth.localLogin);

/* ────────────────────────────────────────────────────────────────────────────
 * Microsoft OAuth (Users)
 * ────────────────────────────────────────────────────────────────────────── */
router.get('/microsoft',          auth.microsoftLogin);
router.get('/microsoft/callback', auth.microsoftCallback);

/* ────────────────────────────────────────────────────────────────────────────
 * Microsoft OAuth (Clients)
 * ────────────────────────────────────────────────────────────────────────── */
router.get('/client/microsoft',          auth.microsoftClientLogin);
router.get('/client/microsoft/callback', auth.microsoftClientCallback);

/* ────────────────────────────────────────────────────────────────────────────
 * Microsoft ID token → local JWTs (MSAL mobile token exchange)
 * ────────────────────────────────────────────────────────────────────────── */
router.post('/microsoft/exchange', auth.microsoftExchange);

/* ────────────────────────────────────────────────────────────────────────────
 * Google OAuth (Users)
 * ────────────────────────────────────────────────────────────────────────── */
router.get('/google',          auth.googleUserLogin);
router.get('/google/callback', auth.googleUserCallback);

/* ────────────────────────────────────────────────────────────────────────────
 * Google OAuth (Clients)
 * ────────────────────────────────────────────────────────────────────────── */
router.get('/client/google',          auth.googleClientLogin);
router.get('/client/google/callback', auth.googleClientCallback);

/* ────────────────────────────────────────────────────────────────────────────
 * Google token exchange (mobile-friendly)
 * Body: { code: "<serverAuthCode>", type: "user"|"client" } 
 *    or { idToken: "<google id_token>", type: "user"|"client" }
 * ────────────────────────────────────────────────────────────────────────── */
router.post('/google/exchange', auth.googleExchange);

/* ────────────────────────────────────────────────────────────────────────────
 * Facebook OAuth (Users)
 * ────────────────────────────────────────────────────────────────────────── */
router.get('/facebook',          auth.facebookUserLogin);
router.get('/facebook/callback', auth.facebookUserCallback);

/* ────────────────────────────────────────────────────────────────────────────
 * Facebook OAuth (Clients)
 * ────────────────────────────────────────────────────────────────────────── */
router.get('/client/facebook',          auth.facebookClientLogin);
router.get('/client/facebook/callback', auth.facebookClientCallback);

/* ────────────────────────────────────────────────────────────────────────────
 * Password reset (Users & Clients) — body must include { type: "user"|"client" }
 * ────────────────────────────────────────────────────────────────────────── */
router.post('/request-password-reset', passwordReset.requestPasswordReset);
router.post('/reset-password',         passwordReset.resetPassword);

/* ────────────────────────────────────────────────────────────────────────────
 * Refresh token → new access token (works for User or Client)
 * ────────────────────────────────────────────────────────────────────────── */
router.post('/refresh-token', auth.refreshToken);

module.exports = router;
