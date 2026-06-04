import crypto from 'node:crypto';

import storage from 'node-persist';
import express from 'express';
import nodemailer from 'nodemailer';

import { checkForNewContent, CONTENT_TYPES } from './content-manager.js';
import {
    toKey,
    getPasswordSalt,
    getPasswordHash,
    getAllUserHandles,
    getUserDirectories,
    ensurePublicDirectoriesExist,
    getAccountVersion,
} from '../users.js';

/**
 * RedQueen Chat — extra authentication on top of SillyTavern's multi-user core:
 *   - Self-registration with e-mail verification codes
 *   - Passwordless e-mail-code login
 *   - Google OAuth 2.0 (OpenID Connect)
 *   - X (Twitter) OAuth 2.0 with PKCE
 *
 * User objects are stored with the same shape as the core, plus optional fields:
 *   email, emailVerified, google_sub, x_sub
 */

const CODE_TTL_MS = 10 * 60 * 1000;       // verification code lifetime
const CODE_RESEND_MS = 60 * 1000;         // min interval between code sends per e-mail
const CODE_MAX_ATTEMPTS = 5;              // wrong-code attempts before a code is burned

/** @type {Map<string, { code: string, expires: number, sentAt: number, attempts: number }>} */
const codeStore = new Map();

const PUBLIC_ORIGIN = (process.env.RQ_PUBLIC_ORIGIN || 'https://chat.redqueen-serving.cloud').replace(/\/$/, '');

// ---------- helpers ----------

function isValidEmail(email) {
    return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function normalizeEmail(email) {
    return String(email).trim().toLowerCase();
}

function generateCode() {
    return crypto.randomInt(0, 1000000).toString().padStart(6, '0');
}

function slugifyHandle(text) {
    return String(text)
        .toLowerCase()
        .normalize('NFKD')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 32) || 'user';
}

async function getAllUsers() {
    const handles = await getAllUserHandles();
    const users = [];
    for (const handle of handles) {
        const user = await storage.getItem(toKey(handle));
        if (user) users.push(user);
    }
    return users;
}

async function findUserByEmail(email) {
    const target = normalizeEmail(email);
    const users = await getAllUsers();
    return users.find(u => u.email && normalizeEmail(u.email) === target) || null;
}

async function findUserByField(field, value) {
    if (!value) return null;
    const users = await getAllUsers();
    return users.find(u => u[field] === value) || null;
}

/**
 * Creates a brand new user account (enabled, with data directories).
 */
async function createUserAccount({ email = '', name = '', password = '', googleSub = '', xSub = '', emailVerified = false }) {
    const handles = await getAllUserHandles();
    const base = slugifyHandle(email ? email.split('@')[0] : (name || 'user'));
    let handle = base;
    let i = 1;
    while (handles.includes(handle)) {
        handle = `${base}-${i++}`;
    }

    const salt = getPasswordSalt();
    const passwordHash = password ? getPasswordHash(password, salt) : '';

    const user = {
        handle,
        name: name || (email ? email.split('@')[0] : handle),
        created: Date.now(),
        password: passwordHash,
        salt,
        admin: false,
        enabled: true,
        email: email ? normalizeEmail(email) : '',
        emailVerified: !!emailVerified,
        google_sub: googleSub || '',
        x_sub: xSub || '',
    };

    await storage.setItem(toKey(handle), user);
    await ensurePublicDirectoriesExist();
    const directories = getUserDirectories(handle);
    await checkForNewContent([directories], [CONTENT_TYPES.SETTINGS]);
    console.info('RedQueen: created account', handle, email ? `(${email})` : '');
    return user;
}

function loginSession(request, user) {
    if (!request.session) {
        throw new Error('Session not available');
    }
    request.session.handle = user.handle;
    request.session.version = getAccountVersion(user);
}

// ---------- e-mail ----------

let transporter = null;
function getTransporter() {
    if (transporter) return transporter;
    const host = process.env.RQ_SMTP_HOST || 'smtpdm.aliyun.com';
    const port = parseInt(process.env.RQ_SMTP_PORT || '465', 10);
    const user = process.env.RQ_SMTP_USER || 'noreply@mail.redqueen-serving.cloud';
    const pass = process.env.RQ_SMTP_PASS || '';
    transporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465,
        auth: { user, pass },
    });
    return transporter;
}

async function sendCodeEmail(email, code) {
    const from = process.env.RQ_SMTP_FROM || 'RedQueen Chat <noreply@mail.redqueen-serving.cloud>';
    const subject = 'RedQueen Chat 验证码 / Verification code';
    const text = `您的 RedQueen Chat 验证码是：${code}\n该验证码 10 分钟内有效，请勿泄露给他人。\n\nYour RedQueen Chat verification code is: ${code}\nIt expires in 10 minutes.`;
    const html = `<div style="font-family:sans-serif;font-size:15px;line-height:1.6">`
        + `<p>您的 <b>RedQueen Chat</b> 验证码是：</p>`
        + `<p style="font-size:28px;font-weight:bold;letter-spacing:4px">${code}</p>`
        + `<p>该验证码 10 分钟内有效，请勿泄露给他人。</p>`
        + `<hr><p style="color:#888">Your verification code is <b>${code}</b> (valid for 10 minutes).</p>`
        + `</div>`;
    await getTransporter().sendMail({ from, to: email, subject, text, html });
}

// ---------- code store ----------

function storeCode(email) {
    const code = generateCode();
    codeStore.set(email, { code, expires: Date.now() + CODE_TTL_MS, sentAt: Date.now(), attempts: 0 });
    return code;
}

/**
 * @returns {{ ok: boolean, error?: string }}
 */
function verifyCode(email, code) {
    const entry = codeStore.get(email);
    if (!entry) return { ok: false, error: 'No code requested for this e-mail' };
    if (Date.now() > entry.expires) {
        codeStore.delete(email);
        return { ok: false, error: 'Code expired, please request a new one' };
    }
    if (entry.attempts >= CODE_MAX_ATTEMPTS) {
        codeStore.delete(email);
        return { ok: false, error: 'Too many attempts, please request a new code' };
    }
    if (String(code) !== entry.code) {
        entry.attempts += 1;
        return { ok: false, error: 'Incorrect code' };
    }
    codeStore.delete(email);
    return { ok: true };
}

// =========================================================================
//  Public router (mounted at /api/users) — protected by the same CSRF layer
// =========================================================================

export const router = express.Router();

router.post('/send-code', async (request, response) => {
    try {
        const email = normalizeEmail(request.body.email || '');

        if (!isValidEmail(email)) {
            return response.status(400).json({ error: 'Invalid e-mail address' });
        }

        // Unified flow: a code can always be sent to any valid e-mail.
        // Whether it logs in or creates an account is decided at verification time.
        const existing = await findUserByEmail(email);
        if (existing && !existing.enabled) {
            return response.status(403).json({ error: 'Account is disabled' });
        }

        const prev = codeStore.get(email);
        if (prev && Date.now() - prev.sentAt < CODE_RESEND_MS) {
            return response.status(429).json({ error: 'Please wait a moment before requesting another code' });
        }

        const code = storeCode(email);
        await sendCodeEmail(email, code);
        return response.sendStatus(204);
    } catch (error) {
        console.error('RedQueen send-code failed:', error);
        return response.status(500).json({ error: 'Failed to send verification e-mail' });
    }
});

// Unified passwordless auth: verify the code, then log in if the account exists,
// or create it on the fly. No separate registration step, no password.
router.post('/auth-email', async (request, response) => {
    try {
        const email = normalizeEmail(request.body.email || '');
        const code = String(request.body.code || '');

        if (!isValidEmail(email)) {
            return response.status(400).json({ error: 'Invalid e-mail address' });
        }

        const verification = verifyCode(email, code);
        if (!verification.ok) {
            return response.status(400).json({ error: verification.error });
        }

        let user = await findUserByEmail(email);
        if (user) {
            if (!user.enabled) {
                return response.status(403).json({ error: 'Account is disabled' });
            }
            if (!user.emailVerified) {
                user.emailVerified = true;
                await storage.setItem(toKey(user.handle), user);
            }
        } else {
            user = await createUserAccount({ email, emailVerified: true });
        }

        loginSession(request, user);
        return response.json({ handle: user.handle });
    } catch (error) {
        console.error('RedQueen auth-email failed:', error);
        return response.status(500).json({ error: 'Authentication failed' });
    }
});

// =========================================================================
//  OAuth router (mounted at /auth) — GET redirects, no CSRF (state-checked)
// =========================================================================

export const oauthRouter = express.Router();

function b64url(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function oauthEnabled(provider) {
    if (provider === 'google') return !!(process.env.RQ_GOOGLE_CLIENT_ID && process.env.RQ_GOOGLE_CLIENT_SECRET);
    if (provider === 'x') return !!(process.env.RQ_X_CLIENT_ID && process.env.RQ_X_CLIENT_SECRET);
    return false;
}

/**
 * Resolves an OAuth identity to a session: link by sub, then by e-mail, else create.
 */
async function resolveOAuthUser(request, response, { provider, sub, email, name }) {
    const field = provider === 'google' ? 'google_sub' : 'x_sub';

    let user = await findUserByField(field, sub);
    if (!user && email) {
        user = await findUserByEmail(email);
        if (user) {
            user[field] = sub;
            if (provider === 'google' && email) user.emailVerified = true;
            await storage.setItem(toKey(user.handle), user);
        }
    }
    if (!user) {
        user = await createUserAccount({
            email: email || '',
            name: name || '',
            googleSub: provider === 'google' ? sub : '',
            xSub: provider === 'x' ? sub : '',
            emailVerified: provider === 'google' && !!email,
        });
    }

    if (!user.enabled) {
        return response.redirect('/login?error=disabled');
    }

    loginSession(request, user);
    return response.redirect('/');
}

// ---- Google ----

oauthRouter.get('/google', (request, response) => {
    if (!oauthEnabled('google')) {
        return response.redirect('/login?error=google_unavailable');
    }
    const state = b64url(crypto.randomBytes(16));
    request.session.oauth_state = state;
    const params = new URLSearchParams({
        client_id: process.env.RQ_GOOGLE_CLIENT_ID,
        redirect_uri: `${PUBLIC_ORIGIN}/auth/google/callback`,
        response_type: 'code',
        scope: 'openid email profile',
        state,
        prompt: 'select_account',
    });
    return response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

oauthRouter.get('/google/callback', async (request, response) => {
    try {
        if (!oauthEnabled('google')) {
            return response.redirect('/login?error=google_unavailable');
        }
        const { code, state } = request.query;
        if (!code || !state || state !== request.session.oauth_state) {
            return response.redirect('/login?error=oauth_state');
        }
        request.session.oauth_state = null;

        const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code: String(code),
                client_id: process.env.RQ_GOOGLE_CLIENT_ID,
                client_secret: process.env.RQ_GOOGLE_CLIENT_SECRET,
                redirect_uri: `${PUBLIC_ORIGIN}/auth/google/callback`,
                grant_type: 'authorization_code',
            }),
        });
        if (!tokenResp.ok) {
            console.error('Google token exchange failed:', await tokenResp.text());
            return response.redirect('/login?error=oauth_token');
        }
        const tokens = await tokenResp.json();

        const userResp = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
            headers: { Authorization: `Bearer ${tokens.access_token}` },
        });
        if (!userResp.ok) {
            console.error('Google userinfo failed:', await userResp.text());
            return response.redirect('/login?error=oauth_userinfo');
        }
        const profile = await userResp.json();

        return await resolveOAuthUser(request, response, {
            provider: 'google',
            sub: profile.sub,
            email: profile.email,
            name: profile.name || profile.given_name || '',
        });
    } catch (error) {
        console.error('Google OAuth callback failed:', error);
        return response.redirect('/login?error=oauth_failed');
    }
});

// ---- X (Twitter) ----

oauthRouter.get('/x', (request, response) => {
    if (!oauthEnabled('x')) {
        return response.redirect('/login?error=x_unavailable');
    }
    const state = b64url(crypto.randomBytes(16));
    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
    request.session.x_oauth_state = state;
    request.session.x_code_verifier = verifier;
    const params = new URLSearchParams({
        response_type: 'code',
        client_id: process.env.RQ_X_CLIENT_ID,
        redirect_uri: `${PUBLIC_ORIGIN}/auth/x/callback`,
        scope: 'tweet.read users.read',
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
    });
    return response.redirect(`https://twitter.com/i/oauth2/authorize?${params.toString()}`);
});

oauthRouter.get('/x/callback', async (request, response) => {
    try {
        if (!oauthEnabled('x')) {
            return response.redirect('/login?error=x_unavailable');
        }
        const { code, state } = request.query;
        if (!code || !state || state !== request.session.x_oauth_state) {
            return response.redirect('/login?error=oauth_state');
        }
        const verifier = request.session.x_code_verifier;
        request.session.x_oauth_state = null;
        request.session.x_code_verifier = null;

        const basic = Buffer.from(`${process.env.RQ_X_CLIENT_ID}:${process.env.RQ_X_CLIENT_SECRET}`).toString('base64');
        const tokenResp = await fetch('https://api.twitter.com/2/oauth2/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Authorization: `Basic ${basic}`,
            },
            body: new URLSearchParams({
                code: String(code),
                grant_type: 'authorization_code',
                redirect_uri: `${PUBLIC_ORIGIN}/auth/x/callback`,
                code_verifier: String(verifier),
                client_id: process.env.RQ_X_CLIENT_ID,
            }),
        });
        if (!tokenResp.ok) {
            console.error('X token exchange failed:', await tokenResp.text());
            return response.redirect('/login?error=oauth_token');
        }
        const tokens = await tokenResp.json();

        const userResp = await fetch('https://api.twitter.com/2/users/me', {
            headers: { Authorization: `Bearer ${tokens.access_token}` },
        });
        if (!userResp.ok) {
            console.error('X users/me failed:', await userResp.text());
            return response.redirect('/login?error=oauth_userinfo');
        }
        const profile = (await userResp.json()).data || {};

        return await resolveOAuthUser(request, response, {
            provider: 'x',
            sub: profile.id,
            email: '',
            name: profile.name || profile.username || '',
        });
    } catch (error) {
        console.error('X OAuth callback failed:', error);
        return response.redirect('/login?error=oauth_failed');
    }
});

/**
 * Reports which social providers are configured, for the login UI to show/hide buttons.
 */
oauthRouter.get('/providers', (_request, response) => {
    return response.json({
        google: oauthEnabled('google'),
        x: oauthEnabled('x'),
    });
});
