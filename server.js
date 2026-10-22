'use strict'

// Website Review — Spyne internal tool.
//
// These static dashboards used to be served straight from GitHub Pages with
// client-side Google Sign-In and a hardcoded allow-list baked into the HTML.
// That left the files open to anyone on the internet (the JS "login" was never
// enforced). This server fixes that: every route is behind a server-side
// Google session, config comes only from APP_SECRETS, and there is an
// unauthenticated /health endpoint for the load balancer.

const path = require('path')
const crypto = require('crypto')
const express = require('express')
const cookieParser = require('cookie-parser')

// ---------------------------------------------------------------------------
// Configuration — everything comes from APP_SECRETS, a single JSON env var.
// Parse it once at startup and fail fast, naming any missing key. No
// production fallbacks, no .env, no values in code: the values live only in AWS.
// ---------------------------------------------------------------------------

function loadConfig() {
  const raw = process.env.APP_SECRETS
  if (!raw) {
    throw new Error(
      'APP_SECRETS is not set. It must be a JSON string holding all runtime config. ' +
        'The app cannot boot without it.'
    )
  }

  let cfg
  try {
    cfg = JSON.parse(raw)
  } catch (err) {
    throw new Error('APP_SECRETS is not valid JSON: ' + err.message)
  }

  // The five auth keys are required, by exactly these names.
  const REQUIRED = [
    'CLIENT_ID', // the shared Spyne Google client
    'CLIENT_SECRET', // its private half
    'GOOGLE_REDIRECT_URI', // https://website-review.spyne.ai/api/auth/callback/google
    'GOOGLE_ALLOWED_DOMAIN', // spyne.ai
    'AUTH_SECRET', // signs session cookies, unique to this app
  ]

  const missing = REQUIRED.filter((k) => !cfg[k] || String(cfg[k]).trim() === '')
  if (missing.length > 0) {
    throw new Error(
      'APP_SECRETS is missing required key(s): ' +
        missing.join(', ') +
        '. The code names the keys; the values live only in AWS.'
    )
  }

  return cfg
}

const config = loadConfig()

const PORT = Number(config.PORT || process.env.PORT || 3000)
const SERVICE_NAME = config.NAME || 'website-review'
const CLIENT_ID = config.CLIENT_ID
const CLIENT_SECRET = config.CLIENT_SECRET
const GOOGLE_REDIRECT_URI = config.GOOGLE_REDIRECT_URI
const GOOGLE_ALLOWED_DOMAIN = config.GOOGLE_ALLOWED_DOMAIN
const AUTH_SECRET = config.AUTH_SECRET

// Optional narrower allow-list. When absent, any verified @<domain> account is
// allowed (the default we want for almost every internal tool). When present,
// only these addresses may sign in — read from config, never hardcoded.
const ALLOWED_EMAILS = String(config.ALLOWED_EMAILS || '')
  .split(',')
  .map((e) => e.trim().toLowerCase())
  .filter(Boolean)

const SESSION_COOKIE = 'wr_session'
const STATE_COOKIE = 'wr_oauth_state'
const RETURN_COOKIE = 'wr_return_to'
const SESSION_TTL_MS = 12 * 60 * 60 * 1000 // 12 hours

// ---------------------------------------------------------------------------
// Session: a stateless signed cookie. payload{email,name,exp} + HMAC(AUTH_SECRET).
// ---------------------------------------------------------------------------

function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64url')
}

function sign(value) {
  return crypto.createHmac('sha256', AUTH_SECRET).update(value).digest('base64url')
}

function makeSession(payload) {
  const body = b64urlEncode(JSON.stringify(payload))
  return body + '.' + sign(body)
}

function readSession(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null
  const [body, mac] = token.split('.')
  const expected = sign(body)
  // constant-time compare
  const a = Buffer.from(mac)
  const b = Buffer.from(expected)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null
  let payload
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
  } catch {
    return null
  }
  if (!payload || typeof payload.exp !== 'number' || payload.exp < Date.now()) return null
  return payload
}

function emailAllowed(email, emailVerified) {
  if (!email || emailVerified !== true) return false
  const addr = String(email).toLowerCase()
  const domain = addr.split('@')[1]
  if (domain !== String(GOOGLE_ALLOWED_DOMAIN).toLowerCase()) return false
  if (ALLOWED_EMAILS.length > 0 && !ALLOWED_EMAILS.includes(addr)) return false
  return true
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = express()
app.disable('x-powered-by')
app.set('trust proxy', true)
app.use(cookieParser())

const cookieBase = {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
}

// --- Health: unauthenticated, must never redirect. The load balancer polls
// this signed out; a redirect to sign-in reads as unhealthy and ECS kills the
// task on a loop. Keep it OUTSIDE the auth middleware (declared before it).
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: SERVICE_NAME,
    timestamp: new Date().toISOString(),
  })
})

// --- Auth routes: exempt from the session requirement so they don't redirect-loop.

// Start sign-in: bounce the user to Google.
app.get('/api/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex')
  res.cookie(STATE_COOKIE, state, { ...cookieBase, maxAge: 10 * 60 * 1000 })

  const returnTo = typeof req.query.return_to === 'string' ? req.query.return_to : '/'
  // Only allow same-origin relative paths as a return target.
  if (returnTo.startsWith('/') && !returnTo.startsWith('//')) {
    res.cookie(RETURN_COOKIE, returnTo, { ...cookieBase, maxAge: 10 * 60 * 1000 })
  }

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'online',
    include_granted_scopes: 'true',
    prompt: 'select_account',
    hd: GOOGLE_ALLOWED_DOMAIN,
    state,
  })
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString())
})

// Google redirects back here with ?code&state.
app.get('/api/auth/callback/google', async (req, res) => {
  try {
    const { code, state } = req.query
    const stateCookie = req.cookies[STATE_COOKIE]
    if (!code || !state || !stateCookie || state !== stateCookie) {
      return res.status(400).send('Invalid sign-in state. Please try again.')
    }
    res.clearCookie(STATE_COOKIE, cookieBase)

    // Exchange the code for tokens directly with Google (server-to-server, TLS).
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: String(code),
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    })

    if (!tokenRes.ok) {
      const detail = await tokenRes.text()
      console.error('Google token exchange failed:', tokenRes.status, detail)
      return res.status(502).send('Sign-in failed at Google. Please try again.')
    }

    const tokens = await tokenRes.json()
    const idToken = tokens.id_token
    if (!idToken || idToken.split('.').length !== 3) {
      return res.status(502).send('Sign-in failed: no identity token returned.')
    }

    // The id_token came straight from Google's token endpoint over TLS, so its
    // payload is trusted; decode the claims.
    const claims = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64url').toString('utf8'))

    if (!emailAllowed(claims.email, claims.email_verified)) {
      return res
        .status(403)
        .send(
          'Access denied. This tool is restricted to Spyne accounts' +
            (ALLOWED_EMAILS.length > 0 ? ' on the allow-list.' : '.')
        )
    }

    const session = makeSession({
      email: String(claims.email).toLowerCase(),
      name: claims.name || claims.email,
      exp: Date.now() + SESSION_TTL_MS,
    })
    res.cookie(SESSION_COOKIE, session, { ...cookieBase, maxAge: SESSION_TTL_MS })

    let returnTo = req.cookies[RETURN_COOKIE] || '/'
    if (!returnTo.startsWith('/') || returnTo.startsWith('//')) returnTo = '/'
    res.clearCookie(RETURN_COOKIE, cookieBase)
    res.redirect(returnTo)
  } catch (err) {
    console.error('Auth callback error:', err)
    res.status(500).send('Sign-in error. Please try again.')
  }
})

app.get('/api/auth/logout', (req, res) => {
  res.clearCookie(SESSION_COOKIE, cookieBase)
  res.redirect('/api/auth/login')
})

// --- Gate: require a session on EVERY remaining route. No session -> Google.
app.use((req, res, next) => {
  const session = readSession(req.cookies[SESSION_COOKIE])
  if (session) {
    req.user = session
    return next()
  }
  const returnTo = encodeURIComponent(req.originalUrl || '/')
  res.redirect('/api/auth/login?return_to=' + returnTo)
})

// --- Everything past the gate is authenticated: serve the static dashboards.
app.use(
  express.static(path.join(__dirname, 'public'), {
    extensions: ['html'],
    index: 'index.html',
  })
)

// Authenticated but unknown path.
app.use((req, res) => {
  res.status(404).send('Not found')
})

app.listen(PORT, '0.0.0.0', () => {
  console.log(`${SERVICE_NAME} listening on 0.0.0.0:${PORT}`)
})
