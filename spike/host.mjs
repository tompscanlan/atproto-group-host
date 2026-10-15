// host.mjs: a THROWAWAY group-host spike, not the product.
//
// Runs inside a container made from the spaces alpha PDS image (bluesky-social/atproto
// permissioned-data-alpha 79d6307e1), so @atproto/pds is exactly the pinned build. It tests:
//   (a) the alpha PDS builds as a library through PDS.create, behind an outer express app;
//   (b) a person signs in through their own PDS and the host signs the browser in as the GROUP
//       with a one-time ticket fed to the PDS's own sign-in step, never the group's password;
//   (c) a group space under the managing-app policy calls back to this host's checkUserAccess,
//       and what the host answers is what the PDS enforces.
//
// Spike-only admin routes under /spike/* set the role table and the access answers.
import crypto from 'node:crypto'
import { createRequire } from 'node:module'
import { PDS, envToCfg, envToSecrets, readEnv } from '/app/packages/pds/dist/index.js'
import { verifyJwt } from '/app/packages/xrpc-server/dist/auth.js'
import { OAuthClient, MemoryStore } from '@atcute/oauth-node-client'
import {
  CompositeDidDocumentResolver,
  LocalActorResolver,
  PlcDidDocumentResolver,
  WebDidDocumentResolver,
  WellKnownHandleResolver,
} from '@atcute/identity-resolver'

const require = createRequire('/app/packages/pds/package.json')
const express = require('express')

const PUBLIC_URL = process.env.HOST_PUBLIC_URL // https://grouphost.devnet.internal
const HOST_DID = `did:web:${new URL(PUBLIC_URL).host}`
const MANAGING_APP = `${HOST_DID}#group_host`
const LOOPBACK = process.env.HOST_LOOPBACK_URL // http://127.0.0.1:7070, where the browser lands
const log = (...a) => console.log(new Date().toISOString(), '[host]', ...a)

// ---- spike state (a real host keeps these in its own tables) ----
const roles = new Map() // groupDid -> Set(personDid) holding any role
const access = new Map() // `${space}|${user}|${read|write}` -> boolean
const tickets = new Map() // id -> { groupDid, personDid, exp, used }
const pending = new Map() // signin state -> { requestUri, clientId, groupDid }
const authorizedBy = [] // { groupDid, personDid, at }: which person each group sign-in stands for
const accessCalls = [] // every checkUserAccess the PDS made

// ---- (a) the PDS as a library ----
const env = readEnv()
const cfg = envToCfg(env)
const secrets = envToSecrets(env)
const pds = await PDS.create(cfg, secrets)
const provider = pds.ctx.oauthProvider
log('PDS.create ok; oauthProvider', provider ? 'present' : 'absent', '; service did', cfg.service.did)

// ---- (b) sign-in by ticket: wrap the provider's account store instance (no file patched) ----
const store = provider.accountManager.store
const origAuthenticate = store.authenticateAccount.bind(store)
store.authenticateAccount = async (data) => {
  if (typeof data.password === 'string' && data.password.startsWith('ticket:')) {
    const id = data.password.slice('ticket:'.length)
    const t = tickets.get(id)
    tickets.delete(id) // single use, whatever happens next
    const groupDid = data.username.startsWith('did:')
      ? data.username
      : await pds.ctx.accountManager.getAccount(data.username).then((a) => a?.did)
    if (!t || t.used || t.exp < Date.now() || t.groupDid !== groupDid) {
      log('ticket sign-in REFUSED', { known: !!t, groupMatches: t?.groupDid === groupDid })
      const { InvalidRequestError } = require('@atproto/oauth-provider')
      throw new InvalidRequestError('Invalid ticket')
    }
    authorizedBy.push({ groupDid, personDid: t.personDid, at: new Date().toISOString() })
    log('ticket sign-in accepted', { groupDid, personDid: t.personDid })
    const { account } = await store.getAccount(groupDid)
    return account
  }
  return origAuthenticate(data)
}

// The host as an OAuth CLIENT of the person's own PDS (authentication only). A loopback public
// client is enough for the spike; the product would be a confidential client at PUBLIC_URL.
const actorResolver = new LocalActorResolver({
  handleResolver: new WellKnownHandleResolver(),
  didDocumentResolver: new CompositeDidDocumentResolver({
    methods: { plc: new PlcDidDocumentResolver({ apiUrl: process.env.HOST_PLC_URL }), web: new WebDidDocumentResolver() },
  }),
})
const personClient = new OAuthClient({
  metadata: { redirect_uris: [`${LOOPBACK}/signin/callback`], scope: 'atproto' },
  actorResolver,
  stores: { sessions: new MemoryStore(), states: new MemoryStore({ ttl: 600_000 }) },
})

async function loginHintOf(requestUri) {
  const id = requestUri.replace(/^urn:ietf:params:oauth:request_uri:/, '')
  const data = await provider.requestManager.store.readRequest(id)
  return data?.parameters?.login_hint
}
async function groupDidOf(hint) {
  if (!hint) return undefined
  if (hint.startsWith('did:')) return hint
  return (await pds.ctx.accountManager.getAccount(hint))?.did
}

const outer = express()

// did:web for the host itself, naming the endpoint the PDS calls for checkUserAccess.
outer.get('/.well-known/did.json', (req, res) => {
  res.json({
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: HOST_DID,
    service: [{ id: '#group_host', type: 'GroupHost', serviceEndpoint: PUBLIC_URL }],
  })
})

// The app's browser arrives at the PDS's authorize page. Unless it is coming back from our own
// sign-in, send it to sign in through the person's own PDS first.
outer.get('/oauth/authorize', async (req, res, next) => {
  try {
    const { request_uri: requestUri, client_id: clientId } = req.query
    if (req.query.gh === 'ticket') return res.type('html').send(ticketPage(requestUri, clientId))
    if (req.query.gh === 'pass' || !requestUri) return next()
    const groupDid = await groupDidOf(await loginHintOf(requestUri))
    if (!groupDid) return next() // not a group sign-in we recognise: the PDS's own page
    const state = crypto.randomBytes(12).toString('hex')
    pending.set(state, { requestUri, clientId, groupDid })
    res.redirect(`${LOOPBACK}/signin/start?state=${state}`)
  } catch (err) {
    next(err)
  }
})

// Ask who you are (your own handle), then OAuth to your own PDS.
outer.get('/signin/start', async (req, res, next) => {
  try {
    const p = pending.get(req.query.state)
    if (!p) return res.status(400).send('unknown sign-in')
    if (!req.query.handle) {
      return res.type('html').send(`<!doctype html><title>Sign in to act as the group</title>
<form method=get><input type=hidden name=state value="${req.query.state}">
<p>Act as group <code>${p.groupDid}</code>. Sign in with your own account:</p>
<input name=handle placeholder="you.example.com"><button>Continue</button></form>`)
    }
    const { url } = await personClient.authorize({
      target: { type: 'account', identifier: String(req.query.handle) },
      scope: 'atproto',
      state: { s: req.query.state },
    })
    res.redirect(url.toString())
  } catch (err) {
    next(err)
  }
})

outer.get('/signin/callback', async (req, res, next) => {
  try {
    const params = new URLSearchParams(req.url.split('?')[1])
    const { session, state } = await personClient.callback(params)
    const personDid = session.did
    const p = pending.get(state?.s)
    pending.delete(state?.s)
    if (!p) return res.status(400).send('unknown sign-in')
    const holds = roles.get(p.groupDid)?.has(personDid) ?? false
    log('person signed in through own PDS', { personDid, groupDid: p.groupDid, holdsRole: holds })
    if (!holds) return res.status(403).send(`You (${personDid}) hold no role in ${p.groupDid}`)
    const id = crypto.randomBytes(24).toString('base64url')
    tickets.set(id, { groupDid: p.groupDid, personDid, exp: Date.now() + 120_000, used: false })
    // The callback is on the loopback origin, so a cookie would not reach the host's origin. The
    // ticket rides the URL fragment instead: never sent to a server, never in a referrer.
    const q = new URLSearchParams({ request_uri: p.requestUri, client_id: p.clientId, gh: 'ticket' })
    const frag = new URLSearchParams({ t: id, g: p.groupDid })
    res.redirect(`${PUBLIC_URL}/oauth/authorize?${q}#${frag}`)
  } catch (err) {
    next(err)
  }
})

// Served AT /oauth/authorize so the provider's sign-in API accepts the call (it requires the
// authorize page as referrer, same-origin fetch and the CSRF cookie/header pair).
function ticketPage(requestUri, clientId) {
  const back = new URLSearchParams({ request_uri: requestUri, client_id: clientId, gh: 'pass' })
  return `<!doctype html><title>Signing you in as the group</title><p id=s>Signing you in as the group...</p>
<script>
(async () => {
  const get = (n) => (document.cookie.split('; ').find((c) => c.startsWith(n + '=')) || '').slice(n.length + 1)
  let csrf = get('csrf-token')
  if (!csrf) { csrf = crypto.randomUUID().replace(/-/g, '').slice(0, 24); document.cookie = 'csrf-token=' + csrf + '; path=/; secure; samesite=lax' }
  const h = new URLSearchParams(location.hash.slice(1)), ticket = h.get('t'), group = h.get('g')
  history.replaceState(null, '', location.pathname + location.search)
  const r = await fetch('/@atproto/oauth-provider/~api/sign-in', {
    method: 'POST', mode: 'same-origin', credentials: 'same-origin',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    body: JSON.stringify({ locale: 'en', username: group, password: 'ticket:' + ticket, remember: true }),
  })
  document.getElementById('s').textContent = 'sign-in ' + r.status
  if (r.ok) location.replace('/oauth/authorize?${back}')
})()
</script>`
}

// ---- (c) the managing app's answer ----
outer.get('/xrpc/com.atproto.simplespace.checkUserAccess', async (req, res) => {
  const { space, user, access: kind, clientId } = req.query
  let iss = null
  try {
    const jwt = (req.headers.authorization || '').replace(/^Bearer /, '')
    const payload = await verifyJwt(jwt, MANAGING_APP, 'com.atproto.simplespace.checkUserAccess', (did, force) =>
      pds.ctx.idResolver.did.resolveAtprotoKey(did, force),
    )
    iss = payload.iss
  } catch (err) {
    accessCalls.push({ space, user, kind, iss: null, error: err.message })
    log('checkUserAccess: bad service auth', err.message)
    return res.status(401).json({ error: 'AuthRequired', message: err.message })
  }
  // The caller must be the space's own authority.
  const authority = String(space).split('/')[2]
  const authorized = iss === authority && access.get(`${space}|${user}|${kind}`) === true
  accessCalls.push({ space, user, kind, clientId: clientId ?? null, iss, authorized, at: new Date().toISOString() })
  log('checkUserAccess', { space, user, kind, iss, authorized })
  res.json({ authorized })
})

// ---- spike admin (no auth: devnet only, bound behind the devnet's nginx) ----
outer.use('/spike', express.json())
outer.post('/spike/roles', (req, res) => {
  const { group, person, hold } = req.body
  if (!roles.has(group)) roles.set(group, new Set())
  hold ? roles.get(group).add(person) : roles.get(group).delete(person)
  res.json({ group, holders: [...roles.get(group)] })
})
outer.post('/spike/access', (req, res) => {
  const { space, user, kind, allow } = req.body
  access.set(`${space}|${user}|${kind}`, !!allow)
  res.json({ ok: true })
})
outer.get('/spike/state', (req, res) => res.json({ authorizedBy, accessCalls, managingApp: MANAGING_APP }))

// ---- everything else: the PDS, unmodified ----
outer.use(pds.app)
pds.app = outer
await pds.start()
log('listening', cfg.service.port, 'as', PUBLIC_URL)
