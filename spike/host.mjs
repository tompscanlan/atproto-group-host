// host.mjs: a THROWAWAY group-host spike, not the product.
//
// Runs inside a container made from the spaces alpha PDS image (bluesky-social/atproto
// permissioned-data-alpha 79d6307e1), so @atproto/pds is exactly the pinned build. It tests:
//   (a) the alpha PDS builds as a library through PDS.create, behind an outer express app;
//   (b) a person signs in through their own PDS and the host signs the browser in as the GROUP
//       with a one-time ticket fed to the PDS's own sign-in step, never the group's password;
//   (c) a group space under the managing-app policy calls back to this host's checkUserAccess,
//       and what the host answers is what the PDS enforces;
//   (d) the person's roles come from the group's own records: the host offers only the scopes
//       those roles grant, records which person authorized each token, and cuts each token's
//       scopes on every request to what that person's roles grant now;
//   (e) prompt=create makes a group: the account, its meta and members spaces, and their records;
//   (f) the host enforces from those records: checkUserAccess answers from `access` and the
//       person's roles, group writes pass the record rules and the writer's `assignable` roles
//       before the PDS takes them, writes to a space with no `access` record are refused, and
//       nobody reconfigures a group space through simplespace.
//
// Spike-only routes under /spike/* show the host's state and set up test cases.
import crypto from 'node:crypto'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import { PDS, envToCfg, envToSecrets, readEnv } from '/app/packages/pds/dist/index.js'
import { verifyJwt } from '/app/packages/xrpc-server/dist/auth.js'
import { SpacePermission } from '/app/packages/oauth/oauth-scopes/dist/index.js'
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
const STATE_FILE = '/data/grouphost-state.json'
const log = (...a) => console.log(new Date().toISOString(), '[host]', ...a)
// The host's own calls to its PDS (creating and seeding a group) carry this, so the gates below
// let them through. It never leaves the process.
const INTERNAL = crypto.randomBytes(32).toString('hex')

const NS = 'group.opensocial'
const META = `${NS}.meta`
const MEMBERS = `${NS}.members`
const spaceUri = (did, type, skey = 'self') => `at://${did}/space/${type}/${skey}`

// ---- spike state (a real host keeps these in its own tables) ----
const tickets = new Map() // id -> { groupDid, personDid, exp }
const pending = new Map() // signin state -> { requestUri, clientId, mode, groupDid? }
const consent = new Map() // requestUri -> what the host's consent page shows
const requestPerson = new Map() // OAuth request id -> person DID, set when the ticket is minted
const codePerson = new Map() // authorization code -> person DID, set when the request is authorized
const authorizedBy = [] // { groupDid, personDid, at }: which person each group sign-in stands for
const accessCalls = [] // every checkUserAccess the PDS made
const narrowings = [] // every per-request cut, newest last (capped)
const refusals = [] // every write or simplespace change the host refused

// Which person authorized each token. Kept on the data volume so a restart does not turn every
// mapped token into an unmapped one (an unmapped token is cut to "atproto").
const saved = fs.existsSync(STATE_FILE) ? JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) : {}
const tokenPerson = new Map(Object.entries(saved.tokenPerson ?? {})) // tokenId -> { groupDid, personDid|null, via }
const persist = () => fs.writeFileSync(STATE_FILE, JSON.stringify({ tokenPerson: Object.fromEntries(tokenPerson) }))

// ---- (a) the PDS as a library ----
const env = readEnv()
const cfg = envToCfg(env)
const secrets = envToSecrets(env)
const pds = await PDS.create(cfg, secrets)
const provider = pds.ctx.oauthProvider
log('PDS.create ok; oauthProvider', provider ? 'present' : 'absent', '; service did', cfg.service.did)

// ---- (b) sign-in by ticket: wrap the provider's account store instance (no file patched) ----
// The provider uses one store object for accounts, requests and tokens.
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
    if (!t || t.exp < Date.now() || t.groupDid !== groupDid) {
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

// ---- (d) roles from the group's records ----
// Reads the group's own space repos straight from the actor store: the host is their PDS.
async function readGroup(groupDid) {
  return pds.ctx.actorStore.read(groupDid, async (actor) => {
    const list = async (space, collection) =>
      (await actor.space.listRecords(space, { limit: 100, collection })).map((r) => ({ rkey: r.rkey, value: r.value }))
    const members = spaceUri(groupDid, MEMBERS)
    const spaces = await actor.space.listSpaces({ limit: 100, authority: groupDid })
    const accessRecords = []
    for (const s of spaces) {
      const [, , , , type, skey] = s.uri.split('/') // at://<did>/space/<type>/<skey>
      const rec = (await list(s.uri, `${NS}.access`)).find((r) => r.rkey === 'self')
      if (rec) accessRecords.push({ space: { uri: s.uri, type, skey }, value: rec.value })
    }
    return {
      roles: await list(members, `${NS}.role`),
      memberships: await list(members, `${NS}.membership`),
      permissions: (await list(members, `${NS}.permissions`)).find((r) => r.rkey === 'self')?.value ?? null,
      access: accessRecords,
      spaces: spaces.map((s) => s.uri),
    }
  })
}

// A space grant from an `access` record applies only to that space, so it is pinned to it.
function pinToSpace(scope, space, groupDid) {
  const sp = SpacePermission.fromString(scope)
  if (!sp) return null // only space: scopes mean anything in an access record
  if (sp.type !== '*' && sp.type !== space.type) return null
  if (sp.authority !== '*' && sp.authority !== groupDid) return null
  if (sp.skey !== '*' && sp.skey !== space.skey) return null
  return new SpacePermission(space.type, groupDid, space.skey, sp.collection, sp.action, sp.manage).toString()
}

// The scopes a person's current roles grant on the group DID, expanded the same way the PDS
// expands a token's scope (permission sets, bare space types, authority=self).
async function grantsFor(groupDid, personDid) {
  const g = await readGroup(groupDid)
  const declared = new Set(g.roles.map((r) => r.rkey))
  const m = g.memberships.find((r) => r.rkey === personDid && r.value?.member === personDid)
  const roles = (m?.value.roles ?? []).filter((r) => declared.has(r))
  const raw = []
  const assignable = new Set()
  for (const grant of g.permissions?.grants ?? []) {
    if (!roles.includes(grant.role)) continue
    for (const s of grant.scopes ?? []) raw.push({ scope: s, space: null })
    for (const a of grant.assignable ?? []) assignable.add(a)
  }
  for (const { space, value } of g.access) {
    for (const grant of value.grants ?? []) {
      if (!roles.includes(grant.role)) continue
      for (const s of grant.scopes ?? []) raw.push({ scope: s, space })
    }
  }
  const strings = new Set()
  const spaces = []
  const bySpace = new Map() // space uri -> the access-record grants pinned to it
  for (const { scope, space } of raw) {
    let parts
    try {
      parts = (await provider.lexiconManager.buildTokenScope(scope, groupDid)).split(' ')
    } catch (err) {
      log('grant scope does not expand, skipped', { scope, err: err.message })
      continue
    }
    for (const p of parts) {
      const s = space ? pinToSpace(p, space, groupDid) : p
      if (!s) continue
      strings.add(s)
      const sp = SpacePermission.fromString(s)
      if (sp) spaces.push(sp)
      if (sp && space) bySpace.set(space.uri, [...(bySpace.get(space.uri) ?? []), sp])
    }
  }
  return { roles, assignable: [...assignable], strings, spaces, bySpace }
}

// Whether one expanded scope is wholly inside what the grants allow. Space scopes are split into
// single operations and each must match some grant; other scopes must be granted as written.
function covered(item, grants) {
  if (item === 'atproto') return true
  const sp = SpacePermission.fromString(item)
  if (!sp) return grants.strings.has(item)
  const ref = { type: sp.type, authority: sp.authority, skey: sp.skey }
  const ops = []
  for (const action of sp.action) {
    if (action === 'read' || action === 'read_self') ops.push({ ...ref, action })
    else for (const collection of sp.collection ?? []) ops.push({ ...ref, action, collection })
  }
  for (const manage of sp.manage ?? []) ops.push({ ...ref, manage })
  return ops.length > 0 && ops.every((op) => grants.spaces.some((g) => g.matches(op)))
}

// At authorize: keep each requested scope (as the app wrote it, permission sets included) only
// if everything it expands to is granted.
async function narrowRequested(scope, grants, groupDid) {
  const kept = []
  const dropped = []
  for (const item of (scope ?? '').split(' ').filter(Boolean)) {
    let parts
    try {
      parts = item === 'atproto' ? ['atproto'] : (await provider.lexiconManager.buildTokenScope(item, groupDid)).split(' ')
    } catch {
      parts = null
    }
    ;(parts && parts.every((p) => covered(p, grants)) ? kept : dropped).push(item)
  }
  if (!kept.includes('atproto')) kept.unshift('atproto')
  return { kept, dropped }
}

// ---- (d) tie each token to the person who authorized it ----
const reqId = (requestUri) => requestUri.replace(/^urn:ietf:params:oauth:request_uri:/, '')

// The provider hands one hooks object to all its managers, so wrapping a hook here is seen by
// the request manager. The PDS's own hook (an event) still runs.
const hooks = provider.hooks
const origOnAuthorized = hooks.onAuthorized
hooks.onAuthorized = async (data) => {
  await origOnAuthorized?.call(null, data)
  const personDid = requestPerson.get(data.requestId)
  requestPerson.delete(data.requestId)
  if (!personDid) return
  // The request store holds the code by now: setAuthorized writes it before calling this hook.
  const req = await store.readRequest(data.requestId)
  if (req?.code) codePerson.set(req.code, personDid)
}

const origCreateToken = store.createToken.bind(store)
store.createToken = async (tokenId, data, refreshToken) => {
  await origCreateToken(tokenId, data, refreshToken)
  const personDid = codePerson.get(data.code) ?? null
  codePerson.delete(data.code)
  tokenPerson.set(tokenId, { groupDid: data.did, personDid, via: personDid ? 'person' : 'direct' })
  persist()
  log('token created', { group: data.did, personDid, scope: data.scope })
}

const origRotateToken = store.rotateToken.bind(store)
store.rotateToken = async (tokenId, newTokenId, newRefreshToken, newData) => {
  await origRotateToken(tokenId, newTokenId, newRefreshToken, newData)
  const entry = tokenPerson.get(tokenId)
  tokenPerson.delete(tokenId)
  if (entry) tokenPerson.set(newTokenId, entry)
  persist()
  log('token rotated', { mapped: !!entry })
}

// In stateful mode the provider reloads each token's claims, scope included, from its store on
// every request. Cutting the scope here applies the person's current roles to every request.
const tm = provider.tokenManager
const origLoadClaims = tm.loadTokenClaims.bind(tm)
tm.loadTokenClaims = async (tokenType, payload) => {
  const claims = await origLoadClaims(tokenType, payload)
  const entry = tokenPerson.get(claims.jti)
  let scope = claims.scope
  if (!entry) scope = 'atproto' // not issued through this host's sign-in, or lost: grants nothing
  else if (entry.personDid) {
    const grants = await grantsFor(claims.sub, entry.personDid)
    scope = (claims.scope ?? '').split(' ').filter((s) => covered(s, grants)).join(' ') || 'atproto'
  }
  if (scope !== claims.scope) {
    narrowings.push({ at: new Date().toISOString(), group: claims.sub, personDid: entry?.personDid ?? null, from: claims.scope, to: scope })
    if (narrowings.length > 50) narrowings.shift()
  }
  return { ...claims, scope }
}

// ---- (e) prompt=create: make the group and write its starting records ----
async function xrpc(nsid, body, jwt) {
  const res = await fetch(`${LOOPBACK}/xrpc/${nsid}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-grouphost-internal': INTERNAL, ...(jwt ? { authorization: `Bearer ${jwt}` } : {}) },
    body: JSON.stringify(body),
  })
  const json = await res.json().catch(() => null)
  if (!res.ok) throw new Error(`${nsid} ${res.status} ${json?.error ?? ''} ${json?.message ?? ''}`)
  return json
}

// A session for a group the host holds, with no password: the PDS's account manager mints it.
// For the host's own acts as the group (setup here, join approval later).
async function groupJwt(did) {
  return (await pds.ctx.accountManager.createSession(did, null)).accessJwt
}

async function createGroup({ label, displayName, creatorDid }) {
  const handle = `${label}${cfg.identity.serviceHandleDomains[0]}`
  // The PDS's createAccount needs a password. This one is random, used for the seeding calls
  // below, and dropped: nobody ever sees or holds it. The product should create the account
  // with no password at all.
  const password = crypto.randomBytes(32).toString('base64url')
  const acct = await xrpc('com.atproto.server.createAccount', { handle, email: `${label}@groups.invalid`, password })
  const did = acct.did
  const jwt = acct.accessJwt
  const MA = { $type: 'com.atproto.simplespace.defs#managingAppPolicy', managingApp: MANAGING_APP }
  const now = new Date().toISOString()
  for (const type of [META, MEMBERS]) {
    await xrpc('com.atproto.simplespace.createSpace', { spaceType: type, skey: 'self', readPolicy: MA, writePolicy: MA, appAccess: { $type: 'com.atproto.simplespace.defs#open' } }, jwt)
  }
  const put = (type, collection, rkey, record) =>
    xrpc('com.atproto.space.createRecord', { space: spaceUri(did, type), repo: did, collection, rkey, record: { $type: collection, ...record } }, jwt)
  // Roles first: a membership may name only declared roles.
  await put(MEMBERS, `${NS}.role`, 'admin', { displayName: 'Admin', description: 'Runs the group.' })
  await put(MEMBERS, `${NS}.role`, 'member', { displayName: 'Member', default: true })
  await put(META, `${NS}.access`, 'self', {
    public: false,
    grants: [
      { role: 'admin', scopes: [`space:${META}?collection=*`] },
      { role: 'member', scopes: [`space:${META}?action=read`] },
    ],
  })
  await put(MEMBERS, `${NS}.access`, 'self', {
    grants: [
      { role: 'admin', scopes: [`space:${MEMBERS}?collection=*`] },
      { role: 'member', scopes: [`space:${MEMBERS}?action=read`] },
    ],
  })
  await put(META, `${NS}.profile`, 'self', { displayName, joinPolicy: 'approval' })
  await put(MEMBERS, `${NS}.permissions`, 'self', {
    grants: [
      {
        role: 'admin',
        scopes: [
          'space:*?action=read_self&manage=create&manage=delete',
          // Labels in any group space, write only: with no action a space scope also reads.
          'space:*?collection=com.atproto.label.label&action=create&action=update&action=delete',
          `rpc:${NS}.listJoinRequests?aud=*`,
          `rpc:${NS}.denyJoinRequest?aud=*`,
        ],
        assignable: ['admin', 'member'],
      },
      { role: 'member', scopes: [], assignable: [] },
    ],
  })
  await put(MEMBERS, `${NS}.membership`, creatorDid, { member: creatorDid, roles: ['admin'], createdAt: now })
  log('group created', { did, handle, creatorDid })
  return { did, handle }
}

// ---- sign-in through the person's own PDS ----
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

async function groupDidOf(hint) {
  if (!hint) return undefined
  if (hint.startsWith('did:')) return (await pds.ctx.accountManager.getAccount(hint)) ? hint : undefined
  return (await pds.ctx.accountManager.getAccount(hint))?.did
}
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)

const outer = express()

// did:web for the host itself, naming the endpoint the PDS calls for checkUserAccess.
outer.get('/.well-known/did.json', (req, res) => {
  res.json({
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: HOST_DID,
    service: [{ id: '#group_host', type: 'GroupHost', serviceEndpoint: PUBLIC_URL }],
  })
})

// Every request for a group, and every prompt=create, signs in through the person's own PDS.
// There is no way past this to the PDS's own sign-in page for a group.
outer.get('/oauth/authorize', async (req, res, next) => {
  try {
    const { request_uri: requestUri, client_id: clientId } = req.query
    if (req.query.gh === 'ticket') return res.type('html').send(ticketPage(requestUri))
    if (!requestUri) return next()
    const data = await store.readRequest(reqId(String(requestUri)))
    const p = data?.parameters ?? {}
    const create = p.prompt === 'create'
    const groupDid = create ? undefined : await groupDidOf(p.login_hint)
    if (!create && !groupDid) return next() // not a group sign-in: the PDS's own page
    const state = crypto.randomBytes(12).toString('hex')
    pending.set(state, { requestUri: String(requestUri), clientId: String(clientId), mode: create ? 'create' : 'act', groupDid })
    res.redirect(`${LOOPBACK}/signin/start?state=${state}`)
  } catch (err) {
    next(err)
  }
})

// Ask who you are (your own handle), and for a new group its name, then OAuth to your own PDS.
outer.get('/signin/start', async (req, res, next) => {
  try {
    const p = pending.get(req.query.state)
    if (!p) return res.status(400).send('unknown sign-in')
    if (!req.query.handle) {
      const createFields =
        p.mode === 'create'
          ? `<p>New group name (handle): <input name=label placeholder="mygroup"></p><p>Display name: <input name=displayName placeholder="My Group"></p>`
          : `<p>Act as group <code>${esc(p.groupDid)}</code>.</p>`
      return res.type('html').send(`<!doctype html><title>${p.mode === 'create' ? 'Create a group' : 'Sign in to act as the group'}</title>
<form method=get><input type=hidden name=state value="${esc(req.query.state)}">${createFields}
<p>Sign in with your own account: <input name=handle placeholder="you.example.com"></p><button>Continue</button></form>`)
    }
    if (p.mode === 'create') {
      p.label = String(req.query.label ?? '').toLowerCase()
      p.displayName = String(req.query.displayName ?? p.label)
      if (!/^[a-z0-9][a-z0-9-]{2,30}$/.test(p.label)) return res.status(400).send('group name: 3 to 31 letters, digits or dashes')
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
    // Who may create a group is the host's call; the spike lets anyone signed in.
    const group = p.mode === 'create' ? await createGroup({ label: p.label, displayName: p.displayName, creatorDid: personDid }) : { did: p.groupDid }
    const grants = await grantsFor(group.did, personDid)
    log('person signed in through own PDS', { personDid, groupDid: group.did, mode: p.mode, roles: grants.roles })
    if (!grants.roles.length) return res.status(403).send(`You (${personDid}) hold no role in ${group.did}`)

    // Offer only what the roles grant: rewrite the pending request's scope before consent.
    const id = reqId(p.requestUri)
    const data = await store.readRequest(id)
    const { kept, dropped } = await narrowRequested(data.parameters.scope, grants, group.did)
    const { prompt, ...rest } = data.parameters
    await store.updateRequest(id, { parameters: { ...rest, scope: kept.join(' '), login_hint: group.did } })
    requestPerson.set(id, personDid)
    const groupHandle = group.handle ?? (await pds.ctx.accountManager.getAccount(group.did))?.handle
    consent.set(p.requestUri, { groupDid: group.did, groupHandle, personDid, roles: grants.roles, clientId: p.clientId, kept, dropped, created: p.mode === 'create' })
    log('scopes offered', { personDid, roles: grants.roles, kept, dropped })

    const t = crypto.randomBytes(24).toString('base64url')
    tickets.set(t, { groupDid: group.did, personDid, exp: Date.now() + 120_000 })
    // The callback is on the loopback origin, so a cookie would not reach the host's origin. The
    // ticket rides the URL fragment instead: never sent to a server, never in a referrer.
    const q = new URLSearchParams({ request_uri: p.requestUri, client_id: p.clientId, gh: 'ticket' })
    const frag = new URLSearchParams({ t, g: group.did })
    res.redirect(`${PUBLIC_URL}/oauth/authorize?${q}#${frag}`)
  } catch (err) {
    next(err)
  }
})

// Served AT /oauth/authorize so the provider's API accepts the calls (it requires the authorize
// page as referrer, same-origin fetch and the CSRF cookie/header pair). The ticket sign-in is
// not remembered (remember: false): the provider returns a token good only for this request on
// this device, the device keeps no group session, and the host's own consent uses that token.
function ticketPage(requestUri) {
  const c = consent.get(requestUri)
  if (!c) return '<!doctype html><title>Unknown sign-in</title><p>Unknown sign-in.</p>'
  const li = (xs) => xs.map((s) => `<li><code>${esc(s)}</code></li>`).join('')
  return `<!doctype html><title>Act for ${esc(c.groupHandle)}</title>
<main id=consent hidden>
<h1>Act for the group @${esc(c.groupHandle)}</h1>
<p>You are signed in as <code>${esc(c.personDid)}</code>, holding the role${c.roles.length > 1 ? 's' : ''} ${c.roles.map(esc).join(', ')} in this group${c.created ? ', which you just created' : ''}.</p>
<p>The app <code>${esc(c.clientId)}</code> will act for the group, not for you, with:</p><ul id=kept>${li(c.kept)}</ul>
${c.dropped.length ? `<p>Not offered, because your roles do not grant it:</p><ul id=dropped>${li(c.dropped)}</ul>` : ''}
<button id=go>Authorize</button>
</main><p id=s>Signing you in as the group...</p>
<script>
(async () => {
  const get = (n) => (document.cookie.split('; ').find((c) => c.startsWith(n + '=')) || '').slice(n.length + 1)
  let csrf = get('csrf-token')
  if (!csrf) { csrf = crypto.randomUUID().replace(/-/g, '').slice(0, 24); document.cookie = 'csrf-token=' + csrf + '; path=/; secure; samesite=lax' }
  const h = new URLSearchParams(location.hash.slice(1)), ticket = h.get('t'), group = h.get('g')
  history.replaceState(null, '', location.pathname + location.search)
  const api = (p, body, bearer) => fetch('/@atproto/oauth-provider/~api/' + p, {
    method: 'POST', mode: 'same-origin', credentials: 'same-origin',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf, ...(bearer ? { authorization: 'Bearer ' + bearer } : {}) },
    body: JSON.stringify(body),
  })
  const r = await api('sign-in', { locale: 'en', username: group, password: 'ticket:' + ticket, remember: false })
  if (!r.ok) { document.getElementById('s').textContent = 'sign-in ' + r.status; return }
  const { ephemeralToken } = await r.json()
  document.getElementById('s').hidden = true
  document.getElementById('consent').hidden = false
  document.getElementById('go').onclick = async () => {
    const c = await api('consent', { did: group }, ephemeralToken)
    const j = await c.json().catch(() => ({}))
    if (j.url) location.replace(j.url)
    else document.body.textContent = 'consent ' + c.status + ' ' + JSON.stringify(j)
  }
})()
</script>`
}

// ---- (f) enforcement from the group's records ----

// Who is calling, from the Authorization header. The token is only decoded here, not verified:
// the PDS verifies the same header right after, so a forged token is refused there. Decoding
// is enough to find the token's person in the host's table.
function callerOf(req) {
  if (req.headers['x-grouphost-internal'] === INTERNAL) return { internal: true }
  const m = /^(DPoP|Bearer) (\S+)$/.exec(req.headers.authorization || '')
  if (!m) return { none: true }
  let payload
  try {
    payload = JSON.parse(Buffer.from(m[2].split('.')[1], 'base64url').toString())
  } catch {
    return { none: true }
  }
  if (payload.jti && payload.client_id) {
    const e = tokenPerson.get(payload.jti)
    return { oauth: true, sub: payload.sub, mapped: !!e, personDid: e?.personDid ?? null }
  }
  return { legacy: true, sub: payload.sub } // a password session: the group acting as itself
}

const isHosted = async (did) => !!(did && (await pds.ctx.accountManager.getAccount(did)))
const refuse = (error, message) => ({ error, message })
const parseSpace = (uri) => {
  const [, , authority, , type, skey] = String(uri ?? '').split('/') // at://<did>/space/<type>/<skey>
  return { authority, type, skey }
}

// Whether a person may read a group space (and so be tracked as a writer in it): the space's
// `access` record is public, or one of their roles is granted `read` there. Only `access` grants
// count here; `permissions` grants are about the group session's own scopes (proposal.md:52-53).
async function decideAccess(spaceUri, user, kind) {
  const { authority } = parseSpace(spaceUri)
  if (user === authority) return { authorized: true, why: 'the group itself' }
  const g = await readGroup(authority)
  const acc = g.access.find((a) => a.space.uri === spaceUri)
  if (!acc) return { authorized: false, why: 'no access record' }
  if (kind === 'read' && acc.value.public === true) return { authorized: true, why: 'public' }
  const grants = await grantsFor(authority, user)
  const s = acc.space
  const reads = (grants.bySpace.get(spaceUri) ?? []).some((p) => p.matches({ type: s.type, authority, skey: s.skey, action: 'read' }))
  return { authorized: reads, why: reads ? `roles ${grants.roles.join(',')} grant read` : grants.roles.length ? `roles ${grants.roles.join(',')} do not grant read` : 'no roles' }
}

const COLLECTION = { membership: `${NS}.membership`, role: `${NS}.role`, access: `${NS}.access`, permissions: `${NS}.permissions` }
const MEMBERS_ONLY = new Set([COLLECTION.membership, COLLECTION.role, COLLECTION.permissions])

// Every scope in a grant has to expand, the way the PDS would expand it in a token.
async function badScopes(scopes, groupDid) {
  const bad = []
  for (const sc of scopes ?? []) {
    try {
      await provider.lexiconManager.buildTokenScope(sc, groupDid)
    } catch {
      bad.push(sc)
    }
  }
  return bad
}

// The checks a group write must pass before the PDS takes it (proposal.md:46, :67; the record
// lexicons). `ops` is one write, or every write of an applyWrites, checked in order against the
// state the earlier ones leave. Returns a refusal, or null.
async function checkGroupWrites(groupDid, space, ops, caller) {
  if (caller.oauth && !caller.mapped) return refuse('UnknownSession', 'this session was not issued through the group host')
  const { authority, type } = parseSpace(space)
  if (authority !== groupDid) return refuse('InvalidSpace', `${space} is not a space of ${groupDid}`)
  const g = await readGroup(groupDid)
  if (!g.access.some((a) => a.space.uri === space)) return refuse('UndeclaredSpace', `${space} has no access record, so the group does not write in it`)
  const roles = new Set(g.roles.map((r) => r.rkey))
  const memberships = new Map(g.memberships.map((r) => [r.rkey, r.value]))
  // The group DID itself holds every permission (proposal.md:44); a person holds their roles'.
  const assignable = caller.personDid ? new Set((await grantsFor(groupDid, caller.personDid)).assignable) : null
  for (const op of ops) {
    if (MEMBERS_ONLY.has(op.collection) && type !== MEMBERS) return refuse('WrongSpace', `${op.collection} belongs in the members space`)
    if (op.collection === COLLECTION.role) {
      if (op.action === 'delete') {
        const users = [...memberships.values()].filter((v) => v.roles?.includes(op.rkey))
        if (users.length) return refuse('RoleInUse', `role ${op.rkey} is held by ${users.length} member(s)`)
        roles.delete(op.rkey)
      } else roles.add(op.rkey)
    }
    if (op.collection === COLLECTION.membership) {
      const old = memberships.get(op.rkey)
      const oldRoles = old?.roles ?? []
      let added = []
      let removed = []
      if (op.action === 'delete') {
        removed = oldRoles // ejecting: every current role of the member
        memberships.delete(op.rkey)
      } else {
        const v = op.value ?? {}
        if (v.member !== op.rkey) return refuse('InvalidMembership', 'a membership record key is the member DID')
        if (!Array.isArray(v.roles) || new Set(v.roles).size !== v.roles.length) return refuse('InvalidMembership', 'roles must be a list of distinct role ids')
        const unknown = v.roles.filter((r) => !roles.has(r))
        if (unknown.length) return refuse('UnknownRole', `the group declares no role ${unknown.join(', ')}`)
        added = v.roles.filter((r) => !oldRoles.includes(r))
        removed = oldRoles.filter((r) => !v.roles.includes(r))
        memberships.set(op.rkey, v)
      }
      if (assignable) {
        const not = [...added, ...removed].filter((r) => !assignable.has(r))
        if (not.length) return refuse('NotAssignable', `your roles cannot assign or remove ${[...new Set(not)].join(', ')}`)
      }
    }
    if ((op.collection === COLLECTION.access || op.collection === COLLECTION.permissions) && op.action !== 'delete') {
      const grants = op.value?.grants ?? []
      const named = grants.map((gr) => gr.role)
      if (new Set(named).size !== named.length) return refuse('InvalidGrants', 'at most one grant per role')
      const unknown = [...named, ...grants.flatMap((gr) => gr.assignable ?? [])].filter((r) => !roles.has(r))
      if (unknown.length) return refuse('UnknownRole', `the group declares no role ${[...new Set(unknown)].join(', ')}`)
      const bad = await badScopes(grants.flatMap((gr) => gr.scopes ?? []), groupDid)
      if (bad.length) return refuse('InvalidScope', `scopes that do not resolve: ${bad.join(' ')}`)
    }
  }
  return null
}

// Group writes through com.atproto.space.*: checked here, ahead of the PDS. The JSON body is
// parsed once, whatever its content type, so the gate cannot be skipped by mislabeling it; the
// PDS's own body parser sees it is done and uses it, and still refuses a non-JSON content type.
const SPACE_WRITES = ['createRecord', 'putRecord', 'deleteRecord', 'applyWrites']
outer.post(
  SPACE_WRITES.map((n) => `/xrpc/com.atproto.space.${n}`),
  express.json({ limit: '5mb', type: () => true }),
  async (req, res, next) => {
    try {
      const body = req.body ?? {}
      if (!(await isHosted(body.repo))) return next()
      const caller = callerOf(req)
      if (caller.internal) return next()
      if (caller.sub && caller.sub !== body.repo) return next() // the PDS refuses a write to another repo
      const nsid = req.path.split('.').pop()
      const ops =
        nsid === 'applyWrites'
          ? (body.writes ?? []).map((w) => ({ action: String(w.$type ?? '').split('#')[1], collection: w.collection, rkey: w.rkey, value: w.value }))
          : [{ action: { createRecord: 'create', putRecord: 'put', deleteRecord: 'delete' }[nsid], collection: body.collection, rkey: body.rkey, value: body.record }]
      const refusal = await checkGroupWrites(body.repo, body.space, ops, caller)
      if (refusal) {
        refusals.push({ at: new Date().toISOString(), nsid, group: body.repo, space: body.space, personDid: caller.personDid ?? null, ...refusal })
        log('group write refused', { nsid, personDid: caller.personDid ?? null, ...refusal })
        return res.status(403).json(refusal)
      }
      next()
    } catch (err) {
      next(err)
    }
  },
)

// Nobody reconfigures a group space through simplespace, the group's own sessions included: a
// space's policy follows its `access` record, and only the host changes it.
const SIMPLESPACE_CHANGES = ['createSpace', 'updateSpace', 'deleteSpace', 'putMember', 'removeMember']
outer.post(
  SIMPLESPACE_CHANGES.map((n) => `/xrpc/com.atproto.simplespace.${n}`),
  express.json({ limit: '1mb', type: () => true }),
  async (req, res, next) => {
    try {
      const caller = callerOf(req)
      if (caller.internal) return next()
      const authority = req.body?.space ? parseSpace(req.body.space).authority : caller.sub
      if (await isHosted(authority)) {
        const nsid = req.path.split('.').pop()
        const refusal = refuse('GroupSpaceManaged', `group spaces change only through the group host, not ${nsid}`)
        refusals.push({ at: new Date().toISOString(), nsid, group: authority, personDid: caller.personDid ?? null, ...refusal })
        log('simplespace change refused', { nsid, authority })
        return res.status(403).json(refusal)
      }
      next()
    } catch (err) {
      next(err)
    }
  },
)

// The managing app's answer, now from the records.
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
  let decision = { authorized: false, why: 'caller is not the space authority' }
  if (iss === parseSpace(space).authority) decision = await decideAccess(String(space), String(user), String(kind))
  accessCalls.push({ space, user, kind, clientId: clientId ?? null, iss, ...decision, at: new Date().toISOString() })
  log('checkUserAccess', { space, user, kind, ...decision })
  res.json({ authorized: decision.authorized })
})

// ---- spike-only routes (no auth: devnet only, bound behind the devnet's nginx) ----
outer.use('/spike', express.json())
outer.get('/spike/state', async (req, res) => {
  const group = req.query.group
  const deviceAccounts = group ? (await store.listDeviceAccounts({ did: group })).length : null
  const grants = group && req.query.person ? await grantsFor(group, req.query.person) : null
  res.json({
    authorizedBy,
    accessCalls: accessCalls.filter((c) => !group || String(c.space).includes(group)),
    narrowings,
    refusals: refusals.filter((r) => !group || r.group === group),
    managingApp: MANAGING_APP,
    tokens: [...tokenPerson.entries()].filter(([, v]) => !group || v.groupDid === group).map(([id, v]) => ({ id: id.slice(0, 8), ...v })),
    deviceAccounts,
    grants: grants && { roles: grants.roles, assignable: grants.assignable, scopes: [...grants.strings] },
  })
})
// A space of the group with no access record, for testing the undeclared-space refusal.
outer.post('/spike/bare-space', async (req, res, next) => {
  try {
    const { group, skey } = req.body
    const MA = { $type: 'com.atproto.simplespace.defs#managingAppPolicy', managingApp: MANAGING_APP }
    await xrpc('com.atproto.simplespace.createSpace', { spaceType: META, skey, readPolicy: MA, writePolicy: MA, appAccess: { $type: 'com.atproto.simplespace.defs#open' } }, await groupJwt(group))
    res.json({ space: spaceUri(group, META, skey) })
  } catch (err) {
    next(err)
  }
})

// ---- everything else: the PDS, unmodified ----
outer.use(pds.app)
pds.app = outer
await pds.start()
log('listening', cfg.service.port, 'as', PUBLIC_URL)
