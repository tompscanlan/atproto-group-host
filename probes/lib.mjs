// lib.mjs: what the probes share. They run on a snowglobe made from probes/snowglobe.yml, under
// `snowglobe run --app probes`, which hands them the settings below and makes Node trust the
// snowglobe's certificate. Passwords and tokens are never printed.
import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import path from 'node:path'
import { chromium } from 'playwright'
import { OAuthClient, MemoryStore } from '@atcute/oauth-node-client'
import {
  CompositeDidDocumentResolver,
  LocalActorResolver,
  PlcDidDocumentResolver,
  WebDidDocumentResolver,
  WellKnownHandleResolver,
} from '@atcute/identity-resolver'
const setting = (name) => {
  const v = process.env[name]
  if (!v) throw new Error(`${name} is not set: run the probe with snowglobe run --app probes (see the README)`)
  return v
}

export const HERE = path.dirname(new URL(import.meta.url).pathname)
// A run's screenshots go in a folder of their own, so no run writes over another's.
const SHOTS = path.join(HERE, 'shots', `${new Date().toISOString().replace(/[:.]/g, '-')}-${path.basename(process.argv[1] ?? 'run', '.mjs')}`)
// The host under test, and the spaces PDS the test people's own accounts are on.
export const HOST = setting('GROUP_HOST_URL')
export const ALPHA = setting('ALPHA_URL')
// The snowglobe's PLC directory. plc.directory is the real one, which has never heard of these DIDs.
export const PLC = setting('PLC_URL')
// The snowglobe's domain: every name in it ends with this.
export const DOMAIN = setting('SNOWGLOBE_DOMAIN')
// The host's container, for the probes that read its log, look in its data or restart it.
export const HOST_CONTAINER = setting('HOST_CONTAINER')
// A group's handle ending: the host's own name, which the host gives its PDS as the service
// handle domain.
export const GROUP_DOMAIN = process.env.GROUP_HANDLE_DOMAIN ?? `.${new URL(HOST).hostname}`

// Chromium, for the sign-in pages. It does not trust the snowglobe's CA, so the browser ignores
// certificate errors; Node's own requests still check certificates. A container that runs as root
// cannot use Chromium's sandbox (CHROMIUM_NO_SANDBOX=1 there).
const launchBrowser = () => chromium.launch(process.env.CHROMIUM_NO_SANDBOX ? { args: ['--no-sandbox'] } : {})
const newPage = async (browser) => (await browser.newContext({ ignoreHTTPSErrors: true })).newPage()
export const META = 'group.opensocial.meta'
export const MEMBERS = 'group.opensocial.members'
export const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z')
export const log = (...a) => console.log(...a)
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
export const spaceUri = (did, type, skey = 'self') => `at://${did}/space/${type}/${skey}`

export const verdicts = []
export const verdict = (id, ok, what) => {
  verdicts.push({ id, ok, what })
  log(`\n### ${id}: ${ok ? 'PASS' : 'FAIL'} - ${what}\n`)
}
export function summary() {
  log('\n## Summary\n')
  for (const v of verdicts) log(`- ${v.id} ${v.ok ? 'PASS' : 'FAIL'}: ${v.what}`)
  log(`\n${verdicts.filter((v) => v.ok).length}/${verdicts.length} pass`)
}

// The two test people, alice and bob, with accounts on the spaces PDS.
const person = (who) => {
  const W = who.toUpperCase()
  return { who, handle: setting(`${W}_HANDLE`), password: setting(`${W}_PASSWORD`), did: setting(`${W}_DID`) }
}
export const alice = person('alice')
export const bob = person('bob')

// GET https://<handle>/.well-known/atproto-did as any client would, certificate check included.
// The name is sent where the PDS's name goes, the snowglobe's front door, which picks the server by
// name, so a handle made a moment ago needs nothing new from DNS.
const viaNginx = (_name, opts, cb) => dns.lookup(new URL(ALPHA).hostname, opts, cb)
export const wellKnownDid = (handle) =>
  new Promise((resolve) => {
    https
      .get({ hostname: handle, path: '/.well-known/atproto-did', lookup: viaNginx }, (res) => {
        let body = ''
        res.on('data', (c) => (body += c))
        res.on('end', () => resolve({ status: res.statusCode, body: body.trim() }))
      })
      .on('error', (e) => resolve({ status: 0, body: e.code ?? e.message }))
  })

// The host's test routes take the PDS's admin login. The probes read the password from the host's
// container, where the snowglobe set it, and never print it.
let adminLogin
const admin = () => {
  adminLogin ??= execFileSync('docker', ['exec', HOST_CONTAINER, 'printenv', 'PDS_ADMIN_PASSWORD'], { encoding: 'utf8' }).trim()
  return `Basic ${Buffer.from(`admin:${adminLogin}`).toString('base64')}`
}
export const state = async (q) => (await fetch(`${HOST}/test/state?${new URLSearchParams(q)}`, { headers: { authorization: admin() } })).json()
export const testRoute = async (p, body) =>
  (await fetch(`${HOST}/test/${p}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: admin() }, body: JSON.stringify(body) })).json()

const redact = (v) => JSON.stringify(v)?.replace(/("(?:token|accessJwt|refreshJwt|credential)"\s*:\s*")[^"]+"/g, '$1<redacted>"')
const parse = (text) => {
  try {
    return JSON.parse(text)
  } catch {
    return text.slice(0, 200)
  }
}

// ---------- the app: an OAuth client of the host, one per person ----------
const actorResolver = new LocalActorResolver({
  handleResolver: new WellKnownHandleResolver(),
  didDocumentResolver: new CompositeDidDocumentResolver({ methods: { plc: new PlcDidDocumentResolver({ apiUrl: PLC }), web: new WebDidDocumentResolver() } }),
})
const CB_PORT = 39418
const REDIRECT = `http://127.0.0.1:${CB_PORT}/cb`
// A client's session store is keyed by the account, and every session here is for the same
// group DID, so each person gets their own client.
const newApp = (scopes) =>
  new OAuthClient({
    metadata: { redirect_uris: [REDIRECT], scope: scopes },
    actorResolver,
    stores: { sessions: new MemoryStore(), states: new MemoryStore({ ttl: 600_000 }) },
  })

// One trip through the browser: the app asks the host, the person signs in at their own PDS,
// and the host's consent page is read and approved. `hints` go on the authorization URL the
// browser opens, as an app puts them (gh_name, gh_person); the start page's fields are read into
// `start` before anything is typed, and `stopAtStart` ends the trip there. `refuseOwn` presses
// Deny access on the person's own PDS instead, and the trip ends at whatever the app is sent back.
export async function groupSignIn(person, { create, groupDid, label: shot, scopes, hints, stopAtStart, refuseOwn }) {
  const app = newApp(scopes)
  const { url } = await app.authorize({
    target: create ? { type: 'pds', serviceUrl: HOST } : { type: 'account', identifier: groupDid },
    scope: scopes.join(' '),
    ...(create ? { prompt: 'create' } : {}),
  })
  for (const [k, v] of Object.entries(hints ?? {})) url.searchParams.set(k, v)
  log(`- ${now()} app PAR at ${url.origin} (${create ? 'prompt=create' : 'group ' + groupDid}) ok${hints ? `; hints ${Object.keys(hints).join(', ')}` : ''}`)
  let cbUrl = null
  const server = http.createServer((rq, rs) => {
    cbUrl = `http://127.0.0.1:${CB_PORT}${rq.url}`
    rs.end('ok')
  })
  await new Promise((r) => server.listen(CB_PORT, '127.0.0.1', r))
  const browser = await launchBrowser()
  const typed = []
  const out = { ok: false, app, typed, kept: [], dropped: [], consentText: null, refused: [], displayNameFields: null, start: null, seen: [], keyPage: false }
  try {
    const p = await newPage(browser)
    p.on('request', (r) => out.seen.push(r.url().split('#')[0]))
    await p.goto(url.toString(), { waitUntil: 'load', timeout: 60000 })
    await p.waitForURL(/\/signin\/start/, { timeout: 30000 })
    // What the start page holds before anything is typed, and what markup it carries.
    const value = async (name) => ((await p.locator(`input[name=${name}]`).count()) ? await p.locator(`input[name=${name}]`).inputValue() : null)
    out.start = {
      label: await value('label'),
      handle: await value('handle'),
      inputs: await p.locator('input').count(),
      scripts: await p.locator('script').count(),
      images: await p.locator('img').count(),
      ran: await p.evaluate(() => window.__hinted ?? null),
    }
    log(`- ${now()} start page fields before typing: ${JSON.stringify(out.start)}`)
    if (stopAtStart) return out
    if (create) {
      // `create.refused`: addresses (or handles) the host should turn down on its own page, tried
      // first. Each comes back to the page with its reason, and the same sign-in carries on.
      for (const t of create.refused ?? []) {
        await p.fill('input[name=label]', t.label)
        await p.fill('input[name=handle]', t.handle ?? person.handle)
        await Promise.all([p.waitForEvent('framenavigated', { predicate: (f) => f === p.mainFrame(), timeout: 30000 }), p.click('button')])
        await p.waitForLoadState('load')
        const problem = p.locator('#problem')
        out.refused.push({
          ...t,
          onPage: /\/signin\/start/.test(p.url()),
          reason: (await problem.count()) ? await problem.getAttribute('data-reason') : null,
          text: (await problem.count()) ? await problem.innerText() : null,
        })
        log(`- ${now()} host page refused ${JSON.stringify(t)}: ${JSON.stringify(out.refused.at(-1))}`)
      }
      out.displayNameFields = await p.locator('input[name=displayName]').count()
      await p.fill('input[name=label]', create.label)
      typed.push({ origin: new URL(p.url()).origin, field: 'new group address' })
    }
    await p.fill('input[name=handle]', person.handle)
    typed.push({ origin: new URL(p.url()).origin, field: 'handle' })
    await p.click('button')
    await p.waitForURL((u) => u.host === new URL(ALPHA).host, { timeout: 30000 })
    await p.waitForSelector('input[name=password]', { timeout: 30000 })
    const user = p.locator('input[name=username]')
    if ((await user.count()) && (await user.isEditable()) && !(await user.inputValue())) await user.fill(person.handle)
    await p.fill('input[name=password]', person.password)
    typed.push({ origin: new URL(p.url()).origin, field: 'password (own account)' })
    await p.getByRole('button', { name: 'Sign in' }).click()
    for (let i = 0; i < 120 && !cbUrl; i++) {
      const origin = new URL(p.url()).origin
      // The recovery key page after a create holds the group's private recovery key. Nothing on
      // it is captured: no screenshot, no innerText, no HTML. A probe that checks the key passes
      // `create.onKey`, which gets the page; then Continue.
      if (origin === HOST && (await p.locator('#recovery').count().catch(() => 0))) {
        out.keyPage = true
        log(`- ${now()} recovery key page (not captured)`)
        if (create?.onKey) await create.onKey(p)
        await Promise.all([p.waitForEvent('framenavigated', { predicate: (f) => f === p.mainFrame(), timeout: 30000 }), p.click('#continue')])
        await p.waitForLoadState('load')
        continue
      }
      if (origin === HOST && (await p.locator('#consent').isVisible().catch(() => false))) {
        out.consentText = (await p.locator('#consent').innerText()).replace(/\s+/g, ' ')
        out.kept = await p.locator('#kept li').allInnerTexts()
        out.dropped = await p.locator('#dropped li').allInnerTexts()
        log(`- ${now()} host consent: ${out.consentText.slice(0, 900)}`)
        if (shot) {
          const file = path.join(SHOTS, `${shot}.png`)
          await p.screenshot({ path: file, fullPage: true })
          log(`- ${now()} screenshot ${path.relative(HERE, file)}`)
        }
        await p.click('#go')
        await p.waitForTimeout(1500)
        continue
      }
      const btn = p.getByRole('button', { name: /^(accept|authorize|allow)/i }).first()
      if (origin !== HOST && (await btn.isVisible().catch(() => false))) {
        log(`- ${now()} consent at ${origin} (own account, atproto only)${refuseOwn ? ': Deny access' : ''}`)
        if (refuseOwn) await p.getByRole('button', { name: /^deny/i }).first().click()
        else await btn.click()
        await p.waitForTimeout(1500)
        continue
      }
      const body = await p.locator('body').innerText().catch(() => '')
      if (/hold no role|Invalid ticket|error|consent \d/i.test(body) && !/Sign in/i.test(body)) {
        log(`- ${now()} page at ${p.url().slice(0, 80)} says: ${body.replace(/\s+/g, ' ').slice(0, 300)}`)
        break
      }
      await p.waitForTimeout(500)
    }
    log(`- fields typed: ${JSON.stringify(typed)}`)
    out.cbUrl = cbUrl
    const keyShown = await p.locator('#recovery').count().catch(() => 0)
    out.lastPage = { url: p.url().split('?')[0], body: keyShown ? '(the recovery key page, not read)' : (await p.locator('body').innerText().catch(() => '')).replace(/\s+/g, ' ').slice(0, 300) }
    if (!cbUrl || refuseOwn) return out
    const { session } = await app.callback(new URL(cbUrl).searchParams)
    return { ...out, ok: true, session }
  } finally {
    await browser.close()
    await new Promise((r) => server.close(r))
  }
}

const OWN_CB_PORT = 39419
const OWN_REDIRECT = `http://127.0.0.1:${OWN_CB_PORT}/cb`

// The person's own sign-in at their own PDS, with OAuth as an app signs them in: no host in
// the path. Returns the session and the scope their PDS granted.
export async function ownOAuth(person, scopes) {
  const app = new OAuthClient({
    metadata: { redirect_uris: [OWN_REDIRECT], scope: scopes.join(' ') },
    actorResolver,
    stores: { sessions: new MemoryStore(), states: new MemoryStore({ ttl: 600_000 }) },
  })
  const { url } = await app.authorize({ target: { type: 'account', identifier: person.handle }, scope: scopes.join(' ') })
  log(`- ${now()} PAR at ${url.origin} for ${person.who}, scope: ${scopes.join(' ')}`)
  let cbUrl = null
  const server = http.createServer((rq, rs) => {
    cbUrl = `http://127.0.0.1:${OWN_CB_PORT}${rq.url}`
    rs.end('ok')
  })
  await new Promise((r) => server.listen(OWN_CB_PORT, '127.0.0.1', r))
  const browser = await launchBrowser()
  try {
    const p = await newPage(browser)
    await p.goto(url.toString(), { waitUntil: 'load', timeout: 60000 })
    await p.waitForSelector('input[name=password]', { timeout: 30000 })
    const user = p.locator('input[name=username]')
    if ((await user.count()) && (await user.isEditable()) && !(await user.inputValue())) await user.fill(person.handle)
    await p.fill('input[name=password]', person.password)
    await p.getByRole('button', { name: 'Sign in' }).click()
    for (let i = 0; i < 120 && !cbUrl; i++) {
      const btn = p.getByRole('button', { name: /^(accept|authorize|allow)/i }).first()
      if (await btn.isVisible().catch(() => false)) {
        const text = (await p.locator('body').innerText().catch(() => '')).replace(/\s+/g, ' ')
        log(`- ${now()} consent at ${new URL(p.url()).origin}: ${text.slice(0, 400)}`)
        await btn.click()
        await p.waitForTimeout(1500)
        continue
      }
      await p.waitForTimeout(500)
    }
    if (!cbUrl) throw new Error(`no callback for ${person.who}`)
    const { session } = await app.callback(new URL(cbUrl).searchParams)
    const { scope } = await session.getTokenInfo(false)
    log(`- ${now()} ${person.who} signed in at ${ALPHA}; granted: ${scope}`)
    return { session, scope }
  } finally {
    await browser.close()
    await new Promise((r) => server.close(r))
  }
}

// A call through an app's OAuth session for the group.
export async function as(session, who, method, nsid, { params, body } = {}) {
  const qs = params ? `?${new URLSearchParams(params)}` : ''
  const res = await session.handle(`/xrpc/${nsid}${qs}`, {
    method,
    ...(body ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {}),
  })
  const parsed = parse(await res.text())
  log(`- ${now()} ${method} ${nsid}${params ? ' ' + JSON.stringify(params) : ''} (as ${who}) -> ${res.status} ${redact(parsed)?.slice(0, 300)}`)
  return { status: res.status, body: parsed }
}
export const listRecords = (s, who, group, type) =>
  as(s, who, 'GET', 'com.atproto.space.listRecords', { params: { space: spaceUri(group, type), repo: group, limit: '100' } })

// A plain XRPC call, for a person's own PDS with a password session.
export async function call(label, base, method, nsid, { params, body, headers = {} } = {}) {
  const qs = params ? `?${new URLSearchParams(params)}` : ''
  const res = await fetch(`${base}/xrpc/${nsid}${qs}`, {
    method,
    headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  })
  const parsed = parse(await res.text())
  log(`- ${now()} ${method} ${base}/xrpc/${nsid}${params ? ' ' + JSON.stringify(params) : ''} (auth: ${label}) -> ${res.status} ${redact(parsed)?.slice(0, 300)}`)
  return { status: res.status, body: parsed }
}
export async function ownSession(person) {
  const r = await call('none', ALPHA, 'POST', 'com.atproto.server.createSession', { body: { identifier: person.handle, password: person.password } })
  if (r.status !== 200) throw new Error(`createSession ${person.who} ${r.status}`)
  return { who: person.who, did: r.body.did, jwt: r.body.accessJwt, base: ALPHA }
}
export const asOwn = (s, method, nsid, opts = {}) =>
  call(`${s.who} own session`, s.base, method, nsid, { ...opts, headers: { ...(opts.headers || {}), authorization: `Bearer ${s.jwt}` } })

// ---------- RFC 9421 space credentials ----------
const b64 = (bytes) => Buffer.from(bytes).toString('base64')
const b58 = (bytes) => {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let n = BigInt('0x' + Buffer.from(bytes).toString('hex'))
  let out = ''
  while (n > 0n) {
    out = A[Number(n % 58n)] + out
    n /= 58n
  }
  for (const b of bytes) {
    if (b !== 0) break
    out = '1' + out
  }
  return out
}
async function p256() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
  const compressed = new Uint8Array(33)
  compressed[0] = raw[64] & 1 ? 0x03 : 0x02
  compressed.set(raw.slice(1, 33), 1)
  const keyId = `did:key:z${b58(new Uint8Array([0x80, 0x24, ...compressed]))}`
  const sign = async (data) => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data))
  return { keyId, sign }
}
// A request made with a space credential, signed for `audience`, as the 2026-10-22 alpha takes it.
export async function sigHeaders(key, authorization, audience) {
  const params = '("authorization" "atproto-space-audience");tag="atproto-space-credential"'
  const lines = [`"authorization": ${authorization}`, `"atproto-space-audience": ${audience}`, `"@signature-params": ${params}`]
  const signature = await key.sign(new TextEncoder().encode(lines.join('\n')))
  return {
    authorization,
    'atproto-space-audience': audience,
    'signature-input': `atproto-space-credential=${params}`,
    signature: `atproto-space-credential=:${b64(signature)}:`,
  }
}
// A person's space credential: a delegation token from their own PDS, traded at the space host.
export async function credentialFor(own, space) {
  const d = await asOwn(own, 'GET', 'com.atproto.space.getDelegationToken', { params: { space } })
  if (d.status !== 200) return { status: d.status, body: d.body }
  const key = await p256()
  const r = await call(`${own.who} delegation token`, HOST, 'POST', 'com.atproto.space.getSpaceCredential', {
    body: { space, credentialKid: key.keyId, delegationToken: d.body.token },
  })
  return { status: r.status, body: r.body, cred: r.status === 200 ? { token: r.body.credential, key } : null }
}
export async function listWriters(cred, space, authority) {
  const lr = await call('space credential', HOST, 'GET', 'com.atproto.space.listRepos', {
    params: { space },
    headers: await sigHeaders(cred.key, `Atproto-Space-Credential ${cred.token}`, authority),
  })
  return (lr.body?.repos ?? []).map((r) => r.did)
}
