// lib.mjs: what the day-2 and day-3 probes share. Logins live in data/accounts.env (mode 600) and
// are never printed; tokens are never printed.
import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { createRequire } from 'node:module'
import { OAuthClient, MemoryStore } from '@atcute/oauth-node-client'
import {
  CompositeDidDocumentResolver,
  LocalActorResolver,
  PlcDidDocumentResolver,
  WebDidDocumentResolver,
  WellKnownHandleResolver,
} from '@atcute/identity-resolver'
// A Chromium launcher that trusts the devnet's certificate. Point DEVNET_BROWSER at your own copy.
const { launchBrowser } = await import(process.env.DEVNET_BROWSER ?? '/workspaces/scratch/wt-atproto-permissioned-data-ewnj3/sandbox/opensocial/devnet-browser.mjs')

const require = createRequire(import.meta.url)
const { chromium } = require('/home/node/.local/share/mise/installs/npm-playwright/1.63.0/node_modules/playwright')

export const HERE = path.dirname(new URL(import.meta.url).pathname)
export const HOST = 'https://grouphost.devnet.internal'
export const ALPHA = 'https://alpha.devnet.test'
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

const E = Object.fromEntries(
  fs.readFileSync(path.join(HERE, 'data/accounts.env'), 'utf8').split('\n').filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
)
export const alice = { who: 'alice', handle: E.GH_ALICE_HANDLE, password: E.GH_ALICE_PASSWORD, did: E.GH_ALICE_DID }
export const bob = { who: 'bob', handle: E.GH_BOB_HANDLE, password: E.GH_BOB_PASSWORD, did: E.GH_BOB_DID }

export const state = async (q) => (await fetch(`${HOST}/spike/state?${new URLSearchParams(q)}`)).json()
export const spike = async (p, body) =>
  (await fetch(`${HOST}/spike/${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json()

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
  didDocumentResolver: new CompositeDidDocumentResolver({ methods: { plc: new PlcDidDocumentResolver(), web: new WebDidDocumentResolver() } }),
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
// and the host's consent page is read and approved.
export async function groupSignIn(person, { create, groupDid, label: shot, scopes }) {
  const app = newApp(scopes)
  const { url } = await app.authorize({
    target: create ? { type: 'pds', serviceUrl: HOST } : { type: 'account', identifier: groupDid },
    scope: scopes.join(' '),
    ...(create ? { prompt: 'create' } : {}),
  })
  log(`- ${now()} app PAR at ${url.origin} (${create ? 'prompt=create' : 'group ' + groupDid}) ok`)
  let cbUrl = null
  const server = http.createServer((rq, rs) => {
    cbUrl = `http://127.0.0.1:${CB_PORT}${rq.url}`
    rs.end('ok')
  })
  await new Promise((r) => server.listen(CB_PORT, '127.0.0.1', r))
  const browser = await launchBrowser(chromium)
  const typed = []
  const out = { ok: false, app, typed, kept: [], dropped: [], consentText: null }
  try {
    const p = await (await browser.newContext()).newPage()
    await p.goto(url.toString(), { waitUntil: 'load', timeout: 60000 })
    await p.waitForURL(/127\.0\.0\.1:7070\/signin\/start/, { timeout: 30000 })
    if (create) {
      await p.fill('input[name=label]', create.label)
      await p.fill('input[name=displayName]', create.displayName)
      typed.push({ origin: new URL(p.url()).origin, field: 'new group name and display name' })
    }
    await p.fill('input[name=handle]', person.handle)
    typed.push({ origin: new URL(p.url()).origin, field: 'handle' })
    await p.click('button')
    await p.waitForURL(/alpha\.devnet\.test/, { timeout: 30000 })
    await p.waitForSelector('input[name=password]', { timeout: 30000 })
    const user = p.locator('input[name=username]')
    if ((await user.count()) && (await user.isEditable()) && !(await user.inputValue())) await user.fill(person.handle)
    await p.fill('input[name=password]', person.password)
    typed.push({ origin: new URL(p.url()).origin, field: 'password (own account)' })
    await p.getByRole('button', { name: 'Sign in' }).click()
    for (let i = 0; i < 120 && !cbUrl; i++) {
      const origin = new URL(p.url()).origin
      if (origin === HOST && (await p.locator('#consent').isVisible().catch(() => false))) {
        out.consentText = (await p.locator('#consent').innerText()).replace(/\s+/g, ' ')
        out.kept = await p.locator('#kept li').allInnerTexts()
        out.dropped = await p.locator('#dropped li').allInnerTexts()
        log(`- ${now()} host consent: ${out.consentText.slice(0, 900)}`)
        if (shot) await p.screenshot({ path: path.join(HERE, `${shot}.png`), fullPage: true })
        await p.click('#go')
        await p.waitForTimeout(1500)
        continue
      }
      const btn = p.getByRole('button', { name: /^(accept|authorize|allow)/i }).first()
      if (origin !== HOST && (await btn.isVisible().catch(() => false))) {
        log(`- ${now()} consent at ${origin} (own account, atproto only)`)
        await btn.click()
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
    if (!cbUrl) return out
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
  const browser = await launchBrowser(chromium)
  try {
    const p = await (await browser.newContext()).newPage()
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

// ---------- RFC 9421 space credentials (from sandbox/opensocial/probe-private-rsvp.mjs) ----------
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
export async function sigHeaders(key, authorization, audience) {
  const params = audience === undefined ? `("authorization");keyid="${key.keyId}"` : '("authorization" "atproto-space-audience")'
  const lines = [`"authorization": ${authorization}`]
  if (audience !== undefined) lines.push(`"atproto-space-audience": ${audience}`)
  lines.push(`"@signature-params": ${params}`)
  const signature = await key.sign(new TextEncoder().encode(lines.join('\n')))
  return {
    authorization,
    ...(audience !== undefined ? { 'atproto-space-audience': audience } : {}),
    'signature-input': `atproto-space=${params}`,
    signature: `atproto-space=:${b64(signature)}:`,
  }
}
// A person's space credential: a delegation token from their own PDS, traded at the space host.
export async function credentialFor(own, space) {
  const d = await asOwn(own, 'GET', 'com.atproto.space.getDelegationToken', { params: { space } })
  if (d.status !== 200) return { status: d.status, body: d.body }
  const key = await p256()
  const r = await call(`${own.who} delegation token`, HOST, 'POST', 'com.atproto.space.getSpaceCredential', {
    body: { space },
    headers: await sigHeaders(key, `Bearer ${d.body.token}`),
  })
  return { status: r.status, body: r.body, cred: r.status === 200 ? { token: r.body.credential, key } : null }
}
export async function listWriters(cred, space, authority) {
  const lr = await call('space credential', HOST, 'GET', 'com.atproto.space.listRepos', {
    params: { space },
    headers: await sigHeaders(cred.key, `Atproto-Space ${cred.token}`, authority),
  })
  return (lr.body?.repos ?? []).map((r) => r.did)
}
