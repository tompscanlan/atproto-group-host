// probe.mjs: drives the group-host spike (host.mjs) on the https devnet.
// Run: ../../atproto-devnet/scripts/https-run node probe.mjs [c|b|all] 2>&1 | tee run.log
// Logins live in data/accounts.env (mode 600) and are never printed; tokens are never printed.
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

const HERE = path.dirname(new URL(import.meta.url).pathname)
const ACCOUNTS = path.join(HERE, 'data/accounts.env')
const HOST = 'https://grouphost.devnet.internal'
const ALPHA = 'https://alpha.devnet.test'
const MANAGING_APP = 'did:web:grouphost.devnet.internal#group_host'
const MODE = process.argv[2] || 'all'
const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z')
const log = (...a) => console.log(...a)
const verdicts = []
const verdict = (id, ok, what) => {
  verdicts.push({ id, ok, what })
  log(`\n### ${id}: ${ok ? 'PASS' : 'FAIL'} - ${what}\n`)
}

// ---------- accounts (values never printed) ----------
const readEnv = () =>
  Object.fromEntries(
    fs.readFileSync(ACCOUNTS, 'utf8').split('\n').filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
  )
let E = readEnv()

async function call(label, base, method, nsid, { params, body, headers = {} } = {}) {
  const qs = params ? `?${new URLSearchParams(params)}` : ''
  const res = await fetch(`${base}/xrpc/${nsid}${qs}`, {
    method,
    headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let parsed
  try {
    parsed = text ? JSON.parse(text) : null
  } catch {
    parsed = text.slice(0, 200)
  }
  const shown = JSON.stringify(parsed)?.replace(/("(?:token|accessJwt|refreshJwt|credential)"\s*:\s*")[^"]+"/g, '$1<redacted>"')
  log(`- ${now()} ${method} ${base}/xrpc/${nsid}${params ? ' ' + JSON.stringify(params) : ''} (auth: ${label}) -> ${res.status} ${shown?.slice(0, 400)}`)
  return { status: res.status, body: parsed }
}
async function session(base, identifier, password, who) {
  const r = await call('none', base, 'POST', 'com.atproto.server.createSession', { body: { identifier, password } })
  if (r.status !== 200) throw new Error(`createSession ${who} ${r.status}`)
  return { who, did: r.body.did, jwt: r.body.accessJwt, base }
}
const asPw = (s, method, nsid, opts = {}) =>
  call(`${s.who} password session`, s.base, method, nsid, { ...opts, headers: { ...(opts.headers || {}), authorization: `Bearer ${s.jwt}` } })
const spike = async (p, body) => {
  const res = await fetch(`${HOST}/spike/${p}`, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {})
  return res.json()
}

// The group account on the host. Its password exists only because the spike creates the group
// with plain createAccount (creating it through prompt=create is not built yet); it is used only for
// setup below, where the group acts as itself, and
// never in the sign-in flow.
if (!E.GH_GROUP_DID) {
  const pw = crypto.randomBytes(18).toString('base64url')
  const r = await call('none', HOST, 'POST', 'com.atproto.server.createAccount', {
    body: { handle: 'spikegroup1.gh.devnet.test', email: 'spikegroup1@gh.devnet.test', password: pw },
  })
  if (r.status !== 200) throw new Error('createAccount group failed')
  fs.appendFileSync(ACCOUNTS, `GH_GROUP_HANDLE=spikegroup1.gh.devnet.test\nGH_GROUP_DID=${r.body.did}\nGH_GROUP_PASSWORD=${pw}\n`)
  E = readEnv()
}
const group = await session(HOST, E.GH_GROUP_DID, E.GH_GROUP_PASSWORD, 'group(itself)')
const alice = await session(ALPHA, E.GH_ALICE_HANDLE, E.GH_ALICE_PASSWORD, 'alice')
const bob = await session(ALPHA, E.GH_BOB_HANDLE, E.GH_BOB_PASSWORD, 'bob')
log(`group ${group.did} on ${HOST}; alice ${alice.did}; bob ${bob.did} on ${ALPHA}`)

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
async function sigHeaders(key, authorization, audience) {
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
async function credentialFor(reader, space) {
  const d = await asPw(reader, 'GET', 'com.atproto.space.getDelegationToken', { params: { space } })
  if (d.status !== 200) return { status: d.status, body: d.body }
  const key = await p256()
  const r = await call(`${reader.who} delegation token`, HOST, 'POST', 'com.atproto.space.getSpaceCredential', {
    body: { space },
    headers: await sigHeaders(key, `Bearer ${d.body.token}`),
  })
  return { status: r.status, body: r.body, cred: r.status === 200 ? { token: r.body.credential, key } : null }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// ---------- (c) managing-app policy calls back to the host, and its answer is enforced ----------
if (MODE === 'c' || MODE === 'all') {
  log('\n## (c) a group space under managing-app asks the host, and the answer is enforced\n')
  const skey = `spikec${Date.now()}`
  const TYPE = 'group.opensocial.members'
  const SPACE = `at://${group.did}/space/${TYPE}/${skey}`
  const MA = { $type: 'com.atproto.simplespace.defs#managingAppPolicy', managingApp: MANAGING_APP }
  const made = await asPw(group, 'POST', 'com.atproto.simplespace.createSpace', {
    body: { spaceType: TYPE, skey, readPolicy: MA, writePolicy: MA, appAccess: { $type: 'com.atproto.simplespace.defs#open' } },
  })
  verdict('c0', made.status === 200, 'the group creates a space whose read and write policy name the host as managing app')
  await asPw(group, 'GET', 'com.atproto.simplespace.getSpace', { params: { space: SPACE } })

  await spike('access', { space: SPACE, user: alice.did, kind: 'read', allow: true })
  const before = (await spike('state')).accessCalls.length
  const a1 = await credentialFor(alice, SPACE)
  const b1 = await credentialFor(bob, SPACE)
  verdict('c1', a1.status === 200 && b1.status !== 200, `host allows alice, gives bob no answer (false): alice ${a1.status}, bob ${b1.status} ${b1.body?.error ?? ''}`)

  await spike('access', { space: SPACE, user: alice.did, kind: 'read', allow: false })
  await spike('access', { space: SPACE, user: bob.did, kind: 'read', allow: true })
  const a2 = await credentialFor(alice, SPACE)
  const b2 = await credentialFor(bob, SPACE)
  verdict('c2', a2.status !== 200 && b2.status === 200, `flipping the host's answers flips who gets a credential: alice ${a2.status}, bob ${b2.status}`)

  const calls = (await spike('state')).accessCalls.slice(before)
  log('host saw checkUserAccess calls:', JSON.stringify(calls, null, 1))
  verdict(
    'c3',
    calls.length >= 4 && calls.every((c) => c.iss === group.did && c.kind === 'read'),
    `every read decision came to the host as service auth from the group (${calls.length} calls, iss=group, verified)`,
  )

  // Writes: both members write into the space on their own PDS. Only writers the host allows
  // are tracked in the writer set (0016: write policy decides tracking, not whether the write lands).
  await spike('access', { space: SPACE, user: alice.did, kind: 'write', allow: true })
  for (const m of [alice, bob]) {
    await asPw(m, 'POST', 'com.atproto.space.createRecord', {
      body: { space: SPACE, repo: m.did, collection: 'group.opensocial.acceptance', rkey: 'self', record: { $type: 'group.opensocial.acceptance', createdAt: new Date().toISOString() } },
    })
  }
  await sleep(4000)
  const g = await credentialFor(group, SPACE)
  let writers = []
  if (g.cred) {
    const lr = await call('group space credential', HOST, 'GET', 'com.atproto.space.listRepos', {
      params: { space: SPACE },
      headers: await sigHeaders(g.cred.key, `Atproto-Space ${g.cred.token}`, group.did),
    })
    writers = (lr.body?.repos ?? []).map((r) => r.did)
  }
  const wcalls = (await spike('state')).accessCalls.filter((c) => c.space === SPACE && c.kind === 'write')
  log('write checks:', JSON.stringify(wcalls))
  verdict(
    'c4',
    writers.includes(alice.did) && !writers.includes(bob.did),
    `writer set follows the host's write answer: alice listed ${writers.includes(alice.did)}, bob listed ${writers.includes(bob.did)} (${wcalls.length} write checks)`,
  )
}

// ---------- (b) sign in as the group through your own PDS, no group password ----------
async function groupSignIn(person, label) {
  const CB_PORT = 39418
  const REDIRECT = `http://127.0.0.1:${CB_PORT}/cb`
  const scopes = ['atproto', 'space:*?authority=self&collection=*']
  const actorResolver = new LocalActorResolver({
    handleResolver: new WellKnownHandleResolver(),
    didDocumentResolver: new CompositeDidDocumentResolver({ methods: { plc: new PlcDidDocumentResolver(), web: new WebDidDocumentResolver() } }),
  })
  const app = new OAuthClient({
    metadata: { redirect_uris: [REDIRECT], scope: scopes },
    actorResolver,
    stores: { sessions: new MemoryStore(), states: new MemoryStore({ ttl: 600_000 }) },
  })
  const { url } = await app.authorize({ target: { type: 'account', identifier: group.did }, scope: scopes.join(' ') })
  log(`- ${now()} app PAR at ${url.origin} for the group DID ok`)
  let cbUrl = null
  const server = http.createServer((rq, rs) => {
    cbUrl = `http://127.0.0.1:${CB_PORT}${rq.url}`
    rs.end('ok')
  })
  await new Promise((r) => server.listen(CB_PORT, '127.0.0.1', r))
  const browser = await launchBrowser(chromium)
  const typed = [] // every field the browser filled, by page origin (values not logged)
  const pages = []
  try {
    const ctx = await browser.newContext()
    const p = await ctx.newPage()
    p.on('framenavigated', (f) => f === p.mainFrame() && pages.push(f.url().replace(/([?&](code|state|iss)=)[^&]+/g, '$1…').slice(0, 160)))
    await p.goto(url.toString(), { waitUntil: 'load', timeout: 60000 })
    await p.waitForURL(/127\.0\.0\.1:7070\/signin\/start/, { timeout: 30000 })
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
    // Consent at the person's own PDS (host asks for 'atproto' only), then consent at the host.
    let groupConsentText = null
    for (let i = 0; i < 120 && !cbUrl; i++) {
      const btn = p.getByRole('button', { name: /^(accept|authorize|allow)/i }).first()
      if (await btn.isVisible().catch(() => false)) {
        const origin = new URL(p.url()).origin
        const text = (await p.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 600)
        log(`- ${now()} consent at ${origin}: ${text}`)
        if (origin === HOST) {
          groupConsentText = text
          await p.screenshot({ path: path.join(HERE, `b-consent-${label}.png`), fullPage: true })
        }
        await btn.click()
        await p.waitForTimeout(1500)
        continue
      }
      const body = await p.locator('body').innerText().catch(() => '')
      if (/hold no role|Invalid ticket|error/i.test(body) && !/Sign in/i.test(body)) {
        log(`- ${now()} page at ${p.url().slice(0, 80)} says: ${body.replace(/\s+/g, ' ').slice(0, 200)}`)
        break
      }
      await p.waitForTimeout(500)
    }
    log(`- pages visited: ${JSON.stringify(pages, null, 1)}`)
    log(`- fields typed: ${JSON.stringify(typed)}`)
    const finalText = await p.locator('body').innerText().catch(() => '')
    if (!cbUrl) return { ok: false, typed, groupConsentText, finalText }
    const { session: s } = await app.callback(new URL(cbUrl).searchParams)
    return { ok: true, session: s, typed, groupConsentText }
  } finally {
    await browser.close()
    await new Promise((r) => server.close(r))
  }
}

if (MODE === 'b' || MODE === 'all') {
  log('\n## (b) a person signs in through their own PDS and the app gets a group-DID session\n')
  await spike('roles', { group: group.did, person: alice.did, hold: true })
  const A = await groupSignIn({ handle: E.GH_ALICE_HANDLE, password: E.GH_ALICE_PASSWORD }, 'alice')
  if (A.ok) {
    const sub = A.session.did
    const res = await A.session.handle('/xrpc/com.atproto.server.getSession')
    const gs = await res.json()
    log(`- ${now()} app's session: sub=${sub}, server=${A.session.server?.issuer ?? "?"}; getSession as it -> ${res.status} did=${gs.did} handle=${gs.handle}`)
    // A space made by the group itself (setup), then a write into it through the app's group session.
    const skey = `spikeb${Date.now()}`
    const SPACE_B = `at://${group.did}/space/group.opensocial.meta/${skey}`
    const ML = { $type: 'com.atproto.simplespace.defs#memberListPolicy' }
    await asPw(group, 'POST', 'com.atproto.simplespace.createSpace', { body: { spaceType: 'group.opensocial.meta', skey, readPolicy: ML, writePolicy: ML, appAccess: { $type: 'com.atproto.simplespace.defs#open' } } })
    const wr = await A.session.handle('/xrpc/com.atproto.space.createRecord', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ space: SPACE_B, repo: group.did, collection: 'group.opensocial.profile', rkey: 'self', record: { $type: 'group.opensocial.profile', displayName: 'Spike group', joinPolicy: 'approval' } }),
    })
    const wrBody = await wr.text()
    log(`- ${now()} group OAuth session writes group.opensocial.profile into ${SPACE_B} -> ${wr.status} ${wrBody.slice(0, 300)}`)
    const mk = await A.session.handle('/xrpc/com.atproto.simplespace.createSpace', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ spaceType: 'group.opensocial.meta', skey: skey + 'x', readPolicy: ML, writePolicy: ML, appAccess: { $type: 'com.atproto.simplespace.defs#open' } }),
    })
    log(`- ${now()} the same session tries simplespace.createSpace (scope lacks manage=create) -> ${mk.status} ${(await mk.text()).slice(0, 200)}`)
    verdict('b4', wr.status === 200 && mk.status === 403, `the group session is usable and bounded by its scopes: space write ${wr.status}, createSpace without manage=create ${mk.status}`)
    const st = await spike('state')
    log('host authorizedBy:', JSON.stringify(st.authorizedBy))
    verdict(
      'b1',
      sub === group.did && gs.did === group.did && st.authorizedBy.some((x) => x.personDid === alice.did && x.groupDid === group.did),
      `alice signed in at her own PDS and the app holds a session for the GROUP DID (${sub}); the host recorded alice as the person behind it`,
    )
    verdict(
      'b2',
      !A.typed.some((t) => t.origin === HOST && /password/.test(t.field)),
      `no password was typed at the host; the only password typed was alice's own, at ${ALPHA}`,
    )
  } else {
    verdict('b1', false, 'alice did not reach an app callback')
  }
  const B = await groupSignIn({ handle: E.GH_BOB_HANDLE, password: E.GH_BOB_PASSWORD }, 'bob')
  verdict('b3', !B.ok && /hold no role/.test(B.finalText ?? ''), `bob, who holds no role, gets no group session: ${B.ok ? 'got one!' : (B.finalText ?? '').slice(0, 120)}`)
}

log('\n## verdicts\n')
for (const v of verdicts) log(`- ${v.id} ${v.ok ? 'PASS' : 'FAIL'}: ${v.what}`)
