// probe-day2.mjs: drives the group-host spike's second round on the https devnet.
//   d1  prompt=create makes a group with its starting records, and the app gets its session
//   d2  every token the host issued for the group names the person who authorized it
//   d3  the group sign-in leaves no group session on the device
//   d4  a member whose role only reads is offered only the read scopes
//   d5  removing a member cuts their existing session on the next request
//   d6  a refreshed token keeps its person
//   d7  the token-to-person table survives a host restart
// Run: ../atproto-devnet/scripts/https-run node probe-day2.mjs 2>&1 | tee run-day2.log
// Logins live in data/accounts.env (mode 600) and are never printed; tokens are never printed.
import { execFileSync } from 'node:child_process'
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
const HOST = 'https://grouphost.devnet.internal'
const ALPHA = 'https://alpha.devnet.test'
const META = 'group.opensocial.meta'
const MEMBERS = 'group.opensocial.members'
const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z')
const log = (...a) => console.log(...a)
const verdicts = []
const verdict = (id, ok, what) => {
  verdicts.push({ id, ok, what })
  log(`\n### ${id}: ${ok ? 'PASS' : 'FAIL'} - ${what}\n`)
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const E = Object.fromEntries(
  fs.readFileSync(path.join(HERE, 'data/accounts.env'), 'utf8').split('\n').filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
)
const alice = { handle: E.GH_ALICE_HANDLE, password: E.GH_ALICE_PASSWORD, did: E.GH_ALICE_DID }
const bob = { handle: E.GH_BOB_HANDLE, password: E.GH_BOB_PASSWORD, did: E.GH_BOB_DID }

const spaceUri = (did, type) => `at://${did}/space/${type}/self`
const state = async (q) => (await fetch(`${HOST}/spike/state?${new URLSearchParams(q)}`)).json()

// What the app asks for: write the two group spaces, make spaces, and read both. The reads are
// separate items so a member who may only read still gets them.
const SCOPES = [
  'atproto',
  `space:${META}?authority=self&skey=self&collection=*`,
  `space:${MEMBERS}?authority=self&skey=self&collection=*`,
  'space:*?authority=self&action=read_self&manage=create',
  `space:${META}?authority=self&skey=self&action=read`,
  `space:${MEMBERS}?authority=self&skey=self&action=read`,
]

const actorResolver = new LocalActorResolver({
  handleResolver: new WellKnownHandleResolver(),
  didDocumentResolver: new CompositeDidDocumentResolver({ methods: { plc: new PlcDidDocumentResolver(), web: new WebDidDocumentResolver() } }),
})
const CB_PORT = 39418
const REDIRECT = `http://127.0.0.1:${CB_PORT}/cb`
// One app client per person: a client's session store is keyed by the account, and every
// session here is for the same group DID.
const newApp = () =>
  new OAuthClient({
    metadata: { redirect_uris: [REDIRECT], scope: SCOPES },
    actorResolver,
    stores: { sessions: new MemoryStore(), states: new MemoryStore({ ttl: 600_000 }) },
  })

// One trip through the browser: the app asks the host, the person signs in at their own PDS,
// and the host's consent page is read and approved.
async function groupSignIn(person, { create, groupDid, label: shot }) {
  const app = newApp()
  const { url } = await app.authorize({
    target: create ? { type: 'pds', serviceUrl: HOST } : { type: 'account', identifier: groupDid },
    scope: SCOPES.join(' '),
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
        await p.screenshot({ path: path.join(HERE, `d-consent-${shot}.png`), fullPage: true })
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

async function as(session, who, method, nsid, { params, body } = {}) {
  const qs = params ? `?${new URLSearchParams(params)}` : ''
  const res = await session.handle(`/xrpc/${nsid}${qs}`, {
    method,
    ...(body ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {}),
  })
  const text = await res.text()
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    parsed = text.slice(0, 200)
  }
  log(`- ${now()} ${method} ${nsid}${params ? ' ' + JSON.stringify(params) : ''} (as ${who}) -> ${res.status} ${JSON.stringify(parsed).slice(0, 300)}`)
  return { status: res.status, body: parsed }
}
const listRecords = (s, who, group, type) => as(s, who, 'GET', 'com.atproto.space.listRecords', { params: { space: spaceUri(group, type), repo: group, limit: '100' } })

// ---------- d1: create ----------
log('\n## d1 prompt=create makes a group, and the app gets its session\n')
const label = `d2g${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label, displayName: 'Day two group' }, label: 'alice-create' })
const G = A.session?.did
let d1ok = false
if (A.ok) {
  const sess = await as(A.session, 'alice for the group', 'GET', 'com.atproto.server.getSession')
  const meta = await listRecords(A.session, 'alice for the group', G, META)
  const members = await listRecords(A.session, 'alice for the group', G, MEMBERS)
  const has = (r, c, k) => (r.body?.records ?? []).some((x) => x.collection === c && x.rkey === k)
  const ms = (members.body?.records ?? []).find((x) => x.collection === 'group.opensocial.membership' && x.rkey === alice.did)
  const parts = {
    handle: sess.body?.handle === `${label}.gh.devnet.test`,
    metaAccess: has(meta, 'group.opensocial.access', 'self'),
    profile: has(meta, 'group.opensocial.profile', 'self'),
    membersAccess: has(members, 'group.opensocial.access', 'self'),
    permissions: has(members, 'group.opensocial.permissions', 'self'),
    roleAdmin: has(members, 'group.opensocial.role', 'admin'),
    roleMember: has(members, 'group.opensocial.role', 'member'),
    aliceAdmin: JSON.stringify(ms?.value?.roles) === '["admin"]',
  }
  log(`- records found: ${JSON.stringify(parts)}`)
  const noGroupPassword = !A.typed.some((t) => t.origin === HOST && /password/.test(t.field))
  d1ok = Object.values(parts).every(Boolean) && noGroupPassword && A.dropped.length === 0
  verdict('d1', d1ok, `alice created ${G} through her own PDS; session sub is the new group; meta and members spaces hold access, profile, permissions, both roles, and alice's admin membership; no group password typed; all ${A.kept.length} requested scopes offered`)
} else verdict('d1', false, 'create flow did not reach the app')

if (G) {
  // ---------- d2, d3 ----------
  log('\n## d2 every token names its person; d3 no group session left on the device\n')
  let st = await state({ group: G })
  log(`- host tokens for the group: ${JSON.stringify(st.tokens)}; device sessions for the group: ${st.deviceAccounts}`)
  verdict('d2', st.tokens.length >= 1 && st.tokens.every((t) => t.personDid === alice.did && t.via === 'person'), `the host's token table maps every token for ${G} to alice (${st.tokens.length} token)`)
  verdict('d3', st.deviceAccounts === 0, `devices signed in as the group after the sign-in: ${st.deviceAccounts}`)

  // ---------- d4 ----------
  log('\n## d4 a member who may only read is offered only the read scopes\n')
  const added = await as(A.session, 'alice for the group', 'POST', 'com.atproto.space.createRecord', {
    body: { space: spaceUri(G, MEMBERS), repo: G, collection: 'group.opensocial.membership', rkey: bob.did, record: { $type: 'group.opensocial.membership', member: bob.did, roles: ['member'], createdAt: new Date().toISOString() } },
  })
  const B = await groupSignIn(bob, { groupDid: G, label: 'bob-member' })
  let bRead0 = null
  if (B.ok) {
    bRead0 = await listRecords(B.session, 'bob for the group', G, MEMBERS)
    const bWrite = await as(B.session, 'bob for the group', 'POST', 'com.atproto.space.createRecord', {
      body: { space: spaceUri(G, META), repo: G, collection: 'group.opensocial.rule', record: { $type: 'group.opensocial.rule', title: 'Be kind', text: 'Be kind.' } },
    })
    const reads = SCOPES.filter((s) => /action=read$/.test(s))
    const offeredOnlyReads = B.kept.length === reads.length + 1 && reads.every((s) => B.kept.includes(s)) && B.dropped.length === SCOPES.length - reads.length - 1
    verdict('d4', added.status === 200 && offeredOnlyReads && bRead0.status === 200 && bWrite.status === 403, `bob (role member) was offered ${B.kept.length} scopes (atproto and the two reads) and not ${B.dropped.length} (writes, manage); his session reads members ${bRead0.status} and is refused a meta write ${bWrite.status} ${bWrite.body?.error ?? ''}`)
  } else verdict('d4', false, `bob's sign-in did not reach the app (membership write ${added.status})`)

  // ---------- d5 ----------
  log('\n## d5 removing a member cuts their existing session on the next request\n')
  if (B.ok) {
    const removed = await as(A.session, 'alice for the group', 'POST', 'com.atproto.space.deleteRecord', {
      body: { space: spaceUri(G, MEMBERS), repo: G, collection: 'group.opensocial.membership', rkey: bob.did },
    })
    const bRead1 = await listRecords(B.session, 'bob for the group', G, MEMBERS)
    const aRead = await listRecords(A.session, 'alice for the group', G, MEMBERS)
    st = await state({ group: G })
    const cut = st.narrowings.filter((n) => n.group === G && n.personDid === bob.did).at(-1)
    log(`- host's last cut for bob: ${JSON.stringify(cut)}`)
    verdict('d5', removed.status === 200 && bRead0?.status === 200 && bRead1.status === 403 && aRead.status === 200, `same session, no new sign-in: bob read ${bRead0?.status} before his membership was deleted and ${bRead1.status} after; alice still ${aRead.status}`)
  } else verdict('d5', false, 'no bob session to test')

  // ---------- d6 ----------
  log('\n## d6 a refreshed token keeps its person\n')
  const before = (await state({ group: G })).tokens.filter((t) => t.personDid === alice.did).map((t) => t.id)
  const refreshed = await A.app.restore(G, { refresh: true }).catch((e) => ({ error: e.message }))
  const after = (await state({ group: G })).tokens.filter((t) => t.personDid === alice.did).map((t) => t.id)
  const aRead2 = refreshed.error ? { status: 0 } : await listRecords(refreshed, 'alice for the group (refreshed)', G, MEMBERS)
  log(`- alice's token ids before ${JSON.stringify(before)}, after ${JSON.stringify(after)}`)
  verdict('d6', !refreshed.error && aRead2.status === 200 && after.length >= 1 && after.some((id) => !before.includes(id)), `after a refresh the new token is mapped to alice and reads ${aRead2.status}${refreshed.error ? ' (' + refreshed.error + ')' : ''}`)

  // ---------- d7 ----------
  log('\n## d7 the token table survives a host restart\n')
  execFileSync('docker', ['restart', 'grouphost-spike'])
  for (let i = 0; i < 60; i++) {
    if ((await fetch(`${HOST}/xrpc/_health`).catch(() => null))?.ok) break
    await sleep(1000)
  }
  const s7 = await A.app.restore(G, { refresh: false })
  const aRead3 = await listRecords(s7, 'alice for the group (after restart)', G, MEMBERS)
  verdict('d7', aRead3.status === 200, `alice's session reads ${aRead3.status} after the host restarted`)
}

log('\n## Summary\n')
for (const v of verdicts) log(`- ${v.id} ${v.ok ? 'PASS' : 'FAIL'}: ${v.what}`)
log(`\n${verdicts.filter((v) => v.ok).length}/${verdicts.length} pass`)
process.exit(0)
