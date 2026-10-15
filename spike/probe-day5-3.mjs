// probe-day5-3.mjs: a person's own acts through an OAuth session at their own PDS, the way atmo
// will make them (om-3r2nx.6.4). Day 4 proxied with a password session, which no app holds.
//   g1  bob signs in at alpha with OAuth, asking only for the three rpc: items; requestJoin sent
//       to alpha with `atproto-proxy: <group>#atproto_pds` reaches the host, which logs bob as the
//       member and the group as the audience
//   g2  the same session's cancelJoinRequest (or leaveGroup, if the group admitted him) reaches
//       the host too, and bob ends holding no request and no membership
//   g3  an OAuth session without the rpc: items is refused at alpha, and the host logs no call
// Run from spike/:
//   DEVNET_LEAF_FILE=/workspaces/scratch/atproto-devnet/data/https/leaf.crt \
//     /workspaces/scratch/atproto-devnet/scripts/https-run node probe-day5-3.mjs > run-day5-3.log 2>&1
import http from 'node:http'
import { createRequire } from 'node:module'
import { OAuthClient, MemoryStore } from '@atcute/oauth-node-client'
import {
  CompositeDidDocumentResolver,
  LocalActorResolver,
  PlcDidDocumentResolver,
  WebDidDocumentResolver,
  WellKnownHandleResolver,
} from '@atcute/identity-resolver'
import { ALPHA, bob, log, now, state, summary, verdict } from './lib.mjs'

const { launchBrowser } = await import(process.env.DEVNET_BROWSER ?? '/workspaces/scratch/wt-atproto-permissioned-data-ewnj3/sandbox/opensocial/devnet-browser.mjs')
const require = createRequire(import.meta.url)
const { chromium } = require('/home/node/.local/share/mise/installs/npm-playwright/1.63.0/node_modules/playwright')

// Day 4's group of record; bob held no request or membership there when day 4 ended.
const GROUP = process.env.GROUP ?? 'did:plc:66pgsrgfxpd66hpqpneupgo4'
const MEMBER_RPC = ['requestJoin', 'cancelJoinRequest', 'leaveGroup'].map((m) => `rpc:group.opensocial.${m}?aud=*`)

const actorResolver = new LocalActorResolver({
  handleResolver: new WellKnownHandleResolver(),
  didDocumentResolver: new CompositeDidDocumentResolver({ methods: { plc: new PlcDidDocumentResolver(), web: new WebDidDocumentResolver() } }),
})
const CB_PORT = 39419
const REDIRECT = `http://127.0.0.1:${CB_PORT}/cb`

// The person's own sign-in at their own PDS: no host in the path.
async function ownOAuth(person, scopes) {
  const app = new OAuthClient({
    metadata: { redirect_uris: [REDIRECT], scope: scopes.join(' ') },
    actorResolver,
    stores: { sessions: new MemoryStore(), states: new MemoryStore({ ttl: 600_000 }) },
  })
  const { url } = await app.authorize({ target: { type: 'account', identifier: person.handle }, scope: scopes.join(' ') })
  log(`- ${now()} PAR at ${url.origin} for ${person.who}, scope: ${scopes.join(' ')}`)
  let cbUrl = null
  const server = http.createServer((rq, rs) => {
    cbUrl = `http://127.0.0.1:${CB_PORT}${rq.url}`
    rs.end('ok')
  })
  await new Promise((r) => server.listen(CB_PORT, '127.0.0.1', r))
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

// A member method, sent to the person's own PDS for the group's host.
async function viaOwnPds(session, name) {
  const res = await session.handle(`/xrpc/group.opensocial.${name}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'atproto-proxy': `${GROUP}#atproto_pds` },
    body: JSON.stringify({ group: GROUP }),
  })
  const text = await res.text()
  let body
  try {
    body = JSON.parse(text)
  } catch {
    body = text.slice(0, 200)
  }
  log(`- ${now()} POST ${ALPHA}/xrpc/group.opensocial.${name} (proxy ${GROUP}#atproto_pds) -> ${res.status} ${JSON.stringify(body)?.slice(0, 300)}`)
  return { status: res.status, body }
}

const hostCalls = async () => (await state({ group: GROUP })).methodCalls ?? []
const newCalls = (before, after) => after.filter((c) => !before.some((b) => b.at === c.at && b.nsid === c.nsid))

log(`# probe-day5-3 ${now()} group ${GROUP}`)
const start = await state({ group: GROUP })
const pendingBefore = (start.joinRequests ?? []).filter((r) => r.member === bob.did)
log(`- before: bob's pending requests here ${pendingBefore.length}`)

// g1
const withRpc = await ownOAuth(bob, ['atproto', ...MEMBER_RPC])
const granted = MEMBER_RPC.every((s) => withRpc.scope.split(' ').includes(s))
let calls0 = await hostCalls()
const join = await viaOwnPds(withRpc.session, 'requestJoin')
let seen = newCalls(calls0, await hostCalls()).filter((c) => c.nsid === 'requestJoin')
log(`- host logged: ${JSON.stringify(seen)}`)
const status = join.body?.status
verdict(
  'g1',
  granted && join.status === 200 && ['pending', 'admitted'].includes(status) && seen.length === 1 && seen[0].member === bob.did && seen[0].aud === GROUP,
  `OAuth session with the rpc: items: requestJoin through alpha -> ${join.status} ${status ?? join.body?.error}; host saw member ${seen[0]?.member === bob.did ? 'bob' : seen[0]?.member}, aud ${seen[0]?.aud}`,
)

// g2
calls0 = await hostCalls()
const undo = await viaOwnPds(withRpc.session, status === 'admitted' ? 'leaveGroup' : 'cancelJoinRequest')
seen = newCalls(calls0, await hostCalls())
const end = await state({ group: GROUP })
const stillPending = (end.joinRequests ?? []).filter((r) => r.member === bob.did).length
verdict(
  'g2',
  undo.status === 200 && seen.length === 1 && seen[0].member === bob.did && stillPending === 0,
  `${seen[0]?.nsid} through alpha -> ${undo.status}; host saw ${seen.length} call(s); bob's pending requests after ${stillPending}`,
)

// g3
const without = await ownOAuth(bob, ['atproto'])
calls0 = await hostCalls()
const refused = await viaOwnPds(without.session, 'requestJoin')
seen = newCalls(calls0, await hostCalls())
verdict(
  'g3',
  refused.status >= 400 && seen.length === 0,
  `OAuth session without them: requestJoin through alpha -> ${refused.status} ${refused.body?.error}; host saw ${seen.length} call(s)`,
)

summary()
