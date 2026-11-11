// in-step.mjs: the host keeps a group's records in step itself.
//   k1  alice makes her group's meta space public and writes its declaration, as an app's save does
//   k2  she makes meta private again with a putRecord of its access record alone: when the write
//       returns, the host has brought the declaration down
//   k3  meta made public again: the host writes no declaration (that is the group's app's choice);
//       one written by her, then meta made private by an applyWrites, comes down
//   k4  a create cut short once its account exists (it fails there): the host removes the account,
//       so the address resolves to nothing, the repo is gone and no note is left
//   k5  a create cut short by the host stopping (it hangs once its account exists, and the host is
//       restarted): at the next start the account is removed and the note dropped; alice's
//       finished group is still there
//   k6  the address freed in k4 makes a group again, with alice its admin
// Restarts the host's container once, so run it where docker reaches the snowglobe's.
// Run from probes/: snowglobe run node in-step.mjs
import { execFileSync } from 'node:child_process'
import { GROUP_DOMAIN, HOST, HOST_CONTAINER, META, MEMBERS, alice, as, call, groupSignIn, log, now, sleep, spaceUri, testRoute, state, summary, verdict } from './lib.mjs'

const NS = 'group.opensocial'
const DECLARATION = `${NS}.declaration`
const SCOPES = ['atproto', `space:${META}?authority=self&skey=self&collection=*`, `space:${MEMBERS}?authority=self&skey=self&collection=*`, `repo?collection=${DECLARATION}`]
const META_GRANTS = [
  { role: 'admin', scopes: [`space:${META}?collection=*`] },
  { role: 'member', scopes: [`space:${META}?action=read`] },
]
const err = (r) => `${r?.status} ${r?.body?.error ?? ''}`.trim()
const readDeclaration = (group) => call('none', HOST, 'GET', 'com.atproto.repo.getRecord', { params: { repo: group, collection: DECLARATION, rkey: 'self' } })
const resolve = (label) => call('none', HOST, 'GET', 'com.atproto.identity.resolveHandle', { params: { handle: `${label}${GROUP_DOMAIN}` } })
const describe = (did) => call('none', HOST, 'GET', 'com.atproto.repo.describeRepo', { params: { repo: did } })
const noted = async (label) => ((await state({})).creates ?? []).some((c) => c.handle === `${label}${GROUP_DOMAIN}`)
const gone = (r) => r.status === 400

log(`# in-step ${now()}`)

// ---------- k1 ----------
log('\n## k1 alice makes her group public and declares it\n')
const label = `ks${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label }, scopes: SCOPES })
if (!A.ok) {
  verdict('setup', false, 'create flow did not reach the app')
  summary()
  process.exit(0)
}
const G = A.session.did
const MET = spaceUri(G, META)
log(`- group ${G} (${label})`)
const asA = (method, nsid, body) => as(A.session, 'alice for the group', method, nsid, { body })
const metaAccess = (pub) => asA('POST', 'com.atproto.space.putRecord', { space: MET, repo: G, collection: `${NS}.access`, rkey: 'self', record: { $type: `${NS}.access`, public: pub, grants: META_GRANTS } })
const declare = () => asA('POST', 'com.atproto.repo.putRecord', { repo: G, collection: DECLARATION, rkey: 'self', record: { $type: DECLARATION, meta: MET } })
const p1 = await metaAccess(true)
const d1 = await declare()
const r1 = await readDeclaration(G)
verdict('k1', p1.status === 200 && d1.status === 200 && r1.status === 200, `meta made public ${err(p1)}; declaration written ${err(d1)}, read back ${err(r1)}`)

// ---------- k2 ----------
log('\n## k2 meta made private by its access record alone\n')
const p2 = await metaAccess(false)
const r2 = await readDeclaration(G)
verdict('k2', p2.status === 200 && gone(r2), `meta made private ${err(p2)}; the declaration, read as soon as the write returned: ${err(r2)}`)

// ---------- k3 ----------
log('\n## k3 public again: no declaration from the host; one of hers comes down by applyWrites\n')
const p3 = await metaAccess(true)
const r3 = await readDeclaration(G)
const d3 = await declare()
const w3 = await asA('POST', 'com.atproto.space.applyWrites', {
  space: MET,
  repo: G,
  writes: [{ $type: 'com.atproto.space.applyWrites#update', collection: `${NS}.access`, rkey: 'self', value: { $type: `${NS}.access`, public: false, grants: META_GRANTS } }],
})
const r3b = await readDeclaration(G)
verdict(
  'k3',
  p3.status === 200 && gone(r3) && d3.status === 200 && w3.status === 200 && gone(r3b),
  `meta public again ${err(p3)}, declaration after ${err(r3)} (the host wrote none); hers written ${err(d3)}; meta private by applyWrites ${err(w3)}, declaration after ${err(r3b)}`,
)

// ---------- k4 ----------
log('\n## k4 a create that fails once its account exists\n')
const failed = `kf${Date.now().toString(36)}`
const f4 = await testRoute('interrupted-create', { label: failed, creatorDid: alice.did, how: 'fail' })
log(`- ${now()} /test/interrupted-create fail -> ${JSON.stringify(f4)}`)
const h4 = await resolve(failed)
const x4 = f4.did ? await describe(f4.did) : null
const n4 = await noted(failed)
verdict(
  'k4',
  !!f4.did && !!f4.error && gone(h4) && gone(x4) && !n4,
  `the create's account ${f4.did ?? 'none'} failed (${f4.error}); the address now ${err(h4)}, its repo ${err(x4)}, a note left ${n4}`,
)

// ---------- k5 ----------
log('\n## k5 a create cut by the host stopping\n')
const hung = `kh${Date.now().toString(36)}`
const f5 = await testRoute('interrupted-create', { label: hung, creatorDid: alice.did, how: 'hang' })
log(`- ${now()} /test/interrupted-create hang -> ${JSON.stringify(f5)}`)
const before = await resolve(hung)
const notedBefore = await noted(hung)
log(`- ${now()} docker restart ${HOST_CONTAINER}`)
execFileSync('docker', ['restart', HOST_CONTAINER], { stdio: 'ignore' })
let up = false
for (let i = 0; i < 60 && !up; i++) {
  await sleep(2000)
  up = await fetch(`${HOST}/xrpc/_health`).then((r) => r.ok, () => false)
}
const h5 = await resolve(hung)
const x5 = f5.did ? await describe(f5.did) : null
const n5 = await noted(hung)
const kept = await describe(G)
verdict(
  'k5',
  before.status === 200 && before.body?.did === f5.did && notedBefore && up && gone(h5) && gone(x5) && !n5 && kept.status === 200,
  `before the restart the address resolved to the half-made ${f5.did} (${err(before)}), noted ${notedBefore}; host back ${up}; after, the address ${err(h5)}, its repo ${err(x5)}, noted ${n5}; alice's finished group ${err(kept)}`,
)

// ---------- k6 ----------
log('\n## k6 the freed address makes a group\n')
const B = await groupSignIn(alice, { create: { label: failed }, scopes: SCOPES })
const roles = B.ok ? (await state({ group: B.session.did, person: alice.did })).grants?.roles ?? [] : []
verdict('k6', B.ok && B.session.did !== f4.did && roles.includes('admin'), `create with ${failed} again ${B.ok ? `made ${B.session.did}` : 'did not reach the app'}; alice's roles ${JSON.stringify(roles)}`)

log(`\n- group of record: ${G}`)
summary()
