// probe-day5.mjs: the admin role's seeded grants include repo: and blob: (om-3r2nx.6.2), so an
// admin's group session can write the group's public repo and upload images, as atmo needs for
// the declaration, the group's avatar and public group events.
//   h1  a new group's admin role is granted repo:* and blob:*/*, and alice, its creator, is
//       offered atmo's repo: and blob: items at consent
//   h2  with that group session she writes group.opensocial.declaration to the group's public repo
//       (com.atproto.repo.putRecord) and uploads an image (com.atproto.repo.uploadBlob); anyone
//       reads the declaration back
//   h3  bob as a member is not offered either item, and his group session's putRecord and
//       uploadBlob are refused; the declaration is unchanged
//   h4  the cut on every request covers them too: bob made admin is offered both and writes; demoted
//       to member, the same session is refused
//   h5  admin reads and writes in every group space (TS, 2026-10-15): alice's session from the create,
//       authorized before the calendar space existed, makes that space and writes an event in it
// Run from spike/ (Chromium needs the devnet's leaf certificate):
//   DEVNET_LEAF_FILE=/workspaces/scratch/atproto-devnet/data/https/leaf.crt \
//     /workspaces/scratch/atproto-devnet/scripts/https-run node probe-day5.mjs > run-day5.log 2>&1
import { HOST, META, MEMBERS, alice, bob, as, call, groupSignIn, log, now, spaceUri, state, summary, verdict } from './lib.mjs'

const NS = 'group.opensocial'
const DECLARATION = `${NS}.declaration`
// What atmo's group session asks for (atmo-events apps/web/src/lib/groups/server/session.ts,
// scope.repo and scope.blob from @atcute/oauth-node-client), word for word.
const REPO = `repo?collection=${DECLARATION}&collection=community.lexicon.calendar.event`
const BLOB = 'blob?accept=image/*'
// atmo's calendar space type, published on the devnet's lexicon authority (day 5.2b).
const CALENDAR = 'rsvp.atmo.group.calendar'
const EVENT = 'community.lexicon.calendar.event'
const CAL_READ = `space:${CALENDAR}?authority=self&action=read`
const CAL_WRITE = `space:${CALENDAR}?authority=self&collection=${EVENT}&action=create&action=update&action=delete`
const MANAGE = 'space:*?authority=self&manage=create'
const SCOPES = [
  'atproto', `space:${META}?authority=self&skey=self&collection=*`, `space:${MEMBERS}?authority=self&skey=self&collection=*`,
  REPO, BLOB, CAL_READ, CAL_WRITE, MANAGE,
]
// A 1x1 PNG.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64')
const ts = () => new Date().toISOString()
const err = (r) => `${r?.status} ${r?.body?.error ?? ''}`.trim()
const offered = (signIn) => [REPO, BLOB].filter((s) => signIn.kept.includes(s))
const offeredCalendar = (signIn) => [CAL_READ, CAL_WRITE].filter((s) => signIn.kept.includes(s))

async function upload(session, who) {
  const res = await session.handle('/xrpc/com.atproto.repo.uploadBlob', { method: 'POST', headers: { 'content-type': 'image/png' }, body: PNG })
  const text = await res.text()
  let body
  try {
    body = JSON.parse(text)
  } catch {
    body = text.slice(0, 200)
  }
  log(`- ${now()} POST com.atproto.repo.uploadBlob image/png ${PNG.length} bytes (as ${who}) -> ${res.status} ${JSON.stringify(body)?.slice(0, 300)}`)
  return { status: res.status, body }
}
const declare = (session, who, group, meta) =>
  as(session, who, 'POST', 'com.atproto.repo.putRecord', { body: { repo: group, collection: DECLARATION, rkey: 'self', record: { $type: DECLARATION, meta } } })
const readDeclaration = (group) => call('none', HOST, 'GET', 'com.atproto.repo.getRecord', { params: { repo: group, collection: DECLARATION, rkey: 'self' } })

log(`# probe-day5 ${now()}`)

// ---------- h1 ----------
log('\n## h1 alice creates a group; admin is granted repo: and blob:\n')
const label = `d5g${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label }, scopes: SCOPES })
if (!A.ok) {
  verdict('setup', false, 'create flow did not reach the app')
  summary()
  process.exit(0)
}
const G = A.session.did
const MET = spaceUri(G, META)
const MEM = spaceUri(G, MEMBERS)
log(`- group ${G} (${label})`)
const asA = (method, nsid, body) => as(A.session, 'alice for the group', method, nsid, { body })
const putA = (space, collection, rkey, record) => asA('POST', 'com.atproto.space.putRecord', { space, repo: G, collection, rkey, record: { $type: collection, ...record } })
const aliceGrants = (await state({ group: G, person: alice.did })).grants?.scopes ?? []
log(`- alice's grants as the host expands them: ${JSON.stringify(aliceGrants)}`)
verdict(
  'h1',
  aliceGrants.includes('repo:*') && aliceGrants.includes('blob:*/*') && offered(A).length === 2,
  `admin granted repo:* ${aliceGrants.includes('repo:*')}, blob:*/* ${aliceGrants.includes('blob:*/*')}; alice offered ${JSON.stringify(offered(A))}, not offered ${JSON.stringify(A.dropped)}`,
)

// ---------- h2 ----------
// The lexicon says to publish the declaration only when meta is public, so meta goes public first.
log("\n## h2 alice's group session writes the declaration and uploads an image\n")
const pub = await putA(MET, `${NS}.access`, 'self', {
  public: true,
  grants: [
    { role: 'admin', scopes: [`space:${META}?collection=*`] },
    { role: 'member', scopes: [`space:${META}?action=read`] },
  ],
})
const d2 = await declare(A.session, 'alice for the group', G, MET)
const u2 = await upload(A.session, 'alice for the group')
const r2 = await readDeclaration(G)
verdict(
  'h2',
  pub.status === 200 && d2.status === 200 && u2.status === 200 && u2.body?.blob?.mimeType === 'image/png' && r2.status === 200 && r2.body?.value?.meta === MET,
  `meta made public ${pub.status}; putRecord ${DECLARATION} ${err(d2)}; uploadBlob ${err(u2)} (${u2.body?.blob?.mimeType}, ${u2.body?.blob?.size} bytes); read back with no auth ${err(r2)}, meta ${r2.body?.value?.meta === MET ? 'is the group meta space' : r2.body?.value?.meta}`,
)

// ---------- h3 ----------
log('\n## h3 bob as a member gets neither\n')
const add3 = await putA(MEM, `${NS}.membership`, bob.did, { member: bob.did, roles: ['member'], createdAt: ts() })
const B = await groupSignIn(bob, { groupDid: G, scopes: SCOPES })
const d3 = B.ok ? await declare(B.session, 'bob (member) for the group', G, MEM) : null
const u3 = B.ok ? await upload(B.session, 'bob (member) for the group') : null
const r3 = await readDeclaration(G)
verdict(
  'h3',
  add3.status === 200 && B.ok && offered(B).length === 0 && B.dropped.includes(REPO) && B.dropped.includes(BLOB) &&
    d3?.status === 403 && u3?.status === 403 && r3.body?.value?.meta === MET,
  `bob added as member ${add3.status}; offered ${JSON.stringify(offered(B))}, not offered ${JSON.stringify(B.dropped)}; his putRecord ${err(d3)}, uploadBlob ${err(u3)}; the declaration's meta after ${r3.body?.value?.meta === MET ? 'unchanged' : r3.body?.value?.meta}`,
)

// ---------- h4 ----------
log('\n## h4 the per-request cut follows the roles for repo: and blob:\n')
const admin4 = await putA(MEM, `${NS}.membership`, bob.did, { member: bob.did, roles: ['admin'], createdAt: ts() })
const B2 = await groupSignIn(bob, { groupDid: G, scopes: SCOPES })
const d4a = B2.ok ? await declare(B2.session, 'bob (admin) for the group', G, MET) : null
const u4a = B2.ok ? await upload(B2.session, 'bob (admin) for the group') : null
const demote4 = await putA(MEM, `${NS}.membership`, bob.did, { member: bob.did, roles: ['member'], createdAt: ts() })
const d4b = B2.ok ? await declare(B2.session, 'bob (now a member), same session', G, MET) : null
const u4b = B2.ok ? await upload(B2.session, 'bob (now a member), same session') : null
const st = await state({ group: G })
const cuts = st.narrowings.filter((n) => n.personDid === bob.did && n.from.includes(REPO) && !n.to.includes(REPO) && n.from.includes(BLOB) && !n.to.includes(BLOB)).length
verdict(
  'h4',
  admin4.status === 200 && B2.ok && offered(B2).length === 2 && d4a?.status === 200 && u4a?.status === 200 &&
    demote4.status === 200 && d4b?.status === 403 && u4b?.status === 403 && cuts > 0,
  `bob made admin ${admin4.status}, offered ${offered(B2).length} of 2; his putRecord ${err(d4a)}, uploadBlob ${err(u4a)}; demoted ${demote4.status}; the same session's putRecord ${err(d4b)}, uploadBlob ${err(u4b)}; host cuts that dropped both for bob ${cuts}`,
)

// ---------- h5 ----------
log("\n## h5 alice's create-time session makes the calendar space and writes in it\n")
const CAL = spaceUri(G, CALENDAR)
const made = await asA('POST', `${NS}.createSpace`, {
  type: CALENDAR,
  skey: 'self',
  access: { grants: [{ role: 'admin', scopes: [`space:${CALENDAR}?collection=*`] }, { role: 'member', scopes: [`space:${CALENDAR}?action=read`] }] },
})
const ev = await asA('POST', 'com.atproto.space.createRecord', {
  space: CAL, repo: G, collection: EVENT, record: { $type: EVENT, name: 'Day five meetup', createdAt: ts() },
})
verdict(
  'h5',
  offeredCalendar(A).length === 2 && made.status === 200 && made.body?.space === CAL && ev.status === 200,
  `at create alice was offered ${offeredCalendar(A).length} of 2 calendar items, before the space existed; createSpace ${err(made)} (${made.body?.space === CAL ? 'the calendar space' : made.body?.space}); an event written there with the same session ${err(ev)}`,
)

log(`\n- group of record: ${G}`)
summary()
