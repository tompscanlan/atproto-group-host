// probe-day3.mjs: the host enforces from the group's records, on the https devnet.
//   e1  a space credential follows the person's roles in that space's `access` record
//   e2  a role that may write memberships may assign only its `assignable` roles
//   e3  membership, role, access and permissions writes follow their record rules
//   e4  the 10-11 walk's member refusals: a plain member's session is refused all five
//   e5  a removed member gets no credential and is not tracked as a writer
//   e6  a public `access` record lets anyone read that space, and only that one
//   e7  nobody reconfigures a group space through simplespace, an admin's session included
//   e8  the group writes only in spaces that have an `access` record
// Run: ../atproto-devnet/scripts/https-run node probe-day3.mjs 2>&1 | tee run-day3.log
import {
  HOST, META, MEMBERS, alice, bob, as, asOwn, credentialFor, groupSignIn, listRecords, listWriters, log, ownSession, sleep, spaceUri, spike, state, summary, verdict,
} from './lib.mjs'

const NS = 'group.opensocial'
const SCOPES = [
  'atproto',
  `space:${META}?authority=self&skey=self&collection=*`,
  `space:${MEMBERS}?authority=self&skey=self&collection=*`,
  'space:*?authority=self&action=read_self&manage=create&manage=delete',
  'space:*?authority=self&collection=com.atproto.label.label&action=create&action=update&action=delete',
  `space:${META}?authority=self&skey=self&action=read`,
  `space:${MEMBERS}?authority=self&skey=self&action=read`,
  `space:${MEMBERS}?authority=self&skey=self&collection=${NS}.membership`,
]
const CAROL = 'did:plc:carolcarolcarolcarol2345' // membership subjects only; they never sign in
const DAVE = 'did:plc:davedavedavedavedave2345'
const ts = () => new Date().toISOString()
const membership = (did, roles) => ({ $type: `${NS}.membership`, member: did, roles, createdAt: ts() })

// ---------- setup: alice creates a group and adds a moderator role ----------
log('\n## setup: alice creates a group and adds a moderator role\n')
const label = `d3g${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label, displayName: 'Day three group' }, label: 'e-consent-alice-create', scopes: SCOPES })
if (!A.ok) {
  verdict('setup', false, 'create flow did not reach the app')
  summary()
  process.exit(0)
}
const G = A.session.did
const MEM = spaceUri(G, MEMBERS)
const MET = spaceUri(G, META)
const asA = (method, nsid, body) => as(A.session, 'alice for the group', method, nsid, { body })
const put = (space, collection, rkey, record) => asA('POST', 'com.atproto.space.putRecord', { space, repo: G, collection, rkey, record: { $type: collection, ...record } })
const create = (s, who, space, collection, rkey, record) =>
  as(s, who, 'POST', 'com.atproto.space.createRecord', { body: { space, repo: G, collection, ...(rkey ? { rkey } : {}), record: { $type: collection, ...record } } })
const del = (s, who, space, collection, rkey) => as(s, who, 'POST', 'com.atproto.space.deleteRecord', { body: { space, repo: G, collection, rkey } })

const setup = [
  await create(A.session, 'alice for the group', MEM, `${NS}.role`, 'moderator', { displayName: 'Moderator' }),
  await put(MEM, `${NS}.permissions`, 'self', {
    grants: [
      {
        role: 'admin',
        scopes: ['space:*?action=read_self&manage=create&manage=delete', 'space:*?collection=com.atproto.label.label&action=create&action=update&action=delete'],
        assignable: ['admin', 'member', 'moderator'],
      },
      { role: 'member', scopes: [], assignable: [] },
      { role: 'moderator', scopes: [], assignable: ['member'] },
    ],
  }),
  await put(MEM, `${NS}.access`, 'self', {
    grants: [
      { role: 'admin', scopes: [`space:${MEMBERS}?collection=*`] },
      { role: 'member', scopes: [`space:${MEMBERS}?action=read`] },
      { role: 'moderator', scopes: [`space:${MEMBERS}?collection=${NS}.membership`] },
    ],
  }),
  await put(MET, `${NS}.access`, 'self', {
    public: false,
    grants: [
      { role: 'admin', scopes: [`space:${META}?collection=*`] },
      { role: 'member', scopes: [`space:${META}?action=read`] },
      { role: 'moderator', scopes: [`space:${META}?action=read`] },
    ],
  }),
]
const setupOk = setup.every((r) => r.status === 200)
log(`- setup writes: ${setup.map((r) => r.status).join(' ')}`)

// ---------- e1 ----------
log('\n## e1 a space credential follows the roles in the access record\n')
const aliceOwn = await ownSession(alice)
const bobOwn = await ownSession(bob)
const b0 = await credentialFor(bobOwn, MEM)
const madeMod = await create(A.session, 'alice for the group', MEM, `${NS}.membership`, bob.did, membership(bob.did, ['moderator']))
const b1 = await credentialFor(bobOwn, MEM)
const a1 = await credentialFor(aliceOwn, MEM)
let st = await state({ group: G })
log(`- host's last access answers: ${JSON.stringify(st.accessCalls.slice(-4).map((c) => ({ user: c.user.slice(-6), kind: c.kind, authorized: c.authorized, why: c.why })))}`)
verdict('e1', setupOk && madeMod.status === 200 && b0.status !== 200 && b1.status === 200 && a1.status === 200, `bob with no role ${b0.status} ${b0.body?.error ?? ''}; bob as moderator ${b1.status}; alice as admin ${a1.status}; answers came from the records`)

// ---------- e2 ----------
log('\n## e2 a moderator may assign only the roles its assignable list names\n')
const B = await groupSignIn(bob, { groupDid: G, label: 'e-consent-bob-moderator', scopes: SCOPES })
let e2 = false
if (B.ok) {
  const asB = (method, nsid, body) => as(B.session, 'bob (moderator) for the group', method, nsid, { body })
  const admit = await create(B.session, 'bob (moderator) for the group', MEM, `${NS}.membership`, CAROL, membership(CAROL, ['member']))
  const promote = await asB('POST', 'com.atproto.space.putRecord', { space: MEM, repo: G, collection: `${NS}.membership`, rkey: CAROL, record: membership(CAROL, ['admin']) })
  const ejectAdmin = await del(B.session, 'bob (moderator) for the group', MEM, `${NS}.membership`, alice.did)
  const batch = await asB('POST', 'com.atproto.space.applyWrites', {
    space: MEM,
    repo: G,
    writes: [
      { $type: 'com.atproto.space.applyWrites#create', collection: `${NS}.membership`, rkey: DAVE, value: membership(DAVE, ['member']) },
      { $type: 'com.atproto.space.applyWrites#update', collection: `${NS}.membership`, rkey: CAROL, value: membership(CAROL, ['admin']) },
    ],
  })
  const after = await listRecords(A.session, 'alice for the group', G, MEMBERS)
  const ms = Object.fromEntries((after.body?.records ?? []).filter((r) => r.collection === `${NS}.membership`).map((r) => [r.rkey, r.value.roles]))
  const ejectMember = await del(B.session, 'bob (moderator) for the group', MEM, `${NS}.membership`, CAROL)
  const offered = B.kept.includes(`space:${MEMBERS}?authority=self&skey=self&collection=${NS}.membership`) && !B.kept.includes(`space:${MEMBERS}?authority=self&skey=self&collection=*`)
  e2 =
    offered &&
    admit.status === 200 &&
    promote.status === 403 && promote.body?.error === 'NotAssignable' &&
    ejectAdmin.status === 403 && ejectAdmin.body?.error === 'NotAssignable' &&
    batch.status === 403 && batch.body?.error === 'NotAssignable' &&
    !ms[DAVE] && JSON.stringify(ms[CAROL]) === '["member"]' && JSON.stringify(ms[alice.did]) === '["admin"]' &&
    ejectMember.status === 200
  verdict('e2', e2, `bob was offered membership writes, not collection=*; admit a member ${admit.status}; promote to admin ${promote.status} ${promote.body?.error ?? ''}; eject the admin ${ejectAdmin.status} ${ejectAdmin.body?.error ?? ''}; a batch with one promotion ${batch.status} ${batch.body?.error ?? ''} and wrote nothing (dave ${ms[DAVE] ? 'present' : 'absent'}, carol ${JSON.stringify(ms[CAROL])}); eject a member ${ejectMember.status}`)
} else verdict('e2', false, "bob's sign-in did not reach the app")

// ---------- e3 ----------
log('\n## e3 record rules, for the admin too\n')
const cases = [
  ['membership key is not the member', 'InvalidMembership', () => create(A.session, 'alice', MEM, `${NS}.membership`, DAVE, membership(CAROL, ['member']))],
  ['undeclared role', 'UnknownRole', () => create(A.session, 'alice', MEM, `${NS}.membership`, DAVE, membership(DAVE, ['ghost']))],
  ['two grants for one role', 'InvalidGrants', () => put(MET, `${NS}.access`, 'self', { grants: [{ role: 'member', scopes: [`space:${META}?action=read`] }, { role: 'member', scopes: [] }] })],
  ['grant to an undeclared role', 'UnknownRole', () => put(MET, `${NS}.access`, 'self', { grants: [{ role: 'ghost', scopes: [`space:${META}?action=read`] }] })],
  ['scope that does not resolve', 'InvalidScope', () => put(MET, `${NS}.access`, 'self', { grants: [{ role: 'member', scopes: [`include:${NS}.noSuchSet`] }] })],
  ['delete a role someone holds', 'RoleInUse', () => del(A.session, 'alice', MEM, `${NS}.role`, 'moderator')],
  ['membership outside the members space', 'WrongSpace', () => create(A.session, 'alice', MET, `${NS}.membership`, DAVE, membership(DAVE, ['member']))],
]
const e3r = []
for (const [what, want, run] of cases) {
  const r = await run()
  e3r.push({ what, want, got: `${r.status} ${r.body?.error ?? ''}`, ok: r.status === 403 && r.body?.error === want })
}
// The gate reads the body whatever its content type says.
const mislabeled = await A.session.handle('/xrpc/com.atproto.space.createRecord', {
  method: 'POST',
  headers: { 'content-type': 'text/plain' },
  body: JSON.stringify({ space: MEM, repo: G, collection: `${NS}.membership`, rkey: DAVE, record: membership(DAVE, ['ghost']) }),
})
const mislabeledBody = await mislabeled.json().catch(() => ({}))
log(`- mislabeled body (text/plain) with an undeclared role -> ${mislabeled.status} ${mislabeledBody.error ?? ''}`)
log(`- e3 cases: ${JSON.stringify(e3r)}`)
verdict('e3', e3r.every((c) => c.ok) && mislabeled.status !== 200, `${e3r.filter((c) => c.ok).length}/${e3r.length} refused with the expected error (${e3r.map((c) => c.want).join(', ')}); a mislabeled body ${mislabeled.status}`)

// ---------- e4 ----------
log("\n## e4 the 10-11 walk's member refusals\n")
const demoted = await put(MEM, `${NS}.membership`, bob.did, membership(bob.did, ['member']))
if (B.ok) {
  const s = B.session
  const who = 'bob (now a member) for the group'
  const walk = [
    ['settings save', await as(s, who, 'POST', 'com.atproto.space.putRecord', { body: { space: MET, repo: G, collection: `${NS}.profile`, rkey: 'self', record: { $type: `${NS}.profile`, displayName: 'Taken over', joinPolicy: 'open' } } })],
    ['admit', await create(s, who, MEM, `${NS}.membership`, DAVE, membership(DAVE, ['member']))],
    ['promote', await as(s, who, 'POST', 'com.atproto.space.putRecord', { body: { space: MEM, repo: G, collection: `${NS}.membership`, rkey: bob.did, record: membership(bob.did, ['admin']) } })],
    ['eject', await del(s, who, MEM, `${NS}.membership`, alice.did)],
    ['repair (authz config)', await as(s, who, 'POST', 'com.atproto.space.putRecord', { body: { space: MEM, repo: G, collection: `${NS}.permissions`, rkey: 'self', record: { $type: `${NS}.permissions`, grants: [] } } })],
  ]
  const read = await listRecords(s, who, G, MEMBERS)
  verdict('e4', demoted.status === 200 && walk.every(([, r]) => r.status === 403) && read.status === 200, `bob's same session after alice made him a plain member: ${walk.map(([w, r]) => `${w} ${r.status} ${r.body?.error ?? ''}`).join('; ')}; he still reads members ${read.status}`)
} else verdict('e4', false, 'no bob session')

// ---------- e5 ----------
log('\n## e5 a removed member gets no credential and is not tracked as a writer\n')
const removed = await del(A.session, 'alice for the group', MEM, `${NS}.membership`, bob.did)
const b5 = await credentialFor(bobOwn, MEM)
const acc = (own) => asOwn(own, 'POST', 'com.atproto.space.createRecord', { body: { space: MEM, repo: own.did, collection: `${NS}.acceptance`, rkey: 'self', record: { $type: `${NS}.acceptance`, createdAt: ts() } } })
const aAcc = await acc(aliceOwn)
const bAcc = await acc(bobOwn)
await sleep(4000)
const a5 = await credentialFor(aliceOwn, MEM)
const writers = a5.cred ? await listWriters(a5.cred, MEM, G) : []
verdict('e5', removed.status === 200 && b5.status !== 200 && aAcc.status === 200 && bAcc.status === 200 && writers.includes(alice.did) && !writers.includes(bob.did), `after removal bob's credential ${b5.status} ${b5.body?.error ?? ''}; both acceptances landed on alpha (${aAcc.status}, ${bAcc.status}); writers listed: alice ${writers.includes(alice.did)}, bob ${writers.includes(bob.did)}`)

// ---------- e6 ----------
log('\n## e6 a public access record opens that space only\n')
const pub = await put(MET, `${NS}.access`, 'self', {
  public: true,
  grants: [
    { role: 'admin', scopes: [`space:${META}?collection=*`] },
    { role: 'member', scopes: [`space:${META}?action=read`] },
  ],
})
const b6meta = await credentialFor(bobOwn, MET)
const b6mem = await credentialFor(bobOwn, MEM)
verdict('e6', pub.status === 200 && b6meta.status === 200 && b6mem.status !== 200, `meta made public: bob (no role) gets a meta credential ${b6meta.status} and still none for members ${b6mem.status}`)

// ---------- e7 ----------
log('\n## e7 no simplespace reconfiguration of group spaces\n')
const PUBLIC = { $type: 'com.atproto.simplespace.defs#publicPolicy' }
const ss = [
  ['createSpace', await asA('POST', 'com.atproto.simplespace.createSpace', { spaceType: META, skey: 'e7', readPolicy: PUBLIC, writePolicy: PUBLIC, appAccess: { $type: 'com.atproto.simplespace.defs#open' } })],
  ['updateSpace', await asA('POST', 'com.atproto.simplespace.updateSpace', { space: MEM, readPolicy: PUBLIC })],
  ['putMember', await asA('POST', 'com.atproto.simplespace.putMember', { space: MEM, did: bob.did, read: true, write: true })],
  ['deleteSpace', await asA('POST', 'com.atproto.simplespace.deleteSpace', { space: MEM })],
]
const still = await listRecords(A.session, 'alice for the group', G, MEMBERS)
verdict('e7', ss.every(([, r]) => r.status === 403 && r.body?.error === 'GroupSpaceManaged') && still.status === 200, `alice's admin session (it holds manage=create and manage=delete): ${ss.map(([n, r]) => `${n} ${r.status} ${r.body?.error ?? ''}`).join('; ')}; members space still reads ${still.status}`)

// ---------- e8 ----------
log('\n## e8 the group writes only in declared spaces\n')
const bare = await spike('bare-space', { group: G, skey: 'bare' })
const label8 = (space) => create(A.session, 'alice for the group', space, 'com.atproto.label.label', undefined, { uri: `at://${G}`, val: 'spike', createdAt: ts() })
const inBare = await label8(bare.space)
const inMeta = await label8(MET)
verdict('e8', inBare.status === 403 && inBare.body?.error === 'UndeclaredSpace' && inMeta.status === 200, `a label (a grant across all spaces) into a space with no access record ${inBare.status} ${inBare.body?.error ?? ''}; into meta ${inMeta.status}`)

st = await state({ group: G })
log(`\n- host refusals for the group: ${JSON.stringify(st.refusals.map((r) => `${r.nsid} ${r.error}`))}`)
summary()
process.exit(0)
