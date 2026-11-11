// grants.mjs: nobody grants more than they hold (the proposal's rule for
// `access` and `permissions` writes, proposal.md at 2b41a9b).
//   h1  the admin's group session gets each permission set it asks for, whole
//   h2  a moderator changes only the grants of roles it may assign
//   h3  a moderator adds only scopes its own roles hold, permission sets expanded; an admin
//       holding a set may grant it
//   h4  a moderator adds to an `assignable` list only roles it may assign
//   h5  one refused write in a batch leaves the whole batch unwritten
//   h6  createSpace grants only what the caller holds, to roles it may assign
// Run from probes/: snowglobe run node grants.mjs
import { META, MEMBERS, alice, bob, as, groupSignIn, listRecords, log, spaceUri, testRoute, state, summary, verdict } from './lib.mjs'

const NS = 'group.opensocial'
const SETS = ['configure', 'manageSpaces', 'manageMembers', 'moderate'].map((s) => `include:${NS}.${s}`)
const MANAGE = 'space:*?authority=self&action=read_self&manage=create'
const TYPE = 'test.grouphost.board' // no lexicon anywhere, so its grants name collections
const ADMIN_SCOPES = ['atproto', ...SETS, `space:${META}?authority=self&skey=self&collection=*`, `space:${MEMBERS}?authority=self&skey=self&collection=*`]
const MOD_SCOPES = [
  'atproto',
  `space:${MEMBERS}?authority=self&skey=self&collection=${NS}.membership`,
  `space:${MEMBERS}?authority=self&skey=self&collection=${NS}.permissions`,
  `space:${MEMBERS}?authority=self&skey=self&collection=${NS}.access`,
  `space:${META}?authority=self&skey=self&action=read`,
  MANAGE,
]
const said = (r) => `${r.status} ${r.body?.error ?? ''}`.trim()
const forbidden = (r) => r.status === 403 && r.body?.error === 'Forbidden'
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)

// ---------- setup: alice creates a group; the group adds a moderator role, and bob holds it ----------
log('\n## setup\n')
const label = `pg${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label }, scopes: ADMIN_SCOPES })
if (!A.ok) {
  verdict('setup', false, 'create flow did not reach the app')
  summary()
  process.exit(0)
}
const G = A.session.did
const MEM = spaceUri(G, MEMBERS)
const MET = spaceUri(G, META)

// ---------- h1 ----------
log('\n## h1 the admin gets each permission set whole\n')
verdict('h1', SETS.every((s) => A.kept.includes(s)), `kept ${SETS.filter((s) => A.kept.includes(s)).length}/${SETS.length} sets; dropped ${JSON.stringify(A.dropped)}`)

// The group itself adds the role and its grants: a role made after the group is in nobody's
// `assignable` list, so no person may grant it anything.
const writes = (list) => list.map(([verb, collection, rkey, record]) => ({ $type: `com.atproto.space.applyWrites#${verb}`, collection, rkey, value: { $type: collection, ...record } }))
const asGroup = (space, list) => testRoute('as-group', { group: G, space, writes: writes(list) })
const PERMISSIONS = [
  { role: 'admin', scopes: [...SETS, 'space:*?action=read_self&manage=create&manage=delete', 'space:*?collection=*', 'repo:*', 'blob:*/*'], assignable: ['admin', 'member', 'moderator'] },
  { role: 'member', scopes: [], assignable: [] },
  { role: 'moderator', scopes: ['space:*?action=read_self&manage=create'], assignable: ['member'] },
]
const MEM_ACCESS = [
  { role: 'admin', scopes: [`space:${MEMBERS}?collection=*`] },
  { role: 'member', scopes: [`space:${MEMBERS}?action=read`] },
  { role: 'moderator', scopes: [`space:${MEMBERS}?collection=${NS}.membership`, `space:${MEMBERS}?collection=${NS}.permissions`, `space:${MEMBERS}?collection=${NS}.access`] },
]
const setup = [
  await asGroup(MEM, [
    ['create', `${NS}.role`, 'moderator', { displayName: 'Moderator' }],
    ['update', `${NS}.permissions`, 'self', { grants: PERMISSIONS }],
    ['update', `${NS}.access`, 'self', { grants: MEM_ACCESS }],
    ['create', `${NS}.membership`, bob.did, { member: bob.did, roles: ['moderator'], createdAt: new Date().toISOString() }],
  ]),
  await asGroup(MET, [
    ['update', `${NS}.access`, 'self', {
      public: false,
      grants: [
        { role: 'admin', scopes: [`space:${META}?collection=*`] },
        { role: 'member', scopes: [`space:${META}?action=read`] },
        { role: 'moderator', scopes: [`space:${META}?action=read`] },
      ],
    }],
  ]),
]
log(`- setup writes, as the group: ${setup.map((r) => r.error ?? 'ok').join(' ')}`)
const B = await groupSignIn(bob, { groupDid: G, scopes: MOD_SCOPES })
const offered = B.ok && MOD_SCOPES.every((s) => B.kept.includes(s))
log(`- bob's session as moderator kept ${B.kept.length}/${MOD_SCOPES.length}: ${JSON.stringify(B.dropped)} dropped`)
if (setup.some((r) => r.error) || !offered) {
  verdict('setup', false, `setup ${setup.map((r) => r.error ?? 'ok').join(' ')}; bob offered every scope he asked: ${offered}`)
  summary()
  process.exit(0)
}

const record = async (space, collection) =>
  ((await listRecords(A.session, 'alice for the group', G, space === MEM ? MEMBERS : META)).body?.records ?? []).find((r) => r.collection === collection && r.rkey === 'self')?.value
const putAs = (s, who, space, collection, value) =>
  as(s, who, 'POST', 'com.atproto.space.putRecord', { body: { space, repo: G, collection, rkey: 'self', record: { $type: collection, ...value } } })
const asBob = (space, collection, value) => putAs(B.session, 'bob (moderator) for the group', space, collection, value)
const asAlice = (space, collection, value) => putAs(A.session, 'alice (admin) for the group', space, collection, value)
// The grants with one role's entry changed.
const withEntry = (grants, role, change) => grants.map((g) => (g.role === role ? change(structuredClone(g)) : g))
const addScope = (sc) => (g) => ({ ...g, scopes: [...g.scopes, sc] })
const addAssignable = (r) => (g) => ({ ...g, assignable: [...g.assignable, r] })

// ---------- h2 ----------
log("\n## h2 a moderator changes only the grants of roles it may assign\n")
const memAccess0 = await record(MEM, `${NS}.access`)
const h2admin = await asBob(MEM, `${NS}.access`, { grants: withEntry(memAccess0.grants, 'admin', (g) => ({ ...g, scopes: [`space:${MEMBERS}?action=read`] })) })
const h2mod = await asBob(MEM, `${NS}.access`, { grants: memAccess0.grants.filter((g) => g.role !== 'moderator') })
const memAccess1 = await record(MEM, `${NS}.access`)
verdict('h2', forbidden(h2admin) && forbidden(h2mod) && same(memAccess1, memAccess0), `narrow the admin's grant ${said(h2admin)}; drop his own role's ${said(h2mod)}; the members access record unchanged: ${same(memAccess1, memAccess0)}`)

// ---------- h3 ----------
log('\n## h3 a moderator adds only scopes its roles hold, sets expanded\n')
const unheld = await asBob(MEM, `${NS}.access`, { grants: withEntry(memAccess0.grants, 'member', addScope(`space:${MEMBERS}?collection=${NS}.role`)) })
const perms0 = await record(MEM, `${NS}.permissions`)
const unheldSet = await asBob(MEM, `${NS}.permissions`, { grants: withEntry(perms0.grants, 'member', addScope(`include:${NS}.manageMembers`)) })
const perms1 = await record(MEM, `${NS}.permissions`)
const held = await asBob(MEM, `${NS}.access`, { grants: withEntry(memAccess0.grants, 'member', addScope(`space:${MEMBERS}?collection=${NS}.membership&action=read`)) })
const memAccess2 = await record(MEM, `${NS}.access`)
const adminSet = await asAlice(MEM, `${NS}.permissions`, { grants: withEntry(perms1.grants, 'member', addScope(`include:${NS}.manageMembers`)) })
const perms2 = await record(MEM, `${NS}.permissions`)
verdict(
  'h3',
  forbidden(unheld) && forbidden(unheldSet) && same(perms1, perms0) && held.status === 200 && memAccess2?.grants?.find((g) => g.role === 'member')?.scopes.length === 2 &&
    adminSet.status === 200 && perms2?.grants?.find((g) => g.role === 'member')?.scopes.includes(`include:${NS}.manageMembers`),
  `bob grants role writes he lacks ${said(unheld)}; the manageMembers set he lacks ${said(unheldSet)} (permissions unchanged: ${same(perms1, perms0)}); a membership read he holds ${said(held)}; alice, who holds the set, grants it ${said(adminSet)}`,
)

// ---------- h4 ----------
log('\n## h4 a moderator adds to assignable only roles it may assign\n')
const perms3 = await record(MEM, `${NS}.permissions`)
const upward = await asBob(MEM, `${NS}.permissions`, { grants: withEntry(perms3.grants, 'member', addAssignable('moderator')) })
const perms4 = await record(MEM, `${NS}.permissions`)
const level = await asBob(MEM, `${NS}.permissions`, { grants: withEntry(perms4.grants, 'member', addAssignable('member')) })
const perms5 = await record(MEM, `${NS}.permissions`)
verdict(
  'h4',
  forbidden(upward) && same(perms4, perms3) && level.status === 200 && same(perms5?.grants?.find((g) => g.role === 'member')?.assignable, ['member']),
  `make moderator assignable by members ${said(upward)} (unchanged: ${same(perms4, perms3)}); make member assignable by members ${said(level)}`,
)

// ---------- h5 ----------
log('\n## h5 one refused write leaves the batch unwritten\n')
const access5 = await record(MEM, `${NS}.access`)
const perms6 = await record(MEM, `${NS}.permissions`)
const batch = await as(B.session, 'bob (moderator) for the group', 'POST', 'com.atproto.space.applyWrites', {
  body: {
    space: MEM,
    repo: G,
    writes: writes([
      ['update', `${NS}.access`, 'self', { grants: withEntry(access5.grants, 'member', addScope(`space:${MEMBERS}?collection=${NS}.membership&action=create`)) }],
      ['update', `${NS}.permissions`, 'self', { grants: withEntry(perms6.grants, 'member', addAssignable('admin')) }],
    ]),
  },
})
const access6 = await record(MEM, `${NS}.access`)
verdict('h5', forbidden(batch) && same(access6, access5), `an allowed access change with a refused permissions change ${said(batch)}; the access record unchanged: ${same(access6, access5)}`)

// ---------- h6 ----------
log('\n## h6 createSpace grants only what the caller holds, to roles it may assign\n')
const spaces = async () => (await state({ group: G })).spaces?.length
const create = (grants) => as(B.session, 'bob (moderator) for the group', 'POST', `${NS}.createSpace`, { body: { type: TYPE, access: { grants } } })
const before6 = await spaces()
const toAdmin = await create([{ role: 'admin', scopes: [] }])
const unheld6 = await create([{ role: 'member', scopes: [`space:${TYPE}?collection=*`] }])
const after6refused = await spaces()
const plain = await create([{ role: 'member', scopes: [] }])
const after6 = await spaces()
verdict(
  'h6',
  forbidden(toAdmin) && forbidden(unheld6) && after6refused === before6 && plain.status === 200 && after6 === before6 + 1,
  `a grant for the admin role ${said(toAdmin)}; a board scope he does not hold ${said(unheld6)}; spaces ${before6} then ${after6refused}; an empty grant for members ${said(plain)}, spaces ${after6}`,
)

summary()
process.exit(0)
