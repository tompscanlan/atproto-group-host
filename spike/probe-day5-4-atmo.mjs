// probe-day5-4-atmo.mjs: atmo's create at the group host (om-3r2nx.6.5). Alice signs up a group at
// the host with the scope atmo's create asks for (prompt=create); atmo's own set-up then runs on the
// session that comes back, and atmo's own repair, reads and upload check the result. atmo's D1 is the
// app's own schema in SQLite. The browser half (atmo's form, its OAuth client and callback route) is
// unit-tested in atmo; here the sign-up is the probe's.
//   h0  at sign-up alice is offered every item of atmo's group session, the calendar space's
//       included, though that space does not exist yet
//   h1  (acceptance 2) the new group's PLC document names the host as its PDS, and its members
//       space, read through the host with atmo's reader, holds alice's admin membership
//   h2  atmo's set-up made the calendar space through the host and wrote its own records there
//       (event bindings, profile, rules, meta made public with the host's grants kept), every one
//       taken by the host's write gate: the host logged no refusal for the group
//   h3  (acceptance 3) atmo's repair on the group finds nothing to fix: no membership restored,
//       orphaned or skipped, and the row unchanged
//   h4  (acceptance 4) the declaration reads back from the group's public repo with no auth; the
//       picture the form gave, which atmo's set-up uploaded and its profile names, reads back through
//       atmo's own avatar read with alice's own space credential, as the group page's route reads it
//   h5  a signed-out visitor gets no picture: the profile is a meta record, so an anonymous
//       sync.getBlob does not serve the blob
// Run from spike/, with atmo's checkout named (its scripts/ bundle the adapter):
//   ATMO_WEB=/workspaces/scratch/wt-atmo-events-group-host-adapter/apps/web \
//   DEVNET_LEAF_FILE=/workspaces/scratch/atproto-devnet/data/https/leaf.crt \
//     /workspaces/scratch/atproto-devnet/scripts/https-run node probe-day5-4-atmo.mjs > run-day5-4-atmo.log 2>&1
import path from 'node:path'
import { ALPHA, HERE, HOST, META, MEMBERS, alice, as, call, groupSignIn, log, now, ownSession, spaceUri, state, summary, verdict } from './lib.mjs'

const ATMO_WEB = process.env.ATMO_WEB ?? '/workspaces/scratch/wt-atmo-events-group-host-adapter/apps/web'
const { bundleAdapter } = await import(path.join(ATMO_WEB, 'scripts/group-host-adapter.build.mjs'))
const atmo = await import(await bundleAdapter(path.join(HERE, 'data/atmo-adapter')))

const NS = 'group.opensocial'
const CALENDAR = 'rsvp.atmo.group.calendar'
const SCOPES = ['atproto', ...atmo.GROUP_SESSION_SCOPES]
const FIELDS = {
  name: 'Day 5.4 group',
  description: 'Made at the host through atmo',
  visibility: 'public',
  requireApproval: true,
  rules: 'Be kind\nShow up',
}
// A 1x1 PNG.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64')
const env = { GROUP_HOST_URL: HOST }

log(`# probe-day5-4-atmo ${now()} atmo ${ATMO_WEB}`)

// ---------- h0: the sign-up ----------
log('\n## h0 alice signs up a group at the host with the scope atmo asks for\n')
const label = `d54g${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label, displayName: FIELDS.name }, scopes: SCOPES })
if (!A.ok) {
  verdict('setup', false, 'the sign-up did not reach the app')
  summary()
  process.exit(0)
}
const G = A.session.did
log(`- ${now()} group ${G} (${label})`)
const calendarItems = SCOPES.filter((s) => s.startsWith(`space:${CALENDAR}?`))
verdict(
  'h0',
  A.dropped.length === 0 && calendarItems.length > 0 && calendarItems.every((s) => A.kept.includes(s)),
  `offered ${A.kept.length} of ${SCOPES.length} items, not offered ${JSON.stringify(A.dropped)}; the calendar items (${calendarItems.length}) all offered before the space existed`,
)

// ---------- atmo's set-up ----------
log("\n## atmo's set-up on the session that came back\n")
const { db, raw } = atmo.sqliteD1()
const cred = { kind: 'linked', person: alice.did, session: A.session }
const setUp = await atmo.setUpHostGroup({ ...env, DB: db }, alice.did, FIELDS, cred, HOST, new Blob([PNG], { type: 'image/png' }))
log(`- ${now()} setUpHostGroup -> ${JSON.stringify(setUp)}`)
const row = await atmo.getGroupByDid(db, G)
const reader = atmo.pdsSpaceReader(cred, G)

// ---------- h1 ----------
log('\n## h1 the PLC document and the creator\'s membership\n')
const plc = await (await fetch(`https://plc.directory/${G}`)).json()
const pds = (plc.service ?? []).find((s) => s.id === '#atproto_pds')?.serviceEndpoint
log(`- ${now()} plc.directory/${G}: #atproto_pds ${pds}, alsoKnownAs ${JSON.stringify(plc.alsoKnownAs)}`)
const members = await atmo.readGroupMembers(reader, row)
const mine = members.memberships.find((m) => m.subject === alice.did)
log(`- ${now()} members as atmo reads them: ${JSON.stringify(members.memberships.map((m) => ({ subject: m.subject, roles: m.roleIds })))}; roles declared ${JSON.stringify(members.roles.map((r) => r.id))}`)
verdict(
  'h1',
  setUp.ok && pds === HOST && mine?.roleIds?.length === 1 && mine.roleIds[0] === 'admin',
  `set-up ${setUp.ok ? 'ok' : setUp.error}; PLC names ${pds} as the PDS (host ${HOST}); alice's membership in members: ${JSON.stringify(mine?.roleIds)}`,
)

// ---------- h2 ----------
log("\n## h2 atmo's records at the host, each taken by the host's gate\n")
const st = await state({ group: G })
const list = async (type, collection) =>
  ((await as(A.session, 'alice for the group', 'GET', 'com.atproto.space.listRecords', { params: { space: spaceUri(G, type), repo: G, collection, limit: '100' } })).body?.records ?? [])
const bindings = (await list(MEMBERS, 'rsvp.atmo.group.eventPermissions'))[0]?.value?.bindings ?? []
const profile = (await list(META, `${NS}.profile`))[0]?.value
const rules = await list(META, `${NS}.rule`)
const metaAccess = (await list(META, `${NS}.access`))[0]?.value
const calAccess = (await list(CALENDAR, `${NS}.access`))[0]?.value
const roleRecords = (await list(MEMBERS, `${NS}.role`)).map((r) => r.rkey)
log(`- bindings ${JSON.stringify(bindings)}; profile ${JSON.stringify(profile)}; rules ${rules.length}; meta access ${JSON.stringify(metaAccess)}; calendar access ${JSON.stringify(calAccess)}; roles ${JSON.stringify(roleRecords)}; host refusals for the group ${JSON.stringify(st.refusals)}`)
verdict(
  'h2',
  (st.spaces ?? []).includes(spaceUri(G, CALENDAR)) && st.refusals.length === 0 &&
    bindings.find((b) => b.role === 'admin')?.actions?.includes('createEvent') &&
    profile?.displayName === FIELDS.name && profile?.joinPolicy === 'approval' && profile?.avatar?.mimeType === 'image/png' && rules.length === 2 &&
    metaAccess?.public === true && metaAccess?.grants?.find((g) => g.role === 'admin')?.scopes?.[0] === `space:${META}?collection=*` &&
    calAccess?.grants?.map((g) => g.role).join() === 'admin,member' &&
    !roleRecords.includes('owner'),
  `calendar space ${(st.spaces ?? []).includes(spaceUri(G, CALENDAR)) ? 'made' : 'missing'}; host refusals ${st.refusals.length}; admin event bindings ${JSON.stringify(bindings.find((b) => b.role === 'admin')?.actions)}; profile ${profile?.displayName}/${profile?.joinPolicy}, avatar ${profile?.avatar?.mimeType} ${profile?.avatar?.size} bytes; rules ${rules.length}; meta public ${metaAccess?.public} with the host's admin grant ${metaAccess?.grants?.find((g) => g.role === 'admin')?.scopes?.[0]}; calendar access roles ${calAccess?.grants?.map((g) => g.role).join()}; role records ${JSON.stringify(roleRecords)}`,
)

// ---------- h3 ----------
log("\n## h3 atmo's repair finds nothing to fix\n")
const columns = (r) => r && { name: r.name, description: r.description, require_approval: r.require_approval, location_name: r.location_name, owner_did: r.owner_did, about: r.about_space_uri, members: r.members_space_uri }
const roster = () => raw.prepare(`SELECT m.did, r.name AS role FROM memberships m JOIN roles r ON r.id = m.role_id WHERE m.group_id = ? ORDER BY m.did`).all(row.id)
const before = { columns: columns(row), roster: roster() }
let repair
try {
  repair = await atmo.repairGroup({ db, env, group: row, callerDid: alice.did, ownReader: reader })
} catch (e) {
  repair = { error: String(e) }
}
const after = { columns: columns(await atmo.getGroupByDid(db, G)), roster: roster() }
const m = repair.rebuild?.members
log(`- repair: atHost ${repair.atHost}; rebuild ${repair.rebuild?.path}; members ${JSON.stringify(m)}; says: ${repair.error ?? atmo.describeRepair(repair)}`)
log(`- row and roster before ${JSON.stringify(before)}; after ${JSON.stringify(after)}`)
verdict(
  'h3',
  repair.atHost === true && repair.rebuild?.path === 'repaired' && m.restored.length === 0 && m.orphans.length === 0 &&
    m.skipped.length === 0 && m.unchanged.includes(alice.did) && JSON.stringify(before) === JSON.stringify(after),
  `repair ran at the host: ${repair.atHost}; restored ${m?.restored.length}, orphans ${m?.orphans.length}, skipped ${JSON.stringify(m?.skipped)}, unchanged ${JSON.stringify(m?.unchanged)}; row and roster unchanged: ${JSON.stringify(before) === JSON.stringify(after)}`,
)

// ---------- h4 ----------
log("\n## h4 the declaration, and the group's picture through atmo's own read\n")
const decl = await call('none', HOST, 'GET', 'com.atproto.repo.getRecord', { params: { repo: G, collection: `${NS}.declaration`, rkey: 'self' } })
const cid = profile?.avatar?.ref?.$link
// alice's own session, as the page's route holds a viewer's: atmo gets her a space credential for
// meta from it, and reads the blob with that.
const own = await ownSession(alice)
const holder = {
  did: own.did,
  handle: (pathname, init = {}) =>
    fetch(`${ALPHA}${pathname}`, { ...init, headers: { ...(init.headers ?? {}), authorization: `Bearer ${own.jwt}` } }),
}
let picture = null
let readError = null
try {
  picture = cid ? await atmo.readGroupAvatar(holder, row, cid) : null
} catch (e) {
  readError = String(e)
}
const same = picture ? Buffer.from(picture.bytes).equals(PNG) : false
log(`- ${now()} atmo's readGroupAvatar(alice's own credential, ${cid}) -> ${readError ?? (picture ? `${picture.type}, ${picture.bytes.byteLength} bytes, same bytes ${same}` : 'null')}`)
verdict(
  'h4',
  decl.status === 200 && decl.body?.value?.meta === spaceUri(G, META) && !!cid && picture?.type === 'image/png' && same,
  `declaration read with no auth ${decl.status}, meta ${decl.body?.value?.meta === spaceUri(G, META) ? 'the group meta space' : decl.body?.value?.meta}; the profile's avatar ${cid ? `${profile.avatar.mimeType}, ${profile.avatar.size} bytes` : 'missing'}; read back through atmo with alice's own credential: ${readError ?? (picture ? `${picture.type}, same bytes ${same}` : 'nothing')}`,
)

// ---------- h5 ----------
log('\n## h5 no picture for a signed-out visitor\n')
const anon = cid ? await call('none', HOST, 'GET', 'com.atproto.sync.getBlob', { params: { did: G, cid } }) : null
verdict(
  'h5',
  !!anon && anon.status !== 200,
  `anonymous sync.getBlob for the avatar -> ${anon?.status} ${anon?.body?.error ?? ''}`,
)

log(`\n- group of record: ${G}`)
summary()
