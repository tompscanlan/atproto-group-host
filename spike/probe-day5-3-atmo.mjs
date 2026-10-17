// probe-day5-3-atmo.mjs: atmo's own group-host seam (`groupHost`, its real-host adapter) driving
// this host (om-3r2nx.6.4). Alice makes two groups here, one open and one by approval; bob, signed
// in at his own PDS with OAuth, joins and leaves through atmo's code, which sends each call to his
// PDS for the group's host. atmo's D1 is the app's own schema in SQLite.
//   h0  atmo reads both groups as this host's (their PDS is GROUP_HOST_URL), and neither without it
//   h1  bob joins the open group: atmo answers joined and caches his row; the host logs requestJoin
//       from bob, the group as audience, admitted
//   h2  bob asks to join the approval group: atmo answers pending and notes it; the host keeps one
//       request, from bob
//   h3  bob withdraws it: the host logs cancelJoinRequest from bob and holds no request; atmo's
//       note is closed
//   h4  bob leaves the open group: the host logs leaveGroup from bob, and atmo's row for him goes
// Run from spike/, with atmo's checkout named (its scripts/ bundle the adapter):
//   ATMO_WEB=/workspaces/scratch/wt-atmo-events-group-host-adapter/apps/web \
//   DEVNET_LEAF_FILE=/workspaces/scratch/atproto-devnet/data/https/leaf.crt \
//     /workspaces/scratch/atproto-devnet/scripts/https-run node probe-day5-3-atmo.mjs > run-day5-3-atmo.log 2>&1
import path from 'node:path'
import { HERE, HOST, META, alice, as, bob, groupSignIn, log, now, ownOAuth, spaceUri, state, summary, verdict } from './lib.mjs'

const ATMO_WEB = process.env.ATMO_WEB ?? '/workspaces/scratch/wt-atmo-events-group-host-adapter/apps/web'
const { bundleAdapter } = await import(path.join(ATMO_WEB, 'scripts/group-host-adapter.build.mjs'))
const atmo = await import(await bundleAdapter(path.join(HERE, 'data/atmo-adapter')))

const NS = 'group.opensocial'
const MEMBER_RPC = ['requestJoin', 'cancelJoinRequest', 'leaveGroup'].map((m) => `rpc:${NS}.${m}?aud=*`)
const ALICE_SCOPES = ['atproto', `space:${META}?authority=self&skey=self&collection=*`]
const env = { GROUP_HOST_URL: HOST }

// ---------- setup: alice makes the two groups, bob signs in at his own PDS ----------
log(`# probe-day5-3-atmo ${now()} atmo ${ATMO_WEB}`)
async function makeGroup(name, joinPolicy) {
  const label = `d53${joinPolicy.slice(0, 1)}${Date.now().toString(36)}`
  const A = await groupSignIn(alice, { create: { label }, scopes: ALICE_SCOPES })
  if (!A.ok) throw new Error(`alice could not create ${name}`)
  const did = A.session.did
  const put = await as(A.session, `alice for ${name}`, 'POST', 'com.atproto.space.putRecord', {
    body: { space: spaceUri(did, META), repo: did, collection: `${NS}.profile`, rkey: 'self', record: { $type: `${NS}.profile`, displayName: name, joinPolicy } },
  })
  if (put.status !== 200) throw new Error(`${name}: joinPolicy ${joinPolicy} not set (${put.status})`)
  log(`- ${now()} ${name} is ${did}, joinPolicy ${joinPolicy}`)
  return did
}
const OPEN = await makeGroup('Day 5.3 open group', 'open')
const APPROVAL = await makeGroup('Day 5.3 approval group', 'approval')

const { db } = atmo.sqliteD1()
async function atmoRow(did, name, requireApproval) {
  const row = await atmo.createGroup(db, { groupDid: did, ownerDid: alice.did, name, requireApproval })
  await atmo.recordGroupSpaces(db, row.id, atmo.groupSpaceUris(did))
  return { ...row, ...{ about_space_uri: atmo.groupSpaceUris(did).aboutSpaceUri, members_space_uri: atmo.groupSpaceUris(did).membersSpaceUri } }
}
const openRow = await atmoRow(OPEN, 'Day 5.3 open group', false)
const approvalRow = await atmoRow(APPROVAL, 'Day 5.3 approval group', true)

const own = await ownOAuth(bob, ['atproto', ...MEMBER_RPC])
const member = { did: own.session.did, scope: own.scope, handle: (p, init) => own.session.handle(p, init) }
const caller = { callerDid: bob.did, member }
const openHost = atmo.groupHost({ db, env, group: openRow })
const approvalHost = atmo.groupHost({ db, env, group: approvalRow })

// The host's log since `before`, for one group.
const callsSince = async (group, before) => ((await state({ group })).methodCalls ?? []).filter((c) => c.at > before)
const fromBob = (c, nsid, group) => c.nsid === nsid && c.member === bob.did && c.aud === group
const attempt = async (what, act) => {
  try {
    const out = await act()
    log(`- ${now()} atmo ${what} -> ${JSON.stringify(out ?? 'ok')}`)
    return { out }
  } catch (e) {
    log(`- ${now()} atmo ${what} threw ${e?.name}: ${e?.message}`)
    return { error: e }
  }
}

// h0
const h0 = [await atmo.isHostGroup(env, OPEN), await atmo.isHostGroup(env, APPROVAL), await atmo.isHostGroup({}, OPEN)]
verdict('h0', h0.join() === 'true,true,false', `isHostGroup with GROUP_HOST_URL: open ${h0[0]}, approval ${h0[1]}; without it: ${h0[2]}`)

// h1
let t = new Date().toISOString()
const joined = await attempt('requestJoin (open group)', () => openHost.requestJoin(caller, null))
let seen = await callsSince(OPEN, t)
log(`- host logged: ${JSON.stringify(seen)}`)
const row = await atmo.getMemberRow(db, openRow.id, bob.did)
verdict(
  'h1',
  joined.out === 'joined' && row?.role === 'member' && seen.length === 1 && fromBob(seen[0], 'requestJoin', OPEN) && /^admitted/.test(seen[0].result),
  `atmo: ${joined.out ?? joined.error?.name}, row ${row?.role ?? 'none'}; host: ${seen.map((c) => `${c.nsid} from ${c.member === bob.did ? 'bob' : c.member} aud ${c.aud === OPEN ? 'group' : c.aud} ${c.result}`).join('; ')}`,
)

// h2
t = new Date().toISOString()
const asked = await attempt('requestJoin (approval group)', () => approvalHost.requestJoin(caller, 'from atmo'))
seen = await callsSince(APPROVAL, t)
let requests = (await state({ group: APPROVAL })).joinRequests ?? []
const note = await atmo.pendingRequestIdOf(db, approvalRow.id, bob.did)
verdict(
  'h2',
  asked.out === 'pending' && note !== null && seen.length === 1 && fromBob(seen[0], 'requestJoin', APPROVAL) && requests.length === 1 && requests[0].member === bob.did && requests[0].message === 'from atmo',
  `atmo: ${asked.out ?? asked.error?.name}, note ${note ? 'kept' : 'none'}; host: ${seen.map((c) => `${c.nsid} ${c.result}`).join('; ')}; requests held ${requests.length}`,
)

// h3
t = new Date().toISOString()
const withdrawn = await attempt('cancelJoinRequest (approval group)', () => approvalHost.cancelJoinRequest(caller))
seen = await callsSince(APPROVAL, t)
requests = (await state({ group: APPROVAL })).joinRequests ?? []
const noteAfter = await atmo.pendingRequestIdOf(db, approvalRow.id, bob.did)
verdict(
  'h3',
  !withdrawn.error && noteAfter === null && seen.length === 1 && fromBob(seen[0], 'cancelJoinRequest', APPROVAL) && requests.length === 0,
  `atmo: ${withdrawn.error?.name ?? 'ok'}, note ${noteAfter ? 'still open' : 'closed'}; host: ${seen.map((c) => `${c.nsid} ${c.result}`).join('; ')}; requests held ${requests.length}`,
)

// h4
t = new Date().toISOString()
const left = await attempt('leaveGroup (open group)', () => openHost.leaveGroup(caller))
seen = await callsSince(OPEN, t)
const rowAfter = await atmo.getMemberRow(db, openRow.id, bob.did)
verdict(
  'h4',
  !left.error && rowAfter === null && seen.length === 1 && fromBob(seen[0], 'leaveGroup', OPEN) && /^left/.test(seen[0].result),
  `atmo: ${left.error?.name ?? 'ok'}, row ${rowAfter ? 'still there' : 'gone'}; host: ${seen.map((c) => `${c.nsid} ${c.result}`).join('; ')}`,
)

log(`\nGroups made: ${OPEN} (open), ${APPROVAL} (approval). Bob holds no request or membership in either.`)
summary()
