// probe-day4.mjs: a person's own acts on a group, with service auth from their own PDS.
//   f1  requestJoin through the person's own PDS reaches the host with the group as the token's
//       audience, and an approval group keeps one pending request however often they ask
//   f2  the host checks that service auth: none, a group session, the host as audience, another
//       group as audience, and a token for another method are refused; a group not hosted here
//       is GroupNotFound
//   f3  writing the requester's membership approves them: requestJoin answers admitted, the
//       request is gone, and they get a credential
//   f4  an open group admits at once with its default roles, the membership written by the group
//   f5  an invite-only group refuses, and so does an invitation (this host issues none)
// Run from spike/: /workspaces/scratch/atproto-devnet/scripts/https-run node probe-day4.mjs 2>&1 | tee run-day4.log
import {
  HOST, META, MEMBERS, alice, bob, as, asOwn, call, credentialFor, groupSignIn, listRecords, log, ownSession, spaceUri, state, summary, verdict,
} from './lib.mjs'

const NS = 'group.opensocial'
const JOIN = `${NS}.requestJoin`
const SCOPES = ['atproto', `space:${META}?authority=self&skey=self&collection=*`, `space:${MEMBERS}?authority=self&skey=self&collection=*`]
const DAY3_GROUP = 'did:plc:5wwtfd2cqt2zvecrmctsla4v' // another group on this host, from day 3
const NOT_HOSTED = 'did:plc:nosuchgroupnosuchgroup23'
const HOST_DID = `did:web:${new URL(HOST).host}`
const ts = () => new Date().toISOString()

// ---------- setup: alice creates a group (joinPolicy approval, roles admin and member) ----------
log('\n## setup: alice creates a group\n')
const label = `d4g${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label, displayName: 'Day four group' }, scopes: SCOPES })
if (!A.ok) {
  verdict('setup', false, 'create flow did not reach the app')
  summary()
  process.exit(0)
}
const G = A.session.did
const MEM = spaceUri(G, MEMBERS)
const MET = spaceUri(G, META)
const asA = (method, nsid, body) => as(A.session, 'alice for the group', method, nsid, { body })
const putA = (space, collection, rkey, record) => asA('POST', 'com.atproto.space.putRecord', { space, repo: G, collection, rkey, record: { $type: collection, ...record } })
const delA = (space, collection, rkey) => asA('POST', 'com.atproto.space.deleteRecord', { space, repo: G, collection, rkey })
const setPolicy = (joinPolicy) => putA(MET, `${NS}.profile`, 'self', { displayName: 'Day four group', joinPolicy })
const memberships = async () =>
  Object.fromEntries(((await listRecords(A.session, 'alice for the group', G, MEMBERS)).body?.records ?? []).filter((r) => r.collection === `${NS}.membership`).map((r) => [r.rkey, r]))

const bobOwn = await ownSession(bob)
// What bob's app does: call his own PDS, which proxies to the group's host with service auth.
const join = (body = { group: G }) => asOwn(bobOwn, 'POST', JOIN, { body, headers: { 'atproto-proxy': `${body.group}#atproto_pds` } })
// A service-auth token bob's own PDS mints for an audience and method, sent straight to the host.
const serviceAuth = async (aud, lxm) => (await asOwn(bobOwn, 'GET', 'com.atproto.server.getServiceAuth', { params: { aud, lxm } })).body?.token
const direct = (who, token, body) => call(who, HOST, 'POST', JOIN, { body, headers: token ? { authorization: `Bearer ${token}` } : {} })
const err = (r) => `${r.status} ${r.body?.error ?? r.body?.status ?? ''}`.trim()
// listRecords gives no record uri, so a returned membership ref is matched by cid, and its uri by shape.
const sameRef = (ref, rec) => !!rec && ref?.cid === rec.cid && ref?.uri === `${MEM}/${G}/${NS}.membership/${bob.did}`

// ---------- f1 ----------
log("\n## f1 requestJoin through bob's own PDS\n")
const j1 = await join()
const j2 = await join()
let st = await state({ group: G })
const auds = [...new Set(st.memberCalls.filter((c) => c.member === bob.did).map((c) => c.aud))]
const pending1 = st.joinRequests.filter((r) => r.member === bob.did)
const ms1 = await memberships()
verdict(
  'f1',
  j1.status === 200 && j1.body?.status === 'pending' && j1.body?.request?.member === bob.did &&
    j2.status === 200 && j2.body?.request?.createdAt === j1.body?.request?.createdAt &&
    pending1.length === 1 && auds.length === 1 && auds[0] === G && !ms1[bob.did],
  `proxied through alpha: ${err(j1)}, asked again ${err(j2)} (same request: ${j2.body?.request?.createdAt === j1.body?.request?.createdAt}); the token's audience as the host saw it: ${JSON.stringify(auds)} (the group is ${G}); pending requests for bob ${pending1.length}; bob has a membership: ${!!ms1[bob.did]}`,
)

// ---------- f2 ----------
log('\n## f2 the host checks the service auth\n')
const none = await direct('none', null, { group: G })
const groupSession = await as(A.session, 'alice for the group', 'POST', JOIN, { body: { group: G } })
const hostAud = await direct('bob service auth, aud = the host', await serviceAuth(HOST_DID, JOIN), { group: G })
const otherAud = await direct('bob service auth, aud = another group on this host', await serviceAuth(DAY3_GROUP, JOIN), { group: G })
const otherLxm = await direct('bob service auth for leaveGroup', await serviceAuth(G, `${NS}.leaveGroup`), { group: G })
const good = await serviceAuth(G, JOIN)
const direct1 = await direct('bob service auth, aud = the group', good, { group: G })
const direct2 = await direct('the same token again', good, { group: G })
const notHere = await direct('bob service auth, aud = a group not here', await serviceAuth(NOT_HOSTED, JOIN), { group: NOT_HOSTED })
const f2 = [
  ['no auth', none, 401, 'AuthRequired'],
  ['a group session', groupSession, 401, 'AuthRequired'],
  ['audience the host', hostAud, 401, 'BadJwtAudience'],
  ['audience another group', otherAud, 401, 'BadJwtAudience'],
  ['token for leaveGroup', otherLxm, 401, 'BadJwtLexiconMethod'],
  ['group not hosted', notHere, 400, 'GroupNotFound'],
]
verdict(
  'f2',
  f2.every(([, r, s, e]) => r.status === s && r.body?.error === e) && direct1.status === 200 && direct1.body?.status === 'pending',
  `${f2.map(([w, r]) => `${w} ${err(r)}`).join('; ')}; the right token sent straight to the host ${err(direct1)} (and reused at once: ${err(direct2)})`,
)

// ---------- f3 ----------
log("\n## f3 writing bob's membership approves him\n")
const approve = await putA(MEM, `${NS}.membership`, bob.did, { member: bob.did, roles: ['member'], createdAt: ts() })
const j3 = await join()
st = await state({ group: G })
const ms3 = await memberships()
const cred3 = await credentialFor(bobOwn, MEM)
verdict(
  'f3',
  approve.status === 200 && j3.status === 200 && j3.body?.status === 'admitted' && sameRef(j3.body?.membership, ms3[bob.did]) &&
    !st.joinRequests.some((r) => r.member === bob.did) && cred3.status === 200,
  `alice wrote bob's membership ${approve.status}; bob's requestJoin then ${err(j3)} with that membership (${sameRef(j3.body?.membership, ms3[bob.did])}); requests left for bob ${st.joinRequests.filter((r) => r.member === bob.did).length}; bob's members credential ${cred3.status}`,
)

// ---------- f4 ----------
log('\n## f4 an open group admits at once with its default roles\n')
const out4 = await delA(MEM, `${NS}.membership`, bob.did)
const open = await setPolicy('open')
const j4 = await join()
const ms4 = await memberships()
const cred4 = await credentialFor(bobOwn, MEM)
verdict(
  'f4',
  out4.status === 200 && open.status === 200 && j4.status === 200 && j4.body?.status === 'admitted' &&
    JSON.stringify(ms4[bob.did]?.value?.roles) === '["member"]' && sameRef(j4.body?.membership, ms4[bob.did]) && cred4.status === 200,
  `bob removed ${out4.status}, policy open ${open.status}; requestJoin ${err(j4)} with that membership (${sameRef(j4.body?.membership, ms4[bob.did])}); his membership in the group's repo has roles ${JSON.stringify(ms4[bob.did]?.value?.roles)} (member is the default role); members credential ${cred4.status}`,
)

// ---------- f5 ----------
log('\n## f5 an invite-only group refuses, and so does an invitation\n')
const out5 = await delA(MEM, `${NS}.membership`, bob.did)
const inviteOnly = await setPolicy('invite')
const j5 = await join()
const j5i = await join({ group: G, invite: `at://${G}/${NS}.invite/self` })
const ms5 = await memberships()
verdict(
  'f5',
  out5.status === 200 && inviteOnly.status === 200 && j5.status === 400 && j5.body?.error === 'JoinClosed' && j5i.status === 400 && j5i.body?.error === 'InvalidInvite' && !ms5[bob.did],
  `bob removed ${out5.status}, policy invite ${inviteOnly.status}; requestJoin ${err(j5)}; with an invitation ${err(j5i)}; bob has a membership: ${!!ms5[bob.did]}`,
)

st = await state({ group: G })
log(`\n- host's member calls for the group: ${JSON.stringify(st.memberCalls.map((c) => `${c.member === bob.did ? 'bob' : c.member} aud=${c.aud === G ? 'group' : c.aud} -> ${c.result}`))}`)
summary()
process.exit(0)
