// group-methods.mjs: the group methods. A person's own acts on a group come with service auth from
// their own PDS; the group's own acts on its join requests and spaces take a group session.
//   f1  requestJoin through the person's own PDS reaches the host with the group as the token's
//       audience, and an approval group keeps one pending request however often they ask
//   f2  the host checks that service auth: none, a group session, the host as audience, another
//       group as audience, and a token for another method are refused; a group not hosted here
//       is GroupNotFound
//   f3  writing the requester's membership approves them: requestJoin answers admitted, the
//       request is gone, and they get a credential
//   f4  an open group admits at once with its default roles, the membership written by the group
//   f5  an invite-only group refuses, and so does an invitation (this host issues none)
//   f6  cancelJoinRequest withdraws a pending request, once; a token for requestJoin does not
//       cancel; once the membership is written there is nothing to cancel
//   f7  leaveGroup deletes the caller's membership as the group, with no assignable check, ends
//       new credentials at once, and succeeds again as a no-op
//   f8  listJoinRequests, with alice's group session: this group's pending requests only, with the
//       message, paged by cursor; no auth and a member's service auth are refused
//   f9  the whole walk: bob asks, alice finds him in the list, approves by writing his membership,
//       the list empties; bob's own group session, whose roles grant no rpc: scope, can neither
//       list nor deny; bob leaves
//   f10 denyJoinRequest drops a pending request, once; the denied person may ask again
//   f11 the rpc: scope is cut on every request: bob made admin signs in and lists; demoted to
//       member, his same session is refused
//   f12 createSpace with alice's group session (manage=create): the space under a generated key,
//       its access record holding the grants, and one index entry in members
//   f13 createSpace with a named key and index false: no index entry; the same type and key again
//       is SpaceAlreadyExists
//   f14 the new spaces follow their access records: bob as member gets a credential for the
//       space whose grants give members read, and none for the space granted to admins only
//   f15 the lexicon's other errors, each leaving no space and no index entry: ReservedSpace (meta,
//       members), UnknownRole, InvalidScope (not a scope, a permission set that does not resolve,
//       a bare space type with no published lexicon)
//   f16 who may call it: no auth is refused, and bob's session from f11, offered manage=create
//       as admin, is refused now that he is a member
// Run from probes/: snowglobe run node group-methods.mjs
import {
  HOST, META, MEMBERS, alice, bob, as, asOwn, call, credentialFor, groupSignIn, listRecords, log, ownSession, spaceUri, state, summary, verdict,
} from './lib.mjs'

const NS = 'group.opensocial'
const JOIN = `${NS}.requestJoin`
const CANCEL = `${NS}.cancelJoinRequest`
const LEAVE = `${NS}.leaveGroup`
const LIST = `${NS}.listJoinRequests`
const DENY = `${NS}.denyJoinRequest`
const CREATE = `${NS}.createSpace`
const MANAGE = 'space:*?authority=self&action=read_self&manage=create'
const SCOPES = [
  'atproto',
  `space:${META}?authority=self&skey=self&collection=*`,
  `space:${MEMBERS}?authority=self&skey=self&collection=*`,
  `rpc:${LIST}?aud=*`,
  `rpc:${DENY}?aud=*`,
  MANAGE,
]
// A space type of no app's, with no lexicon published: its grants name collections,
// since a bare space type expands only through its lexicon.
const TYPE = 'test.grouphost.board'
const NOT_HOSTED = 'did:plc:nosuchgroupnosuchgroup23'
const HOST_DID = `did:web:${new URL(HOST).host}`
const ts = () => new Date().toISOString()

// ---------- setup: alice creates a group (joinPolicy approval, roles admin and member) ----------
log('\n## setup: alice creates a group\n')
const label = `d4g${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label }, scopes: SCOPES })
if (!A.ok) {
  verdict('setup', false, 'create flow did not reach the app')
  summary()
  process.exit(0)
}
const G = A.session.did
// A second group of alice's on this host, also by approval: a request there must stay out of this
// group's list, and a token made for it must not work here.
const O = await groupSignIn(alice, { create: { label: `${label}o` }, scopes: ['atproto'] })
if (!O.ok) {
  verdict('setup', false, 'the second group was not made')
  summary()
  process.exit(0)
}
const OTHER = O.session.did
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
const viaOwn = (nsid, body = { group: G }) => asOwn(bobOwn, 'POST', nsid, { body, headers: { 'atproto-proxy': `${body.group}#atproto_pds` } })
const join = (body) => viaOwn(JOIN, body)
// A service-auth token bob's own PDS mints for an audience and method, sent straight to the host.
const serviceAuth = async (aud, lxm) => (await asOwn(bobOwn, 'GET', 'com.atproto.server.getServiceAuth', { params: { aud, lxm } })).body?.token
const direct = (who, token, body, nsid = JOIN) => call(who, HOST, 'POST', nsid, { body, headers: token ? { authorization: `Bearer ${token}` } : {} })
const err = (r) => `${r.status} ${r.body?.error ?? r.body?.status ?? ''}`.trim()
// listRecords gives no record uri, so a returned membership ref is matched by cid, and its uri by shape.
const sameRef = (ref, rec) => !!rec && ref?.cid === rec.cid && ref?.uri === `${MEM}/${G}/${NS}.membership/${bob.did}`

// ---------- f1 ----------
log("\n## f1 requestJoin through bob's own PDS\n")
const j1 = await join()
const j2 = await join()
let st = await state({ group: G })
const auds = [...new Set(st.methodCalls.filter((c) => c.member === bob.did).map((c) => c.aud))]
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
const otherAud = await direct('bob service auth, aud = another group on this host', await serviceAuth(OTHER, JOIN), { group: G })
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

// ---------- f6 ----------
log('\n## f6 cancelJoinRequest\n')
const approval = await setPolicy('approval')
const r6 = await join()
const c6 = await viaOwn(CANCEL)
st = await state({ group: G })
const left6 = st.joinRequests.filter((r) => r.member === bob.did).length
const c6again = await viaOwn(CANCEL)
const c6lxm = await direct('bob service auth for requestJoin, sent to cancel', await serviceAuth(G, JOIN), { group: G }, CANCEL)
const r6b = await join()
const approve6 = await putA(MEM, `${NS}.membership`, bob.did, { member: bob.did, roles: ['member'], createdAt: ts() })
const c6late = await viaOwn(CANCEL)
const ms6 = await memberships()
verdict(
  'f6',
  approval.status === 200 && r6.body?.status === 'pending' && c6.status === 200 && left6 === 0 &&
    c6again.status === 400 && c6again.body?.error === 'JoinRequestNotFound' &&
    c6lxm.status === 401 && c6lxm.body?.error === 'BadJwtLexiconMethod' &&
    r6b.body?.status === 'pending' && approve6.status === 200 &&
    c6late.status === 400 && c6late.body?.error === 'JoinRequestNotFound' && !!ms6[bob.did],
  `policy approval ${approval.status}; requestJoin ${err(r6)}; cancel ${c6.status}, requests left ${left6}; cancel again ${err(c6again)}; a requestJoin token sent to cancel ${err(c6lxm)}; asked again ${err(r6b)}, alice wrote the membership ${approve6.status}, then cancel ${err(c6late)} and bob is a member: ${!!ms6[bob.did]}`,
)

// ---------- f7 ----------
log('\n## f7 leaveGroup\n')
st = await state({ group: G, person: bob.did })
const bobAssignable = st.grants?.assignable ?? null
const cred7a = await credentialFor(bobOwn, MEM)
const l7 = await viaOwn(LEAVE)
const ms7 = await memberships()
const cred7 = await credentialFor(bobOwn, MEM)
const l7again = await viaOwn(LEAVE)
st = await state({ group: G })
const leaves = st.methodCalls.filter((c) => c.nsid === 'leaveGroup' && c.member === bob.did).map((c) => c.result)
verdict(
  'f7',
  JSON.stringify(bobAssignable) === '[]' && cred7a.status === 200 && l7.status === 200 && !ms7[bob.did] && cred7.status !== 200 && l7again.status === 200,
  `bob (member, assignable ${JSON.stringify(bobAssignable)}) had a members credential ${cred7a.status}; leaveGroup ${l7.status}; his membership is gone: ${!ms7[bob.did]}; a new credential ${err(cred7)}; leave again ${l7again.status}; the host's results: ${JSON.stringify(leaves)}`,
)

// ---------- f8 ----------
log('\n## f8 listJoinRequests with a group session\n')
const list = (s, who, params) => as(s, who, 'GET', LIST, { params })
const r8 = await join({ group: G, message: 'please let me in' })
const r8other = await join({ group: OTHER })
const l8 = await list(A.session, 'alice for the group')
const page1 = await list(A.session, 'alice for the group', { limit: '1' })
const page2 = page1.body?.cursor ? await list(A.session, 'alice for the group', { limit: '1', cursor: page1.body.cursor }) : null
const l8none = await call('none', HOST, 'GET', LIST)
const l8svc = await call('bob service auth for listJoinRequests', HOST, 'GET', LIST, { headers: { authorization: `Bearer ${await serviceAuth(G, LIST)}` } })
const reqs8 = l8.body?.requests ?? []
const aliceRpc = A.kept.filter((k) => k.startsWith('rpc:'))
verdict(
  'f8',
  JSON.stringify(aliceRpc) === JSON.stringify([`rpc:${LIST}?aud=*`, `rpc:${DENY}?aud=*`]) &&
    r8.body?.status === 'pending' && r8other.body?.status === 'pending' &&
    l8.status === 200 && reqs8.length === 1 && reqs8[0].member === bob.did && reqs8[0].message === 'please let me in' &&
    page1.body?.requests?.length === 1 && !!page1.body?.cursor && page2?.status === 200 && page2.body?.requests?.length === 0 && !page2.body?.cursor &&
    l8none.status === 401 && l8svc.status >= 400,
  `alice was offered ${JSON.stringify(aliceRpc)}; bob asked here ${err(r8)} and at the other group ${err(r8other)}; alice's list ${l8.status}: ${JSON.stringify(reqs8.map((r) => ({ member: r.member === bob.did ? 'bob' : r.member, message: r.message })))}; limit 1 gave ${page1.body?.requests?.length} and a cursor, the next page ${page2?.body?.requests?.length} and ${page2?.body?.cursor ? 'a' : 'no'} cursor; no auth ${l8none.status} ${l8none.body?.error ?? ''}; bob's service auth as the session ${l8svc.status} ${l8svc.body?.error ?? ''}`,
)

// ---------- f9 ----------
log('\n## f9 the whole walk with host methods, and the rpc: scope follows roles\n')
const approve9 = await putA(MEM, `${NS}.membership`, bob.did, { member: bob.did, roles: ['member'], createdAt: ts() })
const l9 = await list(A.session, 'alice for the group')
const B = await groupSignIn(bob, { groupDid: G, scopes: SCOPES })
const bobRpc = B.kept.filter((k) => k.startsWith('rpc:'))
const bobDropped = B.dropped.filter((k) => k.startsWith('rpc:'))
const l9b = B.ok ? await list(B.session, 'bob (member) for the group') : null
const d9b = B.ok ? await as(B.session, 'bob (member) for the group', 'POST', DENY, { body: { member: alice.did } }) : null
const leave9 = await viaOwn(LEAVE)
const ms9 = await memberships()
verdict(
  'f9',
  approve9.status === 200 && l9.status === 200 && (l9.body?.requests ?? []).length === 0 &&
    B.ok && bobRpc.length === 0 && bobDropped.length === 2 &&
    l9b?.status === 403 && l9b.body?.error === 'ScopeMissingError' && d9b?.status === 403 && d9b.body?.error === 'ScopeMissingError' &&
    leave9.status === 200 && !ms9[bob.did],
  `alice wrote bob's membership ${approve9.status}; her list then holds ${(l9.body?.requests ?? []).length}; bob signed in for the group as a member: rpc scopes offered ${JSON.stringify(bobRpc)}, not offered ${bobDropped.length}; his session lists ${l9b?.status} ${l9b?.body?.error ?? ''} and denies ${d9b?.status} ${d9b?.body?.error ?? ''}; he leaves ${leave9.status} and has a membership: ${!!ms9[bob.did]}`,
)

// ---------- f10 ----------
log('\n## f10 denyJoinRequest\n')
const deny = (member) => as(A.session, 'alice for the group', 'POST', DENY, { body: { member } })
const r10 = await join()
const d10 = await deny(bob.did)
const l10 = await list(A.session, 'alice for the group')
const d10again = await deny(bob.did)
const d10never = await deny(NOT_HOSTED)
const r10again = await join()
const tidy = [await viaOwn(CANCEL), await viaOwn(CANCEL, { group: OTHER })]
verdict(
  'f10',
  r10.body?.status === 'pending' && d10.status === 200 && (l10.body?.requests ?? []).length === 0 &&
    d10again.status === 400 && d10again.body?.error === 'JoinRequestNotFound' && d10never.status === 400 && d10never.body?.error === 'JoinRequestNotFound' &&
    r10again.body?.status === 'pending',
  `bob asked ${err(r10)}; alice denied ${d10.status}; her list then holds ${(l10.body?.requests ?? []).length}; deny again ${err(d10again)}; deny someone who never asked ${err(d10never)}; bob asked again after the denial ${err(r10again)}; tidied (cancel here and at the other group) ${tidy.map((r) => r.status).join(' ')}`,
)

// ---------- f11 ----------
log('\n## f11 the rpc: scope follows the roles on every request\n')
const admin11 = await putA(MEM, `${NS}.membership`, bob.did, { member: bob.did, roles: ['admin'], createdAt: ts() })
const B2 = await groupSignIn(bob, { groupDid: G, scopes: SCOPES })
const bob2Rpc = B2.kept.filter((k) => k.startsWith('rpc:'))
const l11a = B2.ok ? await list(B2.session, 'bob (admin) for the group') : null
const demote11 = await putA(MEM, `${NS}.membership`, bob.did, { member: bob.did, roles: ['member'], createdAt: ts() })
const l11b = B2.ok ? await list(B2.session, 'bob (now a member), same session') : null
st = await state({ group: G })
const cut = st.narrowings.filter((n) => n.personDid === bob.did && /rpc:/.test(n.from) && !/rpc:/.test(n.to)).length
const leave11 = await viaOwn(LEAVE)
verdict(
  'f11',
  admin11.status === 200 && B2.ok && bob2Rpc.length === 2 && l11a?.status === 200 && demote11.status === 200 &&
    l11b?.status === 403 && l11b.body?.error === 'ScopeMissingError' && cut > 0 && leave11.status === 200,
  `bob made admin ${admin11.status}, signed in and was offered ${bob2Rpc.length} rpc scopes; his list ${l11a?.status}; demoted ${demote11.status}; the same session lists ${l11b?.status} ${l11b?.body?.error ?? ''}; host cuts that dropped the rpc scopes for bob ${cut}; he leaves ${leave11.status}`,
)

// ---------- f12 ----------
log('\n## f12 createSpace: the space, its access record and an index entry\n')
const create = (s, who, body) => as(s, who, 'POST', CREATE, { body })
const createA = (body) => create(A.session, 'alice for the group', body)
const spaceRecords = async (space) => (await as(A.session, 'alice for the group', 'GET', 'com.atproto.space.listRecords', { params: { space, repo: G, limit: '100' } })).body?.records ?? []
const indexEntries = async () => ((await listRecords(A.session, 'alice for the group', G, MEMBERS)).body?.records ?? []).filter((r) => r.collection === `${NS}.space`)
const BOARD = [
  { role: 'admin', scopes: [`space:${TYPE}?collection=*`] },
  { role: 'member', scopes: [`space:${TYPE}?collection=*&action=read`] },
]
const c12 = await createA({ type: TYPE, access: { grants: BOARD } })
const S1 = c12.body?.space
const skey1 = String(S1 ?? '').split('/').pop()
const acc12 = S1 ? (await spaceRecords(S1)).find((r) => r.collection === `${NS}.access` && r.rkey === 'self') : null
const idx12 = await indexEntries()
st = await state({ group: G })
verdict(
  'f12',
  A.kept.includes(MANAGE) && c12.status === 200 && S1 === `at://${G}/space/${TYPE}/${skey1}` && /^[2-7a-j][2-7a-z]{12}$/.test(skey1) &&
    c12.body?.access?.uri === `${S1}/${G}/${NS}.access/self` && acc12?.cid === c12.body?.access?.cid && JSON.stringify(acc12?.value?.grants) === JSON.stringify(BOARD) &&
    idx12.length === 1 && idx12[0].value?.space === S1 && idx12[0].cid === c12.body?.index?.cid && c12.body?.index?.uri === `${MEM}/${G}/${NS}.space/${idx12[0].rkey}` &&
    !!st.spaces?.includes(S1),
  `alice was offered manage=create: ${A.kept.includes(MANAGE)}; createSpace ${c12.status} ${S1 ?? JSON.stringify(c12.body)} (key ${skey1}, a TID: ${/^[2-7a-j][2-7a-z]{12}$/.test(skey1)}); its access record in the new space matches the output (${acc12?.cid === c12.body?.access?.cid}) and holds the grants as sent (${JSON.stringify(acc12?.value?.grants) === JSON.stringify(BOARD)}); index entries in members ${idx12.length}, naming the space: ${idx12[0]?.value?.space === S1}, matching the output: ${idx12[0]?.cid === c12.body?.index?.cid}; the host holds the space: ${!!st.spaces?.includes(S1)}`,
)

// ---------- f13 ----------
log('\n## f13 a named key, no index entry, and SpaceAlreadyExists\n')
const ADMINS = [{ role: 'admin', scopes: [`space:${TYPE}?collection=*`] }]
const c13 = await createA({ type: TYPE, skey: 'admins', access: { grants: ADMINS }, index: false })
const S2 = spaceUri(G, TYPE, 'admins')
const idx13 = await indexEntries()
const c13again = await createA({ type: TYPE, skey: 'admins', access: { grants: BOARD } })
const acc13 = (await spaceRecords(S2)).find((r) => r.collection === `${NS}.access` && r.rkey === 'self')
st = await state({ group: G })
verdict(
  'f13',
  c13.status === 200 && c13.body?.space === S2 && !!c13.body?.access && !('index' in (c13.body ?? {})) && idx13.length === 1 && !!st.spaces?.includes(S2) &&
    c13again.status === 400 && c13again.body?.error === 'SpaceAlreadyExists' && JSON.stringify(acc13?.value?.grants) === JSON.stringify(ADMINS),
  `createSpace with key admins and index false ${c13.status} ${c13.body?.space ?? ''}, index in the output: ${'index' in (c13.body ?? {})}; index entries still ${idx13.length}; the host holds the space: ${!!st.spaces?.includes(S2)}; the same type and key again ${err(c13again)}, and the first access record stands (${JSON.stringify(acc13?.value?.grants) === JSON.stringify(ADMINS)})`,
)

// ---------- f14 ----------
log('\n## f14 the new spaces follow their access records\n')
const member14 = await putA(MEM, `${NS}.membership`, bob.did, { member: bob.did, roles: ['member'], createdAt: ts() })
const cred14a = await credentialFor(bobOwn, S1)
const cred14b = await credentialFor(bobOwn, S2)
st = await state({ group: G })
const answers = (space) => st.accessCalls.filter((c) => c.space === space && c.user === bob.did).map((c) => `${c.authorized} (${c.why})`)
verdict(
  'f14',
  member14.status === 200 && cred14a.status === 200 && cred14b.status !== 200 && answers(S1).some((a) => a.startsWith('true')) && answers(S2).some((a) => a.startsWith('false')),
  `bob made a member ${member14.status}; his credential for the space granting members read ${cred14a.status}, for the admins-only space ${err(cred14b)}; the host's answers: first ${JSON.stringify(answers(S1))}, second ${JSON.stringify(answers(S2))}`,
)

// ---------- f15 ----------
log("\n## f15 the lexicon's other errors leave nothing behind\n")
const before15 = { spaces: st.spaces?.length, index: (await indexEntries()).length }
const f15 = [
  ['the meta space', 'ReservedSpace', { type: META, skey: 'self', access: { grants: [] } }],
  ['the members space', 'ReservedSpace', { type: MEMBERS, skey: 'self', access: { grants: [] } }],
  ['meta under another key', 'ReservedSpace', { type: META, skey: 'other', access: { grants: [] } }],
  ['a grant to an undeclared role', 'UnknownRole', { type: TYPE, access: { grants: [{ role: 'ghost', scopes: [`space:${TYPE}?collection=*&action=read`] }] } }],
  ['not a scope', 'InvalidScope', { type: TYPE, access: { grants: [{ role: 'member', scopes: ['read the board'] }] } }],
  ['a permission set that does not resolve', 'InvalidScope', { type: TYPE, access: { grants: [{ role: 'member', scopes: [`include:${NS}.noSuchSet`] }] } }],
  ['a bare space type with no lexicon', 'InvalidScope', { type: TYPE, access: { grants: [{ role: 'member', scopes: [`space:${TYPE}?action=read`] }] } }],
]
const got15 = []
for (const [what, want, body] of f15) {
  const r = await createA(body)
  got15.push({ what, want, got: err(r), ok: r.status === 400 && r.body?.error === want })
}
st = await state({ group: G })
const after15 = { spaces: st.spaces?.length, index: (await indexEntries()).length }
log(`- f15 cases: ${JSON.stringify(got15)}`)
verdict(
  'f15',
  got15.every((c) => c.ok) && after15.spaces === before15.spaces && after15.index === before15.index,
  `${got15.filter((c) => c.ok).length}/${got15.length} refused as the lexicon names (${got15.map((c) => `${c.what}: ${c.got}`).join('; ')}); spaces ${before15.spaces} then ${after15.spaces}, index entries ${before15.index} then ${after15.index}`,
)

// ---------- f16 ----------
log('\n## f16 who may call createSpace\n')
const c16none = await call('none', HOST, 'POST', CREATE, { body: { type: TYPE, access: { grants: [] } } })
const c16bob = B2.ok ? await create(B2.session, 'bob (now a member), his session from f11', { type: TYPE, access: { grants: [] } }) : null
st = await state({ group: G })
const leave16 = await viaOwn(LEAVE)
verdict(
  'f16',
  c16none.status === 401 && B2.kept.includes(MANAGE) && c16bob?.status === 403 && c16bob.body?.error === 'ScopeMissingError' && st.spaces?.length === after15.spaces && leave16.status === 200,
  `no auth ${c16none.status} ${c16none.body?.error ?? ''}; bob's session from f11 was offered manage=create as admin: ${B2.kept.includes(MANAGE)}; as a member now it creates ${c16bob?.status} ${c16bob?.body?.error ?? ''}; spaces still ${st.spaces?.length}; he leaves ${leave16.status}`,
)

st = await state({ group: G })
log(`\n- host's method calls for the group: ${JSON.stringify(st.methodCalls.map((c) => `${c.nsid} ${c.member ? `${c.member === bob.did ? 'bob' : c.member} aud=${c.aud === G ? 'group' : c.aud}` : `session person ${c.person === alice.did ? 'alice' : c.person === bob.did ? 'bob' : c.person}`} -> ${c.result}`))}`)
summary()
process.exit(0)
