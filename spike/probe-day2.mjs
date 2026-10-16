// probe-day2.mjs: drives the group-host spike's second round on the https devnet.
//   d1  prompt=create makes a group with its starting records, and the app gets its session
//   d2  every token the host issued for the group names the person who authorized it
//   d3  the group sign-in leaves no group session on the device
//   d4  a member whose role only reads is offered only the read scopes
//   d5  removing a member cuts their existing session on the next request
//   d6  a refreshed token keeps its person
//   d7  the token-to-person table survives a host restart
// Run: ../../atproto-devnet/scripts/https-run node probe-day2.mjs 2>&1 | tee run-day2.log
// Logins live in data/accounts.env (mode 600) and are never printed; tokens are never printed.
import { execFileSync } from 'node:child_process'
import { HOST, META, MEMBERS, alice, bob, as, listRecords, groupSignIn as signIn, log, sleep, spaceUri, state, summary, verdict } from './lib.mjs'

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
const groupSignIn = (person, opts) => signIn(person, { ...opts, label: `d-consent-${opts.label}`, scopes: SCOPES })

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

summary()
process.exit(0)
