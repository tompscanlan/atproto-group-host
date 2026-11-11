// probe-hints.mjs: the hints an app puts on the link to the host's start page (gh_name, gh_person),
// on the https devnet. Each check reads the start page's input values before anything is typed.
//   h1  gh_name=Kona Trail Runners suggests the address kona-trail-runners
//   h2  a name longer than 18 characters is cut to 18, and a dash left at the end is dropped
//   h3  a name that comes to under 3 characters suggests nothing
//   h4  gh_person=<a devnet DID> fills in that DID's handle
//   h5  a gh_person that does not resolve leaves the handle empty
//   h6  no hints: both fields empty, as before
//   h7  a hostile gh_name and gh_person show only as a value, never as markup, and nothing runs
//   h8  the act-for-group page fills in the handle from gh_person
//   h9  a hint is never trusted: with gh_person naming bob, signing in as alice makes alice the
//       creator, and nothing is written or granted for bob
// Run: ../../atproto-devnet/scripts/https-run node probe-hints.mjs 2>&1 | tee run-hints.log
// Logins live in data/accounts.env (mode 600) and are never printed; tokens are never printed.
import { GROUP_DOMAIN, HOST, META, MEMBERS, alice, bob, groupSignIn, listRecords, log, state, summary, verdict } from './lib.mjs'

const SCOPES = ['atproto', `space:${META}?authority=self&skey=self&action=read`]
const start = (hints, opts = {}) => groupSignIn(alice, { create: opts.groupDid ? undefined : {}, groupDid: opts.groupDid, scopes: SCOPES, hints, stopAtStart: true })
const show = (s) => JSON.stringify(s)

log('\n## h1-h7 the create page, read before anything is typed\n')

const h1 = (await start({ gh_name: 'Kona Trail Runners' })).start
verdict('h1', h1?.label === 'kona-trail-runners' && h1?.handle === '', `gh_name=Kona Trail Runners: ${show(h1)}`)

// "hilo-bay-paddlers-guild" cut to 18 is "hilo-bay-paddlers-", whose last dash goes.
const h2 = (await start({ gh_name: 'Hilo Bay Paddlers Guild' })).start
verdict('h2', h2?.label === 'hilo-bay-paddlers', `gh_name=Hilo Bay Paddlers Guild: ${show(h2)}`)

const h3 = (await start({ gh_name: '¡Ok!' })).start
verdict('h3', h3?.label === '', `gh_name=¡Ok! (comes to "ok"): ${show(h3)}`)

const h4 = (await start({ gh_person: bob.did })).start
verdict('h4', h4?.handle === bob.handle && h4?.label === '', `gh_person=${bob.did}: ${show(h4)} (want handle ${bob.handle})`)

const NOWHERE = 'did:plc:zzzzzzzzzzzzzzzzzzzzzzzz' // well formed, on no PLC
const h5 = (await start({ gh_person: NOWHERE })).start
verdict('h5', h5?.handle === '', `gh_person=${NOWHERE}: ${show(h5)}`)

const h6 = (await start(undefined)).start
verdict('h6', h6?.label === '' && h6?.handle === '', `no hints: ${show(h6)}`)

// Anything that ran would set window.__hinted; anything rendered as markup adds an element. The
// create page holds three inputs (state, label, handle), no script and no image.
const h7 = (
  await start({
    gh_name: '"><script>window.__hinted=1</script><img src=x onerror="window.__hinted=2">',
    gh_person: '"><script>window.__hinted=3</script>',
  })
).start
verdict(
  'h7',
  h7?.label === 'script-window-hint' && h7?.handle === '' && h7?.inputs === 3 && h7?.scripts === 0 && h7?.images === 0 && h7?.ran === null,
  `hostile gh_name and gh_person: ${show(h7)}`,
)

log('\n## h8 the act-for-group page\n')
// Any group at the host will do; nobody signs in. gh_name is for a create only, so it adds
// nothing here: the act page holds two inputs (state, handle).
let group = null
for (const r of (await (await fetch(`${HOST}/xrpc/com.atproto.sync.listRepos?limit=100`)).json()).repos ?? []) {
  const d = await (await fetch(`${HOST}/xrpc/com.atproto.repo.describeRepo?repo=${r.did}`)).json()
  if (d.handle?.endsWith(GROUP_DOMAIN)) {
    group = r.did
    break
  }
}
const h8 = group ? (await start({ gh_person: alice.did, gh_name: 'Kona Trail Runners' }, { groupDid: group })).start : null
verdict(
  'h8',
  h8?.handle === alice.handle && h8?.label === null && h8?.inputs === 2,
  `act page for ${group ?? 'no group (run probe-day2 first)'}, gh_person=${alice.did}: ${show(h8)} (want handle ${alice.handle})`,
)

log('\n## h9 the hint is not trusted: gh_person names bob, alice signs in\n')
const stamp = Date.now().toString(36)
const label = `ht-${stamp}`
// The page suggests `label` from gh_name and fills in bob's handle; alice keeps the address and
// types her own handle over bob's, then signs in at her own PDS.
// The session also reads the members space, to see whose membership was written.
const READ = [...SCOPES, `space:${MEMBERS}?authority=self&skey=self&action=read`]
const T = await groupSignIn(alice, { create: { label }, scopes: READ, hints: { gh_name: `HT ${stamp}`, gh_person: bob.did } })
const G = T.session?.did
const membersRead = G ? await listRecords(T.session, 'alice for the group', G, MEMBERS) : null
const metaRead = G ? await listRecords(T.session, 'alice for the group', G, META) : null
const members = membersRead?.body?.records ?? []
const meta = metaRead?.body?.records ?? []
const memberships = members.filter((r) => r.collection === 'group.opensocial.membership')
const st = G ? await state({ group: G, person: bob.did }) : null
const bobsTokens = (st?.tokens ?? []).filter((t) => t.personDid === bob.did).length
const bobsSignIns = (st?.authorizedBy ?? []).filter((a) => a.groupDid === G && a.personDid === bob.did).length
const alicesSignIns = (st?.authorizedBy ?? []).filter((a) => a.groupDid === G && a.personDid === alice.did).length
const namesBob = JSON.stringify([...members, ...meta]).includes(bob.did)
verdict(
  'h9',
  T.start?.label === label &&
    T.start?.handle === bob.handle &&
    T.ok &&
    !!G &&
    membersRead?.status === 200 &&
    metaRead?.status === 200 &&
    memberships.length === 1 &&
    memberships[0].rkey === alice.did &&
    memberships[0].value?.member === alice.did &&
    JSON.stringify(memberships[0].value?.roles) === '["admin"]' &&
    !namesBob &&
    (st?.grants?.roles ?? ['?']).length === 0 &&
    bobsTokens === 0 &&
    bobsSignIns === 0 &&
    alicesSignIns >= 1,
  `start page ${show(T.start)}; made ${G ?? 'nothing'}; reads ${membersRead?.status}/${metaRead?.status}; memberships ${show(memberships.map((r) => ({ rkey: r.rkey, member: r.value?.member, roles: r.value?.roles })))}; ` +
    `records in members and meta naming bob: ${namesBob}; bob's roles ${show(st?.grants?.roles)}, tokens ${bobsTokens}, group sign-ins ${bobsSignIns}; alice's group sign-ins ${alicesSignIns}`,
)

summary()
