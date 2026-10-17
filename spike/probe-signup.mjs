// probe-signup.mjs: the host's sign-up page (prompt=create) on the https devnet.
//   u1  an address the PDS would refuse, and a handle that leads nowhere, are turned down on the
//       host's own page with their reason, before the person goes to their own PDS
//   u2  after those refusals the same sign-in still makes the group: a refusal does not spend it
//   u3  the page asks only for the group's address, and the starting profile is named after it
//   u4  the host's request log prints request headers, and never the host's internal mark
// Run: ../../atproto-devnet/scripts/https-run node probe-signup.mjs 2>&1 | tee run-signup.log
// Logins live in data/accounts.env (mode 600) and are never printed; tokens are never printed.
import { spawnSync } from 'node:child_process'
import { HOST, META, alice, groupSignIn, listRecords, log, summary, verdict } from './lib.mjs'

const since = new Date().toISOString()
const DOMAIN = '.gh.devnet.test'
const SCOPES = ['atproto', `space:${META}?authority=self&skey=self&action=read`]

// An address some group here already holds.
let taken = null
for (const r of (await (await fetch(`${HOST}/xrpc/com.atproto.sync.listRepos?limit=100`)).json()).repos ?? []) {
  const d = await (await fetch(`${HOST}/xrpc/com.atproto.repo.describeRepo?repo=${r.did}`)).json()
  if (d.handle?.endsWith(DOMAIN)) {
    taken = d.handle.slice(0, -DOMAIN.length)
    break
  }
}

const REFUSED = [
  { label: 'first', want: 'reserved' }, // on the PDS's reserved list
  { label: 'a'.repeat(19), want: 'length' }, // one over the PDS's 18
  { label: '-dash', want: 'characters' },
  ...(taken ? [{ label: taken, want: 'taken' }] : []),
  { label: 'unused-address', handle: 'nobody-here.devnet.test', want: 'handle' },
]

log('\n## u1-u3 refusals on the page, then the create\n')
const label = `su${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label, refused: REFUSED }, scopes: SCOPES })

const wrong = A.refused.filter((r) => !r.onPage || r.reason !== r.want)
verdict(
  'u1',
  taken !== null && A.refused.length === REFUSED.length && wrong.length === 0,
  `${A.refused.length} of ${REFUSED.length} turned down on the host's page with the expected reason` +
    (taken ? '' : '; the host holds no group to test a taken address against (run probe-day2 first)') +
    (wrong.length ? `; wrong: ${JSON.stringify(wrong)}` : ''),
)

const G = A.session?.did
verdict('u2', A.ok && !!G, A.ok ? `the same sign-in made ${G} after ${A.refused.length} refusals` : 'the sign-in did not finish')

const meta = G ? await listRecords(A.session, 'alice for the group', G, META) : null
const profile = (meta?.body?.records ?? []).find((x) => x.collection === 'group.opensocial.profile' && x.rkey === 'self')
verdict(
  'u3',
  A.displayNameFields === 0 && profile?.value?.displayName === label,
  `display-name fields on the page: ${A.displayNameFields}; the starting profile's display name ${JSON.stringify(profile?.value?.displayName)} (address ${label})`,
)

log('\n## u4 the request log\n')
const logs = spawnSync('docker', ['logs', '--since', since, 'grouphost-spike'], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
const text = `${logs.stdout}${logs.stderr}`
const count = (s) => text.split(s).length - 1
const headers = count('"headers":')
const creates = count('/xrpc/com.atproto.server.createAccount')
const marks = count('x-grouphost-internal')
verdict(
  'u4',
  logs.status === 0 && headers > 0 && creates > 0 && marks === 0,
  `since ${since}: ${headers} logged requests with headers, ${creates} of them the host's own createAccount; the internal mark appears ${marks} times`,
)

summary()
