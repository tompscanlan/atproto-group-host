// probe-cancel.mjs: saying no at your own PDS during a group create ends the app's request as a
// refusal, not an error page.
//   c1  the person presses Deny access on their own PDS: the app is sent back error=access_denied
//       with its own state and the host as issuer, the host's page never shows a server error, and
//       no group is made
//   c2  the app's request is gone afterwards: the same authorization URL no longer starts a sign-in
// Run: ../../atproto-devnet/scripts/https-run node probe-cancel.mjs 2>&1 | tee run-cancel.log
import { GROUP_DOMAIN, HOST, META, alice, groupSignIn, log, summary, verdict } from './lib.mjs'

log('\n## c1 Deny access at your own PDS\n')
const label = `pc${Date.now().toString(36)}`
const before = await fetch(`${HOST}/xrpc/com.atproto.identity.resolveHandle?handle=${label}${GROUP_DOMAIN}`).then((r) => r.status)
const A = await groupSignIn(alice, { create: { label }, refuseOwn: true, scopes: ['atproto', `space:${META}?authority=self&skey=self&action=read`] })
const cb = A.cbUrl ? new URL(A.cbUrl).searchParams : null
const after = await fetch(`${HOST}/xrpc/com.atproto.identity.resolveHandle?handle=${label}${GROUP_DOMAIN}`).then((r) => r.status)
const serverError = /internal server error|unanswered error/i.test(A.lastPage?.body ?? '')
verdict(
  'c1',
  cb?.get('error') === 'access_denied' && !!cb.get('state') && cb.get('iss') === HOST && !serverError && before !== 200 && after !== 200,
  `app sent back ${cb ? JSON.stringify(Object.fromEntries(cb)) : 'nothing'}; last page ${JSON.stringify(A.lastPage)}; group ${label} resolves: before ${before}, after ${after}`,
)

log('\n## c2 the request is closed\n')
const page = A.seen.find((u) => u.startsWith(`${HOST}/oauth/authorize?`) && u.includes('request_uri=') && !u.includes('gh=ticket'))
const again = page ? await fetch(page, { redirect: 'manual' }) : null
const location = again?.headers.get('location') ?? ''
verdict(
  'c2',
  !!again && !location.includes('/signin/start'),
  `${page ? 'reopened the authorization URL' : 'no authorization URL seen'}: status ${again?.status}, location ${location.slice(0, 120) || '(none)'}`,
)

summary()

process.exit(0)
