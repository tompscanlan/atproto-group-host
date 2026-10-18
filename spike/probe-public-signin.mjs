// probe-public-signin.mjs: the host's sign-in works from a browser that is not on the host's machine.
//   p1  the host serves its sign-in client's metadata at its own https name: a public web client,
//       whose id is that URL and whose redirect is on the same name (nothing on a loopback address)
//   p2  a group is made through the host's sign-in and consent pages, and every request the browser
//       made went to a devnet name (the probe's own app callback aside): none to the loopback address
//       the old sign-in sent it to, so the flow ran by name alone
// Run: ../../atproto-devnet/scripts/https-run node probe-public-signin.mjs 2>&1 | tee run-public-signin.log
import { DOMAIN, HOST, META, alice, groupSignIn, listRecords, log, summary, verdict } from './lib.mjs'

log('\n## p1 the sign-in client\n')
const res = await fetch(`${HOST}/signin/client-metadata.json`)
const meta = await res.json().catch(() => null)
const loopbackish = (u) => /^(https?:\/\/)?(127\.|localhost|\[::1\])/.test(String(u))
verdict(
  'p1',
  res.ok &&
    meta?.client_id === `${HOST}/signin/client-metadata.json` &&
    meta?.redirect_uris?.length === 1 &&
    meta.redirect_uris[0] === `${HOST}/signin/callback` &&
    meta.token_endpoint_auth_method === 'none' &&
    meta.application_type === 'web' &&
    !meta.redirect_uris.some(loopbackish) &&
    meta.scope === 'atproto',
  `status ${res.status}: client_id ${meta?.client_id}, redirect ${JSON.stringify(meta?.redirect_uris)}, auth ${meta?.token_endpoint_auth_method}, type ${meta?.application_type}, scope ${meta?.scope}`,
)

log('\n## p2 a group is made, by name alone\n')
const label = `ps${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label }, scopes: ['atproto', `space:${META}?authority=self&skey=self&action=read`] })
const G = A.session?.did
const meta2 = G ? await listRecords(A.session, 'alice for the group', G, META) : null
const hosts = [...new Set(A.seen.map((u) => new URL(u).host))]
// The app's own callback is the probe's loopback listener (lib.mjs): the app, not the host.
const stray = A.seen.filter((u) => {
  const h = new URL(u)
  return !(h.host.endsWith(`.${DOMAIN}`) || h.host.endsWith('.devnet.internal') || h.host === 'plc.directory' || h.host === '127.0.0.1:39418')
})
const onHostStart = A.seen.some((u) => u.startsWith(`${HOST}/signin/start`))
const onHostCallback = A.seen.some((u) => u.startsWith(`${HOST}/signin/callback`))
verdict(
  'p2',
  A.ok && !!G && onHostStart && onHostCallback && stray.length === 0 && (meta2?.body?.records ?? []).length > 0,
  `${A.seen.length} requests to ${hosts.join(', ')}; sign-in start on the host's name ${onHostStart}, callback on it ${onHostCallback}; group ${G ?? 'not made'}; requests to other places: ${JSON.stringify(stray)}`,
)

summary()

process.exit(0)
