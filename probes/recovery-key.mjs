// recovery-key.mjs: a new group's creator gets its recovery key, once.
//   k1  a create shows the recovery key page before consent, and the key's private half matches the
//       public half the page names
//   k2  the group's PLC lists that key first among its rotation keys, ahead of the host's own
//   k3  the key is shown once: the sign-in that showed it cannot show it again, and Continue works once
//   k4  the create carries on to the app as before: the app holds a session for the new group, and the
//       consent named the creator as its admin
//   k5  the host keeps no copy: the private key is in neither the host's log nor anything under /data
// Nothing here prints, logs or screenshots the private key. Its checks print only what they found.
// Run from probes/: snowglobe run node recovery-key.mjs
import { execFileSync } from 'node:child_process'
import { Secp256k1PrivateKeyExportable, parsePrivateMultikey } from '@atcute/crypto'
import { HOST_CONTAINER, PLC, alice, groupSignIn, log, summary, verdict } from './lib.mjs'

const hex = (bytes) => Buffer.from(bytes).toString('hex')

log('\n## create a group, and read its recovery key page\n')
const label = `pk${Date.now().toString(36)}`
// What the key page held. The private key stays in this closure's variables and is never printed.
const page = { seen: false, did: null, secret: null, raw: null, derived: null, consentAfter: null, reshown: null, continueUrl: null }
const A = await groupSignIn(alice, {
  create: {
    label,
    onKey: async (p) => {
      page.seen = true
      page.did = await p.locator('#recovery').getAttribute('data-did')
      page.secret = await p.locator('#recovery-key').inputValue()
      page.continueUrl = await p.locator('#continue').getAttribute('href')
      page.consentAfter = (await p.locator('#consent').count()) === 0
      try {
        const { type, privateKeyBytes } = parsePrivateMultikey(page.secret)
        if (type === 'secp256k1') page.derived = await (await Secp256k1PrivateKeyExportable.importRaw(privateKeyBytes)).exportPublicKey('did')
        page.raw = privateKeyBytes
      } catch {
        page.derived = null
      }
      // The same sign-in, asked again: its state is spent, so it must not show the key.
      const again = await p.context().newPage()
      try {
        const res = await again.goto(p.url(), { waitUntil: 'load', timeout: 30000 })
        page.reshown = { status: res?.status() ?? null, key: (await again.locator('#recovery-key').count()) > 0 }
      } finally {
        await again.close()
      }
    },
  },
  scopes: ['atproto'],
})

verdict(
  'k1',
  A.keyPage && page.seen && page.consentAfter && /^did:key:z/.test(page.did ?? '') && /^z/.test(page.secret ?? '') && page.derived === page.did,
  `key page shown before consent: ${A.keyPage && page.consentAfter}; public half ${page.did}; private half parses as secp256k1 and gives that public half: ${page.derived === page.did}`,
)

const groupDid = A.session?.did
let rotationKeys = null
if (groupDid) {
  const res = await fetch(`${PLC}/${groupDid}/data`)
  rotationKeys = res.ok ? (await res.json()).rotationKeys : `PLC ${res.status}`
}
verdict(
  'k2',
  Array.isArray(rotationKeys) && rotationKeys[0] === page.did && rotationKeys.length >= 2 && rotationKeys.slice(1).every((k) => k !== page.did),
  `${groupDid ?? 'no group'} rotation keys at its PLC: ${JSON.stringify(rotationKeys)}`,
)

let continueAgain = null
if (page.continueUrl) continueAgain = (await fetch(page.continueUrl, { redirect: 'manual' })).status
verdict(
  'k3',
  page.reshown && !page.reshown.key && page.reshown.status >= 400 && continueAgain === 400,
  `the sign-in asked again: ${JSON.stringify(page.reshown)}; Continue used a second time: ${continueAgain}`,
)

verdict(
  'k4',
  A.ok && !!groupDid && /which you just created/.test(A.consentText ?? '') && /\badmin\b/.test(A.consentText ?? ''),
  `app session for ${groupDid ?? 'nothing'}; consent: ${(A.consentText ?? '').slice(0, 200)}`,
)

// k5: the key as the page showed it, as hex and as its raw bytes, searched for in the host's whole
// log and in a tar of its data directory. Only the counts and sizes are printed.
let k5 = { log: null, data: null, bytes: null }
if (page.secret && page.raw) {
  const needles = [Buffer.from(page.secret), Buffer.from(hex(page.raw)), Buffer.from(page.raw)]
  const found = (buf) => needles.filter((n) => buf.indexOf(n) !== -1).length
  // docker logs replays the container's stdout and stderr on its own two; read both.
  const logs = execFileSync('sh', ['-c', 'docker logs "$0" 2>&1', HOST_CONTAINER], { maxBuffer: 2 ** 30 })
  const data = execFileSync('docker', ['exec', HOST_CONTAINER, 'tar', '-c', '-C', '/', 'data'], { maxBuffer: 2 ** 31, stdio: ['ignore', 'pipe', 'ignore'] })
  k5 = { log: found(logs), data: found(data), bytes: { log: logs.length, data: data.length } }
}
verdict('k5', k5.log === 0 && k5.data === 0, `encodings of the private key found: in the host's log ${k5.log}, under /data ${k5.data} (searched ${JSON.stringify(k5.bytes)} bytes)`)

summary()
