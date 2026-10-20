// probe-subscribe-repos.mjs: the host serves com.atproto.sync.subscribeRepos, the feed a relay follows.
//   f1  subscribeRepos opens at the host: the websocket upgrade is answered 101. A host that listens
//       without the PDS's upgrade handler (before 9645bcc) answers it as a plain GET instead
//   f2  a group writes to its public repo (alice's new group puts its declaration) and the commit
//       arrives on the feed: a #commit for the group's repo with that create in its ops
//   f3  the delete that takes it back down arrives too, later in the feed
// The feed is opened before anything is written, so a host that refuses it gets no group made.
// FEED_URL points the feed at another host (http://127.0.0.1:<port>, a throwaway one for a
// control); the default is the host's own name, through the devnet's nginx, as a relay reaches it.
// Run: ../../atproto-devnet/scripts/https-run node probe-subscribe-repos.mjs 2>&1 | tee run-subscribe-repos.log
import crypto from 'node:crypto'
import http from 'node:http'
import https from 'node:https'
import { HOST, alice, as, groupSignIn, log, now, sleep, summary, verdict } from './lib.mjs'

const NS = 'group.opensocial'
const DECLARATION = `${NS}.declaration`
const PATH = `${DECLARATION}/self`
const FEED = new URL('/xrpc/com.atproto.sync.subscribeRepos', process.env.FEED_URL ?? HOST)
const WAIT_MS = 15000

// ---------- DAG-CBOR, as much of it as a feed frame uses ----------
function decode(buf, pos = 0) {
  const head = buf[pos++]
  const major = head >> 5
  const info = head & 0x1f
  let n = info
  if (info === 24) n = buf[pos++]
  else if (info === 25) (n = buf.readUInt16BE(pos)), (pos += 2)
  else if (info === 26) (n = buf.readUInt32BE(pos)), (pos += 4)
  else if (info === 27) (n = Number(buf.readBigUInt64BE(pos))), (pos += 8)
  else if (info > 27 && major !== 7) throw new Error(`cbor: indefinite or reserved length at ${pos - 1}`)
  switch (major) {
    case 0:
      return [n, pos]
    case 1:
      return [-1 - n, pos]
    case 2:
      return [buf.subarray(pos, pos + n), pos + n]
    case 3:
      return [buf.toString('utf8', pos, pos + n), pos + n]
    case 4: {
      const out = []
      for (let i = 0; i < n; i++) {
        let v
        ;[v, pos] = decode(buf, pos)
        out.push(v)
      }
      return [out, pos]
    }
    case 5: {
      const out = {}
      for (let i = 0; i < n; i++) {
        let k, v
        ;[k, pos] = decode(buf, pos)
        ;[v, pos] = decode(buf, pos)
        out[k] = v
      }
      return [out, pos]
    }
    case 6: {
      // Tag 42 is a CID: its bytes, behind a 0x00. The probe keeps it as hex.
      const [v, next] = decode(buf, pos)
      return [n === 42 ? { cid: Buffer.from(v.subarray(1)).toString('hex') } : v, next]
    }
    default:
      if (info === 20) return [false, pos]
      if (info === 21) return [true, pos]
      if (info === 22) return [null, pos]
      if (info === 27) return [buf.readDoubleBE(pos - 8), pos]
      throw new Error(`cbor: simple value ${info}`)
  }
}

// ---------- a websocket client, as small as the feed needs ----------
// The handshake is made by hand so a refusal can be read: its status and XRPC error, not just a
// closed socket.
function openFeed(url) {
  const frames = []
  const waiters = new Set()
  const notify = () => waiters.forEach((w) => w())
  return new Promise((resolve) => {
    const secure = url.protocol === 'https:'
    const req = (secure ? https : http).request(url, {
      headers: { connection: 'Upgrade', upgrade: 'websocket', 'sec-websocket-version': '13', 'sec-websocket-key': crypto.randomBytes(16).toString('base64') },
    })
    req.on('response', (res) => {
      let body = ''
      res.on('data', (c) => (body += c))
      res.on('end', () => {
        let parsed = null
        try {
          parsed = JSON.parse(body)
        } catch {}
        resolve({ open: false, status: res.statusCode, error: parsed?.error ?? null, upgrade: res.headers.upgrade ?? null })
      })
    })
    req.on('error', (e) => resolve({ open: false, status: 0, error: e.code ?? e.message }))
    req.on('upgrade', (res, socket, head) => {
      let pending = head
      let message = []
      socket.on('data', (chunk) => {
        pending = Buffer.concat([pending, chunk])
        for (;;) {
          if (pending.length < 2) return
          const fin = pending[0] & 0x80
          const opcode = pending[0] & 0x0f
          let len = pending[1] & 0x7f
          let at = 2
          if (len === 126) {
            if (pending.length < 4) return
            len = pending.readUInt16BE(2)
            at = 4
          } else if (len === 127) {
            if (pending.length < 10) return
            len = Number(pending.readBigUInt64BE(2))
            at = 10
          }
          if (pending.length < at + len) return
          const payload = pending.subarray(at, at + len)
          pending = pending.subarray(at + len)
          if (opcode === 0x9) {
            // A ping: answer with a masked pong, as a client must.
            const mask = crypto.randomBytes(4)
            const masked = Buffer.from(payload.map((b, i) => b ^ mask[i % 4]))
            socket.write(Buffer.concat([Buffer.from([0x8a, 0x80 | masked.length]), mask, masked]))
            continue
          }
          if (opcode === 0x8) {
            frames.push({ closed: payload.length >= 2 ? payload.readUInt16BE(0) : null })
            notify()
            continue
          }
          message.push(payload)
          if (!fin) continue
          const whole = Buffer.concat(message)
          message = []
          try {
            const [header, next] = decode(whole)
            const [body] = decode(whole, next)
            frames.push({ at: Date.now(), header, body })
          } catch (e) {
            frames.push({ at: Date.now(), undecoded: e.message })
          }
          notify()
        }
      })
      socket.on('close', () => {
        frames.push({ closed: 'socket' })
        notify()
      })
      resolve({
        open: true,
        status: res.statusCode,
        upgrade: res.headers.upgrade ?? null,
        frames,
        // Wait for a frame `match` accepts, from those received at index `from` on.
        waitFor: (match, from = 0, ms = WAIT_MS) =>
          new Promise((done) => {
            const look = () => {
              const i = frames.findIndex((f, j) => j >= from && match(f))
              if (i < 0) return false
              waiters.delete(look)
              clearTimeout(timer)
              done({ index: i, frame: frames[i] })
              return true
            }
            const timer = setTimeout(() => {
              waiters.delete(look)
              done(null)
            }, ms)
            waiters.add(look)
            look()
          }),
        close: () => socket.destroy(),
      })
    })
    req.end()
  })
}

const opIn = (repo, action) => (f) => f.header?.t === '#commit' && f.body?.repo === repo && (f.body.ops ?? []).some((o) => o.action === action && o.path === PATH)
const brief = (f) => (f ? { t: f.header?.t, seq: f.body?.seq, repo: f.body?.repo, rev: f.body?.rev, ops: (f.body?.ops ?? []).map((o) => `${o.action} ${o.path}`) } : null)

log(`# probe-subscribe-repos ${now()}`)

// ---------- f1 ----------
log(`\n## f1 subscribeRepos opens at ${FEED.origin}\n`)
const feed = await openFeed(FEED)
log(`- ${now()} GET ${FEED.href} with a websocket upgrade -> ${feed.status}${feed.upgrade ? ` upgrade: ${feed.upgrade}` : ''}${feed.error ? ` error: ${feed.error}` : ''}`)
verdict('f1', feed.open && feed.status === 101, feed.open ? `the upgrade was answered ${feed.status} (${feed.upgrade})` : `no feed: answered ${feed.status} as a plain request, XRPC error ${feed.error}`)

if (!feed.open) {
  verdict('f2', false, 'not tried: no feed to watch, so no group was made')
  verdict('f3', false, 'not tried: no feed to watch')
  summary()
  process.exit(0)
}

// ---------- f2 ----------
log('\n## f2 a group write arrives on the feed\n')
const label = `fh${Date.now().toString(36)}`
const A = await groupSignIn(alice, { create: { label }, scopes: ['atproto', `repo?collection=${DECLARATION}`] })
if (!A.ok) {
  verdict('f2', false, 'not tried: the create flow did not reach the app')
  verdict('f3', false, 'not tried')
  feed.close()
  summary()
  process.exit(0)
}
const G = A.session.did
log(`- group ${G} (${label}); ${feed.frames.length} frames on the feed so far, ${feed.frames.filter((f) => f.body?.repo === G || f.body?.did === G).length} of them for the group`)
const asA = (method, nsid, body) => as(A.session, 'alice for the group', method, nsid, { body })
const mark = feed.frames.length
const w2 = await asA('POST', 'com.atproto.repo.putRecord', { repo: G, collection: DECLARATION, rkey: 'self', record: { $type: DECLARATION, meta: `at://${G}/space/${NS}.meta/self` } })
const sent2 = Date.now()
const got2 = w2.status === 200 ? await feed.waitFor(opIn(G, 'create'), mark) : null
log(`- ${now()} on the feed: ${JSON.stringify(brief(got2?.frame))}${got2 ? ` ${got2.frame.at - sent2} ms after the write returned` : ` nothing within ${WAIT_MS} ms`}`)
verdict(
  'f2',
  w2.status === 200 && !!got2 && got2.frame.body.rev === w2.body?.commit?.rev,
  `putRecord ${w2.status}; ${got2 ? `#commit seq ${got2.frame.body.seq} for the group, rev ${got2.frame.body.rev} (the write's rev ${w2.body?.commit?.rev}), ops ${JSON.stringify(brief(got2.frame).ops)}` : `no #commit for ${PATH} within ${WAIT_MS} ms`}`,
)

// ---------- f3 ----------
log('\n## f3 the delete arrives too\n')
const w3 = await asA('POST', 'com.atproto.repo.deleteRecord', { repo: G, collection: DECLARATION, rkey: 'self' })
const sent3 = Date.now()
const got3 = w3.status === 200 && got2 ? await feed.waitFor(opIn(G, 'delete'), got2.index + 1) : null
log(`- ${now()} on the feed: ${JSON.stringify(brief(got3?.frame))}${got3 ? ` ${got3.frame.at - sent3} ms after the write returned` : ` nothing within ${WAIT_MS} ms`}`)
verdict(
  'f3',
  w3.status === 200 && !!got3 && got3.frame.body.seq > got2.frame.body.seq,
  `deleteRecord ${w3.status}; ${got3 ? `#commit seq ${got3.frame.body.seq} (after ${got2.frame.body.seq}), ops ${JSON.stringify(brief(got3.frame).ops)}` : 'no delete on the feed'}`,
)

await sleep(200)
feed.close()
log(`\n- group of record: ${G}`)
summary()
process.exit(0)
