// host.mjs: a group host for atproto groups, following the opensocial.group proposal. A group is an
// account with its own DID, and this host is its PDS. docs/design.md explains the design.
//
// Runs inside a container made from the spaces alpha PDS image (bluesky-social/atproto
// permissioned-data-alpha 11c5d98cd, 2026-10-29), so @atproto/pds is exactly the pinned build.
// The sections below, (a) to (h):
//   (a) the alpha PDS runs as a library through PDS.create, behind an outer express app;
//   (b) a person signs in through their own PDS and the host signs the browser in as the GROUP
//       with a one-time ticket fed to the PDS's own sign-in step, never the group's password;
//   (c) a group space under the managedspace policy calls back to this host's checkUserAccess,
//       and what the host answers is what the PDS enforces;
//   (d) the person's roles come from the group's own records: the host offers only the scopes
//       those roles grant, records which person authorized each token, and cuts each token's
//       scopes on every request to what that person's roles grant now;
//   (e) prompt=create makes a group: the account, its meta and members spaces, and their records,
//       with the creator's own recovery key first among the DID's rotation keys, shown once;
//   (f) the host enforces from those records: checkUserAccess answers from `access` and the
//       person's roles, group writes pass the record rules and the writer's `assignable` roles
//       before the PDS takes them, nobody grants more than they hold, writes to a space with no
//       `access` record are refused, and nobody reconfigures, wipes or migrates a group space;
//   (g) a person's own acts on a group (requestJoin, cancelJoinRequest, leaveGroup) come with
//       service auth from their own PDS, not a group session, and the host acts on them as the
//       group;
//   (h) the group's own methods on its join requests (listJoinRequests, denyJoinRequest) take a
//       group session holding the method's rpc: scope, and createSpace takes one holding
//       manage=create for the space's type.
//
// Test routes under /test/*, behind the PDS's admin login, show the host's state and set up test cases.
import crypto from 'node:crypto'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import { PDS, envToCfg, envToSecrets, readEnv } from '/app/packages/pds/dist/index.js'
import { verifyJwt } from '/app/packages/xrpc-server/dist/auth.js'
import { reservedSubdomains } from '/app/packages/pds/dist/handle/reserved.js'
import { hasExplicitSlur } from '/app/packages/pds/dist/handle/explicit-slurs.js'
import { AUTHORIZATION_INACTIVITY_TIMEOUT } from '/app/packages/oauth/oauth-provider/dist/oauth-constants.js'
import { BlobPermission, RepoPermission, SpacePermission, isAtprotoOauthScope } from '/app/packages/oauth/oauth-scopes/dist/index.js'
import { TID } from '/app/packages/common-web/dist/index.js'
import { SpaceRef, isValidDid, isValidNsid, isValidRecordKey } from '/app/packages/syntax/dist/index.js'
import { Secp256k1PrivateKeyExportable } from '@atcute/crypto'
import { OAuthClient, OAuthCallbackError, MemoryStore } from '@atcute/oauth-node-client'
import {
  CompositeDidDocumentResolver,
  LocalActorResolver,
  PlcDidDocumentResolver,
  WebDidDocumentResolver,
  WellKnownHandleResolver,
} from '@atcute/identity-resolver'

const require = createRequire('/app/packages/pds/package.json')
const express = require('express')

const PUBLIC_URL = process.env.HOST_PUBLIC_URL // https://gh.example.com
const HOST_DID = `did:web:${new URL(PUBLIC_URL).host}`
const MANAGING_APP = `${HOST_DID}#group_host`
// Every group space is made under this policy, so the PDS asks the host (checkUserAccess) who may
// read and write it.
const MA = { $type: 'com.atproto.managedspace.policy', managingApp: MANAGING_APP }
const LOOPBACK = process.env.HOST_LOOPBACK_URL // http://127.0.0.1:7070, how the host calls its own PDS
const STATE_FILE = '/data/grouphost-state.json'
const log = (...a) => console.log(new Date().toISOString(), '[host]', ...a)
// The host's own calls to its PDS (creating and seeding a group) carry this, so the gates below
// let them through. It never leaves the process.
const INTERNAL = crypto.randomBytes(32).toString('hex')

const NS = 'group.opensocial'
const META = `${NS}.meta`
const MEMBERS = `${NS}.members`
const spaceUri = (did, type, skey = 'self') => `at://${did}/space/${type}/${skey}`

// ---- the host's own state, in memory (a host in production would keep these in tables) ----
const tickets = new Map() // id -> { groupDid, personDid, exp }
const pending = new Map() // signin state -> { requestUri, clientId, mode, groupDid? }
const consent = new Map() // requestUri -> what the host's consent page shows
const requestPerson = new Map() // OAuth request id -> person DID, set when the ticket is minted
const codePerson = new Map() // authorization code -> person DID, set when the request is authorized
const authorizedBy = [] // { groupDid, personDid, at }: which person each group sign-in stands for
const accessCalls = [] // every checkUserAccess the PDS made
const narrowings = [] // every per-request cut, newest last (capped)
const refusals = [] // every write, space change or group sign-in the host refused, by its gate (no `by`), its PDS or its sign-in

// Which person authorized each token. Kept on the data volume so a restart does not turn every
// mapped token into an unmapped one (an unmapped token is cut to "atproto").
const saved = fs.existsSync(STATE_FILE) ? JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) : {}
const tokenPerson = new Map(Object.entries(saved.tokenPerson ?? {})) // tokenId -> { groupDid, personDid|null, via }
// Pending join requests are the host's own state, not records (proposal.md:222-226).
const joinRequests = new Map(Object.entries(saved.joinRequests ?? {})) // `${group} ${member}` -> { group, member, createdAt, message? }
// Creates under way: noted before the account is made and dropped once the creator's membership
// is written, so a create the process did not live to finish is found at the next start.
const creates = new Map(Object.entries(saved.creates ?? {})) // handle -> { handle, creatorDid, startedAt, did? }
const persist = () =>
  fs.writeFileSync(
    STATE_FILE,
    JSON.stringify({ tokenPerson: Object.fromEntries(tokenPerson), joinRequests: Object.fromEntries(joinRequests), creates: Object.fromEntries(creates) }),
  )
const methodCalls = [] // every group method call: who, which audience, what came of it (capped)

// ---- (a) the PDS as a library ----
const env = readEnv()
const cfg = envToCfg(env)
const secrets = envToSecrets(env)
const pds = await PDS.create(cfg, secrets)
const provider = pds.ctx.oauthProvider
log('PDS.create ok; oauthProvider', provider ? 'present' : 'absent', '; service did', cfg.service.did)

// ---- (b) sign-in by ticket: wrap the provider's account store instance (no file patched) ----
// The provider uses one store object for accounts, requests and tokens.
const store = provider.accountManager.store
const origAuthenticate = store.authenticateAccount.bind(store)
store.authenticateAccount = async (data) => {
  if (typeof data.password === 'string' && data.password.startsWith('ticket:')) {
    const id = data.password.slice('ticket:'.length)
    const t = tickets.get(id)
    tickets.delete(id) // single use, whatever happens next
    const groupDid = data.username.startsWith('did:')
      ? data.username
      : await pds.ctx.accountManager.getAccount(data.username).then((a) => a?.did)
    if (!t || t.exp < Date.now() || t.groupDid !== groupDid) {
      log('ticket sign-in REFUSED', { known: !!t, groupMatches: t?.groupDid === groupDid })
      const { InvalidRequestError } = require('@atproto/oauth-provider')
      throw new InvalidRequestError('Invalid ticket')
    }
    authorizedBy.push({ groupDid, personDid: t.personDid, at: new Date().toISOString() })
    log('ticket sign-in accepted', { groupDid, personDid: t.personDid })
    const { account } = await store.getAccount(groupDid)
    return account
  }
  return origAuthenticate(data)
}

// ---- (d) roles from the group's records ----
// Reads the group's own space repos straight from the actor store: the host is their PDS.
async function readGroup(groupDid) {
  return pds.ctx.actorStore.read(groupDid, async (actor) => {
    const list = async (space, collection) =>
      (await actor.space.listRecords(space, { limit: 100, collection })).map((r) => ({ rkey: r.rkey, uri: r.uri, cid: r.cid, value: r.value }))
    const members = spaceUri(groupDid, MEMBERS)
    const spaces = await actor.space.listSpaces({ limit: 100, authority: groupDid })
    const accessRecords = []
    for (const s of spaces) {
      const [, , , , type, skey] = s.uri.split('/') // at://<did>/space/<type>/<skey>
      const rec = (await list(s.uri, `${NS}.access`)).find((r) => r.rkey === 'self')
      if (rec) accessRecords.push({ space: { uri: s.uri, type, skey }, value: rec.value })
    }
    return {
      roles: await list(members, `${NS}.role`),
      memberships: await list(members, `${NS}.membership`),
      permissions: (await list(members, `${NS}.permissions`)).find((r) => r.rkey === 'self')?.value ?? null,
      profile: (await list(spaceUri(groupDid, META), `${NS}.profile`)).find((r) => r.rkey === 'self')?.value ?? null,
      access: accessRecords,
      spaces: spaces.map((s) => s.uri),
    }
  })
}

// A space grant from an `access` record applies only to that space, so it is pinned to it.
function pinToSpace(scope, space, groupDid) {
  const sp = SpacePermission.fromString(scope)
  if (!sp) return null // only space: scopes mean anything in an access record
  if (sp.type !== '*' && sp.type !== space.type) return null
  if (sp.authority !== '*' && sp.authority !== groupDid) return null
  if (sp.skey !== '*' && sp.skey !== space.skey) return null
  return new SpacePermission(space.type, groupDid, space.skey, sp.collection, sp.action, sp.manage).toString()
}

// The scopes a person's current roles grant on the group DID, expanded the same way the PDS
// expands a token's scope (permission sets, bare space types, authority=self).
async function grantsFor(groupDid, personDid) {
  const g = await readGroup(groupDid)
  const declared = new Set(g.roles.map((r) => r.rkey))
  const m = g.memberships.find((r) => r.rkey === personDid && r.value?.member === personDid)
  const roles = (m?.value.roles ?? []).filter((r) => declared.has(r))
  const raw = []
  const assignable = new Set()
  for (const grant of g.permissions?.grants ?? []) {
    if (!roles.includes(grant.role)) continue
    for (const s of grant.scopes ?? []) raw.push({ scope: s, space: null })
    for (const a of grant.assignable ?? []) assignable.add(a)
  }
  for (const { space, value } of g.access) {
    for (const grant of value.grants ?? []) {
      if (!roles.includes(grant.role)) continue
      for (const s of grant.scopes ?? []) raw.push({ scope: s, space })
    }
  }
  const strings = new Set()
  const spaces = []
  const repos = [] // repo: and blob: grants come from `permissions` only: pinToSpace drops them
  const blobs = []
  const bySpace = new Map() // space uri -> the access-record grants pinned to it
  for (const { scope, space } of raw) {
    let parts
    try {
      parts = (await provider.lexiconManager.buildTokenScope(scope, groupDid)).split(' ')
    } catch (err) {
      log('grant scope does not expand, skipped', { scope, err: err.message })
      continue
    }
    for (const p of parts) {
      const s = space ? pinToSpace(p, space, groupDid) : p
      if (!s) continue
      strings.add(s)
      const sp = SpacePermission.fromString(s)
      if (sp) spaces.push(sp)
      if (sp && space) bySpace.set(space.uri, [...(bySpace.get(space.uri) ?? []), sp])
      const rp = RepoPermission.fromString(s)
      if (rp) repos.push(rp)
      const bp = BlobPermission.fromString(s)
      if (bp) blobs.push(bp)
    }
  }
  return { roles, assignable: [...assignable], strings, spaces, repos, blobs, bySpace }
}

// Whether a granted blob accept (`*/*`, `image/*`, `image/png`) takes in a requested one.
const acceptCovers = (granted, asked) =>
  granted === '*/*' || granted === asked || (granted.endsWith('/*') && asked.startsWith(granted.slice(0, -1)))

// Whether one expanded scope is wholly inside what the grants allow. Space and repo scopes are
// split into single operations and each must match some grant, and each type a blob scope accepts
// must be inside some grant's, so `repo:*` covers an app asking for one collection; other scopes
// must be granted as written.
function covered(item, grants) {
  if (item === 'atproto') return true
  const rp = RepoPermission.fromString(item)
  if (rp) return rp.collection.every((collection) => rp.action.every((action) => grants.repos.some((g) => g.matches({ collection, action }))))
  const bp = BlobPermission.fromString(item)
  if (bp) return bp.accept.every((asked) => grants.blobs.some((g) => g.accept.some((granted) => acceptCovers(granted, asked))))
  const sp = SpacePermission.fromString(item)
  if (!sp) return grants.strings.has(item)
  const ref = { type: sp.type, authority: sp.authority, skey: sp.skey }
  const ops = []
  for (const action of sp.action) {
    if (action === 'read' || action === 'read_self') ops.push({ ...ref, action })
    else for (const collection of sp.collection ?? []) ops.push({ ...ref, action, collection })
  }
  for (const manage of sp.manage ?? []) ops.push({ ...ref, manage })
  return ops.length > 0 && ops.every((op) => grants.spaces.some((g) => g.matches(op)))
}

// At authorize: keep each requested scope (as the app wrote it, permission sets included) only
// if everything it expands to is granted.
async function narrowRequested(scope, grants, groupDid) {
  const kept = []
  const dropped = []
  for (const item of (scope ?? '').split(' ').filter(Boolean)) {
    let parts
    try {
      parts = item === 'atproto' ? ['atproto'] : (await provider.lexiconManager.buildTokenScope(item, groupDid)).split(' ')
    } catch {
      parts = null
    }
    ;(parts && parts.every((p) => covered(p, grants)) ? kept : dropped).push(item)
  }
  if (!kept.includes('atproto')) kept.unshift('atproto')
  return { kept, dropped }
}

// ---- (d) tie each token to the person who authorized it ----
const reqId = (requestUri) => requestUri.replace(/^urn:ietf:params:oauth:request_uri:/, '')

// The provider hands one hooks object to all its managers, so wrapping a hook here is seen by
// the request manager. The PDS's own hook (an event) still runs.
const hooks = provider.hooks
const origOnAuthorized = hooks.onAuthorized
hooks.onAuthorized = async (data) => {
  await origOnAuthorized?.call(null, data)
  const personDid = requestPerson.get(data.requestId)
  requestPerson.delete(data.requestId)
  if (!personDid) return
  // The request store holds the code by now: setAuthorized writes it before calling this hook.
  const req = await store.readRequest(data.requestId)
  if (req?.code) codePerson.set(req.code, personDid)
}

const origCreateToken = store.createToken.bind(store)
store.createToken = async (tokenId, data, refreshToken) => {
  await origCreateToken(tokenId, data, refreshToken)
  const personDid = codePerson.get(data.code) ?? null
  codePerson.delete(data.code)
  tokenPerson.set(tokenId, { groupDid: data.did, personDid, via: personDid ? 'person' : 'direct' })
  persist()
  log('token created', { group: data.did, personDid, scope: data.scope })
}

const origRotateToken = store.rotateToken.bind(store)
store.rotateToken = async (tokenId, newTokenId, newRefreshToken, newData) => {
  await origRotateToken(tokenId, newTokenId, newRefreshToken, newData)
  const entry = tokenPerson.get(tokenId)
  tokenPerson.delete(tokenId)
  if (entry) tokenPerson.set(newTokenId, entry)
  persist()
  log('token rotated', { mapped: !!entry })
}

// In stateful mode the provider reloads each token's claims, scope included, from its store on
// every request. Cutting the scope here applies the person's current roles to every request.
const tm = provider.tokenManager
const origLoadClaims = tm.loadTokenClaims.bind(tm)
tm.loadTokenClaims = async (tokenType, payload) => {
  const claims = await origLoadClaims(tokenType, payload)
  const entry = tokenPerson.get(claims.jti)
  let scope = claims.scope
  if (!entry) scope = 'atproto' // not issued through this host's sign-in, or lost: grants nothing
  else if (entry.personDid) {
    const grants = await grantsFor(claims.sub, entry.personDid)
    scope = (claims.scope ?? '').split(' ').filter((s) => covered(s, grants)).join(' ') || 'atproto'
  }
  if (scope !== claims.scope) {
    narrowings.push({ at: new Date().toISOString(), group: claims.sub, personDid: entry?.personDid ?? null, from: claims.scope, to: scope })
    if (narrowings.length > 50) narrowings.shift()
  }
  return { ...claims, scope }
}

// ---- (e) prompt=create: make the group and write its starting records ----
async function xrpc(nsid, body, jwt) {
  const res = await fetch(`${LOOPBACK}/xrpc/${nsid}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-grouphost-internal': INTERNAL, ...(jwt ? { authorization: `Bearer ${jwt}` } : {}) },
    body: JSON.stringify(body),
  })
  const json = await res.json().catch(() => null)
  if (!res.ok) throw new Error(`${nsid} ${res.status} ${json?.error ?? ''} ${json?.message ?? ''}`)
  return json
}

// A session for a group the host holds, with no password: the PDS's account manager mints it.
// For the host's own acts as the group (setup here, join approval later).
async function groupJwt(did) {
  return (await pds.ctx.accountManager.createSession(did, null)).accessJwt
}

const HANDLE_DOMAIN = cfg.identity.serviceHandleDomains[0]
const groupEmail = (label) => `${label}@groups.invalid`

// Why a new group's address cannot be made: a reason, worded for the person in one place.
const ADDRESS_WORDS = {
  empty: () => 'Choose an address for the group.',
  characters: () => 'An address uses only letters, digits and dashes, and does not start or end with a dash.',
  length: (label) => `An address is 3 to 18 characters long; "${label}" is ${label.length}.`,
  reserved: (label) => `"${label}" is reserved on this server. Choose another address.`,
  word: (label) => `"${label}" is not allowed on this server. Choose another address.`,
  taken: (label) => `${label}${HANDLE_DOMAIN} is taken. Choose another address.`,
  refused: (label, detail) => `This server will not take "${label}" (${detail}).`,
}
const addressRefusal = (reason, label, detail) => ({ reason, text: ADDRESS_WORDS[reason](label, detail) })

// What the PDS's createAccount would refuse in a new group's address, checked before the person
// goes to their own PDS, so a refusal is said on the sign-in page and the sign-in is not spent.
// These are the PDS's own checks (account-manager.js normalizeAndValidateHandle, handle/index.js
// ensureHandleServiceConstraints): 3 to 18 characters before the domain, its reserved names and
// word filter, a handle and email no account holds. Anything else it refuses, in its own words.
async function addressProblem(label) {
  if (!label) return addressRefusal('empty', label)
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) return addressRefusal('characters', label)
  if (label.length < 3 || label.length > 18) return addressRefusal('length', label)
  const handle = `${label}${HANDLE_DOMAIN}`
  if (reservedSubdomains[label]) return addressRefusal('reserved', label)
  if (hasExplicitSlur(handle)) return addressRefusal('word', label)
  try {
    await pds.ctx.accountManager.normalizeAndValidateHandle(handle)
  } catch (err) {
    return addressRefusal('refused', label, err.message)
  }
  const all = { includeDeactivated: true, includeTakenDown: true }
  const [byHandle, byEmail] = await Promise.all([
    pds.ctx.accountManager.getAccount(handle, all),
    pds.ctx.accountManager.getAccountByEmail(groupEmail(label), all),
  ])
  return byHandle || byEmail ? addressRefusal('taken', label) : null
}

// Whether the group's DID, as its PLC holds it now, has `key` first among its rotation keys. The
// PLC is asked, not the request: the key first is what lets the creator move the group without
// this host, since the first key wins any conflict there.
async function recoveryKeyFirst(did, key) {
  const res = await fetch(new URL(`/${did}/data`, cfg.identity.plcUrl))
  if (!res.ok) throw new Error(`the PLC answered ${res.status} for ${did}`)
  const { rotationKeys } = await res.json()
  if (!Array.isArray(rotationKeys) || rotationKeys[0] !== key) {
    throw new Error(`${did}'s first rotation key is ${JSON.stringify(rotationKeys?.[0] ?? null)}, not the creator's`)
  }
}

// A create that fails once its account exists removes the account, so the address is free again
// and no group is left without an admin. `afterAccount` is the probes' way to cut it short there
// (/test/interrupted-create).
//
// The creator gets a recovery key: a new keypair whose public half createAccount puts first
// among the DID's rotation keys, ahead of the PDS's own. The private half is returned for the
// creator to see once, and is never written down here, not in the state file, a log or the PDS.
// The proposal is silent on recovery; this is the host's choice.
async function createGroup({ label, creatorDid, afterAccount }) {
  const handle = `${label}${HANDLE_DOMAIN}`
  creates.set(handle, { handle, creatorDid, startedAt: new Date().toISOString() })
  persist()
  let did, recoveryKey
  try {
    const keypair = await Secp256k1PrivateKeyExportable.createKeypair()
    const recoveryDid = await keypair.exportPublicKey('did')
    // The PDS's createAccount needs a password. This one is random, used for the seeding calls
    // below, and dropped: nobody ever sees or holds it. The product should create the account
    // with no password at all.
    const password = crypto.randomBytes(32).toString('base64url')
    const acct = await xrpc('com.atproto.server.createAccount', { handle, email: groupEmail(label), password, recoveryKey: recoveryDid })
    did = acct.did
    creates.set(handle, { ...creates.get(handle), did })
    persist()
    await afterAccount?.(did)
    await recoveryKeyFirst(did, recoveryDid)
    recoveryKey = { did: recoveryDid, secret: await keypair.exportPrivateKey('multikey') }
    await seedRecords(did, acct.accessJwt, { label, creatorDid })
  } catch (err) {
    try {
      if (did) await removeGroupAccount(did, `create failed: ${err.message}`)
      creates.delete(handle)
      persist()
    } catch (cleanup) {
      // The note stays, so the next start removes it.
      log('could not remove a half-made group', { handle, did, err: cleanup.message })
    }
    throw err
  }
  creates.delete(handle)
  persist()
  log('group created', { did, handle, creatorDid, recoveryKey: recoveryKey.did })
  return { did, handle, recoveryKey }
}

// Removes a group the host made but did not finish, as the PDS's own admin deleteAccount does: the
// account first, then the deletion event, then its files (its spaces are in them).
async function removeGroupAccount(did, why) {
  await pds.ctx.accountManager.deleteAccount(did)
  try {
    await pds.ctx.sequencer.sequenceAccountDeletion(did)
  } finally {
    await pds.ctx.actorStore.destroy(did)
  }
  log('half-made group removed', { did, why })
}

// The group's starting records, the creator's membership last.
// The starting profile's display name is the address. The app that made the group names it: the
// host's page asks only what the host decides, as a PDS's own sign-up asks only the handle.
async function seedRecords(did, jwt, { label, creatorDid }) {
  const now = new Date().toISOString()
  for (const type of [META, MEMBERS]) {
    await xrpc('com.atproto.space.createSpace', { spaceType: type, skey: 'self', policy: MA }, jwt)
  }
  const put = (type, collection, rkey, record) =>
    xrpc('com.atproto.space.createRecord', { space: spaceUri(did, type), repo: did, collection, rkey, record: { $type: collection, ...record } }, jwt)
  // Roles first: a membership may name only declared roles.
  await put(MEMBERS, `${NS}.role`, 'admin', { displayName: 'Admin', description: 'Runs the group.' })
  await put(MEMBERS, `${NS}.role`, 'member', { displayName: 'Member', default: true })
  await put(META, `${NS}.access`, 'self', {
    public: false,
    grants: [
      { role: 'admin', scopes: [`space:${META}?collection=*`] },
      { role: 'member', scopes: [`space:${META}?action=read`] },
    ],
  })
  await put(MEMBERS, `${NS}.access`, 'self', {
    grants: [
      { role: 'admin', scopes: [`space:${MEMBERS}?collection=*`] },
      { role: 'member', scopes: [`space:${MEMBERS}?action=read`] },
    ],
  })
  await put(META, `${NS}.profile`, 'self', { displayName: label, joinPolicy: 'approval' })
  await put(MEMBERS, `${NS}.permissions`, 'self', {
    grants: [
      {
        role: 'admin',
        scopes: [
          // The proposal's permission sets, as its example `permissions` record grants an admin,
          // so a group session that asks for a set gets it whole. Where the group lexicons do not
          // resolve a set grants nothing, and the scopes below still hold.
          `include:${NS}.configure`,
          `include:${NS}.manageSpaces`,
          `include:${NS}.manageMembers`,
          `include:${NS}.moderate`,
          'space:*?action=read_self&manage=create&manage=delete',
          // Read and write in every group space, ones made later included, so a session the
          // creator authorizes at create already covers the spaces an app adds next.
          'space:*?collection=*',
          // Labels in any group space, write only: with no action a space scope also reads.
          'space:*?collection=com.atproto.label.label&action=create&action=update&action=delete',
          // The group's public repo (its declaration, public records) and blob uploads (images).
          'repo:*',
          'blob:*/*',
          `rpc:${NS}.listJoinRequests?aud=*`,
          `rpc:${NS}.denyJoinRequest?aud=*`,
        ],
        assignable: ['admin', 'member'],
      },
      { role: 'member', scopes: [], assignable: [] },
    ],
  })
  await put(MEMBERS, `${NS}.membership`, creatorDid, { member: creatorDid, roles: ['admin'], createdAt: now })
}

// Whether a create got as far as its last record, the creator's membership.
const createFinished = (did, creatorDid) =>
  pds.ctx.actorStore.read(did, async (actor) =>
    (await actor.space.listRecords(spaceUri(did, MEMBERS), { limit: 100, collection: `${NS}.membership` })).some((r) => r.rkey === creatorDid),
  )

// A create the last run did not finish: its account is removed, unless the create got as far as
// the creator's membership and only the note was left. Without the new DID (the process stopped
// before it was noted), the account found by the address counts only if it was made after the
// note, so a group that already held the address is never taken for a half-made one.
async function settleInterruptedCreates() {
  for (const c of [...creates.values()]) {
    try {
      const account = await pds.ctx.accountManager.getAccount(c.did ?? c.handle)
      const ours = account && (c.did || account.createdAt >= c.startedAt)
      if (ours && !(await createFinished(account.did, c.creatorDid).catch(() => false))) {
        await removeGroupAccount(account.did, 'create interrupted')
      }
      creates.delete(c.handle)
    } catch (err) {
      log('could not settle an interrupted create', { handle: c.handle, err: err.message })
    }
  }
  persist()
}

// ---- sign-in through the person's own PDS ----
// The host as an OAuth CLIENT of the person's own PDS (authentication only). A public client at
// PUBLIC_URL, so the browser comes back to the host's public name from wherever the person is. It
// holds no key and asks for no more than `atproto`, and its session is dropped once the callback
// has said who the person is. A host that keeps the person's session would be a confidential
// client, with a key.
const CLIENT_ID = `${PUBLIC_URL}/signin/client-metadata.json`
// Kept by name so the callback can find whose sign-in a refusal belongs to: the client drops the
// state before it throws a refusal, and the refusal carries only the state's id.
const personStates = new MemoryStore({ ttl: 600_000 })
const actorResolver = new LocalActorResolver({
  handleResolver: new WellKnownHandleResolver(),
  didDocumentResolver: new CompositeDidDocumentResolver({
    methods: { plc: new PlcDidDocumentResolver({ apiUrl: process.env.HOST_PLC_URL }), web: new WebDidDocumentResolver() },
  }),
})
const personClient = new OAuthClient({
  metadata: {
    client_id: CLIENT_ID,
    client_name: 'Group host sign-in',
    client_uri: PUBLIC_URL,
    redirect_uris: [`${PUBLIC_URL}/signin/callback`],
    scope: 'atproto',
  },
  actorResolver,
  stores: { sessions: new MemoryStore(), states: personStates },
})

async function groupDidOf(hint) {
  if (!hint) return undefined
  if (hint.startsWith('did:')) return (await pds.ctx.accountManager.getAccount(hint)) ? hint : undefined
  return (await pds.ctx.accountManager.getAccount(hint))?.did
}
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)

// Hints an app may put on the link it sends the browser to, to fill in the start page: gh_name,
// the group's name as the person typed it in the app (a create only), and gh_person, the person's
// DID. This host's own addition; the proposal is silent on it, and another host ignores
// them. A hint only fills in a field, which stays editable, and the checks on Continue are the same
// as for anything typed. Nothing else reads a hint: the creator is whoever signs in at their own
// PDS. A hint that does not work out (too long, malformed, unresolvable) leaves its field empty.
const GH_NAME_MAX = 256 // characters; a longer name suggests nothing
const GH_PERSON_MAX = 2048 // characters, atproto's DID limit (isValidDid checks it too)
const ADDRESS_MAX = 18 // the PDS's limit on a handle's first label, which addressProblem checks

// The address a name suggests: lowercase, each run of anything outside a-z0-9 one dash, no dash at
// either end, cut to 18 with no dash left at the end. Under 3 characters suggests nothing.
function addressFromName(name) {
  if (typeof name !== 'string' || name.length > GH_NAME_MAX) return ''
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, ADDRESS_MAX)
    .replace(/-+$/, '')
  return slug.length >= 3 ? slug : ''
}

// The handle a person's DID names, checked both ways by the host's own resolver, or ''.
async function handleOfPerson(did) {
  if (typeof did !== 'string' || did.length > GH_PERSON_MAX || !isValidDid(did)) return ''
  try {
    const { handle } = await actorResolver.resolve(did, { signal: AbortSignal.timeout(5000) })
    return handle && handle !== 'handle.invalid' ? handle : ''
  } catch {
    return ''
  }
}

const outer = express()

// The host's own calls to its PDS carry INTERNAL. The mark comes off the request here, before
// anything else sees it, so the PDS's request log, which prints every header, never shows it.
const internalCalls = new WeakSet()
outer.use((req, res, next) => {
  if (req.headers['x-grouphost-internal'] === INTERNAL) internalCalls.add(req)
  delete req.headers['x-grouphost-internal']
  next()
})

// The sign-in client's metadata, which a person's own PDS fetches to learn who is asking.
outer.get('/signin/client-metadata.json', (req, res) => res.json(personClient.metadata))

// did:web for the host itself, naming the endpoint the PDS calls for checkUserAccess.
outer.get('/.well-known/did.json', (req, res) => {
  res.json({
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: HOST_DID,
    service: [{ id: '#group_host', type: 'GroupHost', serviceEndpoint: PUBLIC_URL }],
  })
})

// Every request for a group, and every prompt=create, signs in through the person's own PDS.
// There is no way past this to the PDS's own sign-in page for a group.
outer.get('/oauth/authorize', async (req, res, next) => {
  try {
    const { request_uri: requestUri, client_id: clientId } = req.query
    if (req.query.gh === 'ticket') return res.type('html').send(ticketPage(requestUri))
    if (!requestUri) return next()
    const data = await store.readRequest(reqId(String(requestUri)))
    const p = data?.parameters ?? {}
    const create = p.prompt === 'create'
    const groupDid = create ? undefined : await groupDidOf(p.login_hint)
    if (!create && !groupDid) return next() // not a group sign-in: the PDS's own page
    const state = crypto.randomBytes(12).toString('hex')
    // What the start page shows first, from the app's hints (see addressFromName).
    const hint = { label: create ? addressFromName(req.query.gh_name) : '', handle: await handleOfPerson(req.query.gh_person) }
    pending.set(state, { requestUri: String(requestUri), clientId: String(clientId), mode: create ? 'create' : 'act', groupDid, hint })
    res.redirect(`${PUBLIC_URL}/signin/start?state=${state}`)
  } catch (err) {
    next(err)
  }
})

// Ask who you are (your own handle), and for a new group its address, then OAuth to your own
// PDS. A refusal comes back to this page as a line above the form, with what was typed kept and
// the sign-in still open; `data-reason` names it for a test. The fields start from the app's
// hints; what the person typed always comes first.
function startPage(state, p, { problem, label = '', handle = '' } = {}) {
  const fields =
    p.mode === 'create'
      ? `<p><label>Address for the new group: <input name=label value="${esc(label)}" placeholder="mygroup">${esc(HANDLE_DOMAIN)}</label><br><small>3 to 18 letters, digits or dashes.</small></p>`
      : `<p>Act as group <code>${esc(p.groupDid)}</code>.</p>`
  return `<!doctype html><title>${p.mode === 'create' ? 'Create a group' : 'Sign in to act as the group'}</title>
${problem ? `<p id=problem role=alert data-reason="${esc(problem.reason)}">${esc(problem.text)}</p>` : ''}
<form method=get><input type=hidden name=state value="${esc(state)}">${fields}
<p>Sign in with your own account: <input name=handle value="${esc(handle)}" placeholder="you.example.com"></p><button>Continue</button></form>`
}

outer.get('/signin/start', async (req, res, next) => {
  try {
    const state = String(req.query.state ?? '')
    const p = pending.get(state)
    // A made group's sign-in is past this page: it goes on only from the recovery key page.
    if (!p || p.mode === 'created') return res.status(400).send('unknown sign-in')
    if (req.query.handle === undefined) {
      // A first visit, or back from a create that failed after the person signed in.
      const { problem } = p
      delete p.problem
      return res.type('html').send(startPage(state, p, { problem, label: p.label ?? p.hint?.label, handle: p.handle ?? p.hint?.handle }))
    }
    const label = String(req.query.label ?? '').trim().toLowerCase()
    const handle = String(req.query.handle).trim()
    const again = (problem) => res.status(400).type('html').send(startPage(state, p, { problem, label, handle }))
    if (p.mode === 'create') {
      const problem = await addressProblem(label)
      if (problem) return again(problem)
      p.label = label
    }
    if (!handle) return again({ reason: 'handle', text: 'Enter your own handle, the account you sign in with.' })
    p.handle = handle
    let url
    try {
      ;({ url } = await personClient.authorize({ target: { type: 'account', identifier: handle }, scope: 'atproto', state: { s: state } }))
    } catch (err) {
      log('person sign-in start failed', { handle, err: err.message })
      return again({ reason: 'handle', text: `Could not find where ${handle} signs in (${err.message}). Check the handle.` })
    }
    res.redirect(url.toString())
  } catch (err) {
    next(err)
  }
})

outer.get('/signin/callback', async (req, res, next) => {
  try {
    const params = new URLSearchParams(req.url.split('?')[1])
    const stored = await personStates.get(params.get('state') ?? '')
    let session, state
    try {
      ;({ session, state } = await personClient.callback(params))
    } catch (err) {
      // The person said no at their own PDS: the app's request ends the same way, as a refusal.
      if (err instanceof OAuthCallbackError && err.error === 'access_denied') {
        return await refuseToApp(res, stored?.userState?.s, err.errorDescription)
      }
      throw err
    }
    const personDid = session.did
    // Who the person is was all the session was for: revoke it at their PDS and drop it here (the
    // client drops it even when the revoke fails). Not awaited, so a slow PDS doesn't hold the sign-in.
    session.signOut().catch((err) => log('sign-out after sign-in failed', { personDid, err: err.message }))
    const p = pending.get(state?.s)
    pending.delete(state?.s)
    if (!p) return res.status(400).send('unknown sign-in')
    // Who may create a group is the host's call; this one lets anyone signed in.
    if (p.mode !== 'create') return await toConsent(res, p, { did: p.groupDid }, personDid)
    let group
    try {
      group = await createGroup({ label: p.label, creatorDid: personDid })
    } catch (err) {
      // Back to the sign-in page with the reason. The app's request is still open, so the person
      // picks another address there instead of starting again from the app.
      log('group create failed', { label: p.label, personDid, err: err.message })
      p.problem = (await addressProblem(p.label)) ?? { reason: 'create', text: `The group could not be made (${err.message}). Try again.` }
      pending.set(state.s, p)
      return res.redirect(`${PUBLIC_URL}/signin/start?${new URLSearchParams({ state: state.s })}`)
    }
    // The recovery key goes in this response and nowhere else, so a reload cannot show it again:
    // this callback's state is spent. Consent follows from Continue, which mints the ticket then,
    // so the ticket's two minutes start after the key is saved. The app's request is extended
    // here as the provider extends it on each step, five minutes of inactivity.
    const { recoveryKey, ...made } = group
    const id = reqId(p.requestUri)
    const data = await store.readRequest(id)
    if (data && data.expiresAt > new Date()) await store.updateRequest(id, { expiresAt: new Date(Date.now() + AUTHORIZATION_INACTIVITY_TIMEOUT) })
    pending.set(state.s, { ...p, mode: 'created', group: made, personDid })
    res.set({ 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' })
    res.type('html').send(recoveryKeyPage(state.s, made, recoveryKey))
  } catch (err) {
    next(err)
  }
})

// The person has the recovery key; on to the host's consent for the app's request. If that
// request has run out meanwhile, the group stands and the person is its admin: the app's sign-in
// as the group starts again from the app.
outer.get('/signin/created', async (req, res, next) => {
  try {
    const s = String(req.query.state ?? '')
    const p = pending.get(s)
    if (p?.mode !== 'created') return res.status(400).send('unknown sign-in')
    pending.delete(s)
    const data = await store.readRequest(reqId(p.requestUri))
    if (!data || data.expiresAt < new Date()) {
      log('app request ran out on the recovery key page', { groupDid: p.group.did, personDid: p.personDid })
      return res.status(410).type('html').send(`<!doctype html><title>Group made</title>
<p id=made>The group @${esc(p.group.handle)} is made, and you are its admin. The app's sign-in ran out while the key was shown, so go back to the app and sign in to the group from there.</p>`)
    }
    await toConsent(res, p, p.group, p.personDid)
  } catch (err) {
    next(err)
  }
})

// Shown once, in the response to the sign-in that made the group. It says what the key does and
// what it does not. `data-did` is the key's
// public half, which the group's PLC lists first among its rotation keys.
function recoveryKeyPage(state, group, key) {
  return `<!doctype html><title>Save the recovery key for @${esc(group.handle)}</title>
<main id=recovery data-did="${esc(key.did)}">
<h1>Save the recovery key for @${esc(group.handle)}</h1>
<p>This is the only time it is shown. This host does not keep it.</p>
<p>With it you can move the group to another host without this host's help: the group's identity record lists it ahead of this host's own keys, so it wins any change to where the group lives. Without it you cannot. Anyone who gets it can do the same, so keep it private.</p>
<p>It is not a password. It does not sign you in here; you act for the group as yourself, as its admin.</p>
<p><label>Recovery key (private)<br><textarea id=recovery-key readonly rows=2 cols=70>${esc(key.secret)}</textarea></label></p>
<p><small>Its public half, as the group's identity lists it: <code>${esc(key.did)}</code></small></p>
<p><a id=continue href="${PUBLIC_URL}/signin/created?${new URLSearchParams({ state })}">I have saved it. Continue</a></p>
</main>`
}

// What the person's roles grant, offered to the app's request on the host's own consent page.
async function toConsent(res, p, group, personDid) {
  const grants = await grantsFor(group.did, personDid)
  log('person signed in through own PDS', { personDid, groupDid: group.did, mode: p.mode, roles: grants.roles })
  if (!grants.roles.length) {
    refusals.push({ at: new Date().toISOString(), by: 'sign-in', group: group.did, personDid, message: 'holds no role' })
    return res.status(403).send(`You (${personDid}) hold no role in ${group.did}`)
  }

  // Offer only what the roles grant: rewrite the pending request's scope before consent.
  const id = reqId(p.requestUri)
  const data = await store.readRequest(id)
  const { kept, dropped } = await narrowRequested(data.parameters.scope, grants, group.did)
  const { prompt, ...rest } = data.parameters
  await store.updateRequest(id, { parameters: { ...rest, scope: kept.join(' '), login_hint: group.did } })
  requestPerson.set(id, personDid)
  const groupHandle = group.handle ?? (await pds.ctx.accountManager.getAccount(group.did))?.handle
  consent.set(p.requestUri, { groupDid: group.did, groupHandle, personDid, roles: grants.roles, clientId: p.clientId, kept, dropped, created: p.mode === 'created' })
  log('scopes offered', { personDid, roles: grants.roles, kept, dropped })

  const t = crypto.randomBytes(24).toString('base64url')
  tickets.set(t, { groupDid: group.did, personDid, exp: Date.now() + 120_000 })
  // The ticket rides the URL fragment, never sent to a server and never in a referrer, and not
  // a cookie, which the sign-in step of the provider's own page would not see.
  const q = new URLSearchParams({ request_uri: p.requestUri, client_id: p.clientId, gh: 'ticket' })
  const frag = new URLSearchParams({ t, g: group.did })
  res.redirect(`${PUBLIC_URL}/oauth/authorize?${q}#${frag}`)
}

// Ends the app's open request with access_denied at the app's redirect, as the provider does when
// someone refuses on its own consent page (RFC 6749 4.1.2.1, with iss per RFC 9207). Without the
// app's request to answer, the person gets a page saying so instead.
async function refuseToApp(res, s, description) {
  const p = s ? pending.get(s) : undefined
  if (s) pending.delete(s)
  const data = p ? await store.readRequest(reqId(p.requestUri)) : null
  const q = data?.parameters
  if (!q?.redirect_uri) {
    return res.status(400).type('html').send('<!doctype html><title>Sign-in cancelled</title><p>Sign-in cancelled. Go back to the app to start again.</p>')
  }
  await store.deleteRequest(reqId(p.requestUri))
  log('person refused at their own PDS', { clientId: p.clientId, mode: p.mode })
  const answer = new URLSearchParams({ error: 'access_denied', error_description: description ?? 'The sign-in was cancelled', iss: provider.issuer ?? PUBLIC_URL })
  if (q.state) answer.set('state', q.state)
  const to = new URL(q.redirect_uri)
  if (q.response_mode === 'fragment') to.hash = answer.toString()
  else for (const [k, v] of answer) to.searchParams.set(k, v)
  res.redirect(to.toString())
}

// Served AT /oauth/authorize so the provider's API accepts the calls (it requires the authorize
// page as referrer, same-origin fetch and the CSRF cookie/header pair). The ticket sign-in is
// not remembered (remember: false): the provider returns a token good only for this request on
// this device, the device keeps no group session, and the host's own consent uses that token.
function ticketPage(requestUri) {
  const c = consent.get(requestUri)
  if (!c) return '<!doctype html><title>Unknown sign-in</title><p>Unknown sign-in.</p>'
  const li = (xs) => xs.map((s) => `<li><code>${esc(s)}</code></li>`).join('')
  return `<!doctype html><title>Act for ${esc(c.groupHandle)}</title>
<main id=consent hidden>
<h1>Act for the group @${esc(c.groupHandle)}</h1>
<p>You are signed in as <code>${esc(c.personDid)}</code>, holding the role${c.roles.length > 1 ? 's' : ''} ${c.roles.map(esc).join(', ')} in this group${c.created ? ', which you just created' : ''}.</p>
<p>The app <code>${esc(c.clientId)}</code> will act for the group, not for you, with:</p><ul id=kept>${li(c.kept)}</ul>
${c.dropped.length ? `<p>Not offered, because your roles do not grant it:</p><ul id=dropped>${li(c.dropped)}</ul>` : ''}
<button id=go>Authorize</button>
</main><p id=s>Signing you in as the group...</p>
<script>
(async () => {
  const get = (n) => (document.cookie.split('; ').find((c) => c.startsWith(n + '=')) || '').slice(n.length + 1)
  let csrf = get('csrf-token')
  if (!csrf) { csrf = crypto.randomUUID().replace(/-/g, '').slice(0, 24); document.cookie = 'csrf-token=' + csrf + '; path=/; secure; samesite=lax' }
  const h = new URLSearchParams(location.hash.slice(1)), ticket = h.get('t'), group = h.get('g')
  history.replaceState(null, '', location.pathname + location.search)
  const api = (p, body, bearer) => fetch('/@atproto/oauth-provider/~api/' + p, {
    method: 'POST', mode: 'same-origin', credentials: 'same-origin',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf, ...(bearer ? { authorization: 'Bearer ' + bearer } : {}) },
    body: JSON.stringify(body),
  })
  const r = await api('sign-in', { locale: 'en', username: group, password: 'ticket:' + ticket, remember: false })
  if (!r.ok) { document.getElementById('s').textContent = 'sign-in ' + r.status; return }
  const { ephemeralToken } = await r.json()
  document.getElementById('s').hidden = true
  document.getElementById('consent').hidden = false
  document.getElementById('go').onclick = async () => {
    const c = await api('consent', { did: group }, ephemeralToken)
    const j = await c.json().catch(() => ({}))
    if (j.url) location.replace(j.url)
    else document.body.textContent = 'consent ' + c.status + ' ' + JSON.stringify(j)
  }
})()
</script>`
}

// ---- (f) enforcement from the group's records ----

// Who is calling, from the Authorization header. The token is only decoded here, not verified:
// the PDS verifies the same header right after, so a forged token is refused there. Decoding
// is enough to find the token's person in the host's table.
function callerOf(req) {
  if (internalCalls.has(req)) return { internal: true }
  const m = /^(DPoP|Bearer) (\S+)$/.exec(req.headers.authorization || '')
  if (!m) return { none: true }
  let payload
  try {
    payload = JSON.parse(Buffer.from(m[2].split('.')[1], 'base64url').toString())
  } catch {
    return { none: true }
  }
  if (payload.jti && payload.client_id) {
    const e = tokenPerson.get(payload.jti)
    return { oauth: true, sub: payload.sub, mapped: !!e, personDid: e?.personDid ?? null }
  }
  return { legacy: true, sub: payload.sub } // a password session: the group acting as itself
}

const isHosted = async (did) => !!(did && (await pds.ctx.accountManager.getAccount(did)))
// A refusal names only what the standard names: XRPC's InvalidRequest (a write the record rules
// refuse) and Forbidden (a write the caller's roles or session do not allow), or a name a
// group.opensocial lexicon defines. Why it was refused is in the message.
const refuse = (status, error, message) => ({ status, error, message })
const invalid = (message) => refuse(400, 'InvalidRequest', message)
const forbidden = (message) => refuse(403, 'Forbidden', message)
const refusalBody = ({ error, message }) => ({ error, message })
const parseSpace = (uri) => {
  const [, , authority, , type, skey] = String(uri ?? '').split('/') // at://<did>/space/<type>/<skey>
  return { authority, type, skey }
}

// Whether a person may read a group space (and so be tracked as a writer in it): the space's
// `access` record is public, or one of their roles is granted `read` there. Only `access` grants
// count here; `permissions` grants are about the group session's own scopes (proposal.md:52-53).
async function decideAccess(spaceUri, user, kind) {
  const { authority } = parseSpace(spaceUri)
  if (user === authority) return { authorized: true, why: 'the group itself' }
  const g = await readGroup(authority)
  const acc = g.access.find((a) => a.space.uri === spaceUri)
  if (!acc) return { authorized: false, why: 'no access record' }
  if (kind === 'read' && acc.value.public === true) return { authorized: true, why: 'public' }
  const grants = await grantsFor(authority, user)
  const s = acc.space
  const reads = (grants.bySpace.get(spaceUri) ?? []).some((p) => p.matches({ type: s.type, authority, skey: s.skey, action: 'read' }))
  return { authorized: reads, why: reads ? `roles ${grants.roles.join(',')} grant read` : grants.roles.length ? `roles ${grants.roles.join(',')} do not grant read` : 'no roles' }
}

const COLLECTION = { membership: `${NS}.membership`, role: `${NS}.role`, access: `${NS}.access`, permissions: `${NS}.permissions` }
const MEMBERS_ONLY = new Set([COLLECTION.membership, COLLECTION.role, COLLECTION.permissions])

// Every scope in a grant has to be an atproto OAuth scope and expand, the way the PDS would
// expand it in a token. A bare space type (no collection) expands only if its lexicon resolves.
async function badScopes(scopes, groupDid) {
  const bad = []
  for (const sc of scopes ?? []) {
    if (!isAtprotoOauthScope(sc)) {
      bad.push(sc)
      continue
    }
    try {
      await provider.lexiconManager.buildTokenScope(sc, groupDid)
    } catch {
      bad.push(sc)
    }
  }
  return bad
}

// No granting more than you hold (proposal.md at 2b41a9b, the paragraph after the session
// rules): in an `access` or `permissions` write a person changes only the entries of roles they
// may assign, adds only scopes their own roles cover once permission sets are expanded, and adds
// to an `assignable` list only roles they may assign. `before` and `after` are the record's grants
// (null for none); `space` is the access record's space, or null for `permissions`.
const sortedSet = (a) => [...new Set(a ?? [])].sort()
const sameEntry = (a, b) =>
  !a === !b && (!a || JSON.stringify([sortedSet(a.scopes), sortedSet(a.assignable)]) === JSON.stringify([sortedSet(b.scopes), sortedSet(b.assignable)]))
async function beyondOwn(groupDid, mine, before, after, space) {
  const entry = (grants, role) => (grants ?? []).find((g) => g.role === role)
  const mayAssign = new Set(mine.assignable)
  for (const role of new Set([...(before ?? []), ...(after ?? [])].map((g) => g.role))) {
    const was = entry(before, role)
    const now = entry(after, role)
    if (sameEntry(was, now)) continue
    if (!mayAssign.has(role)) return `your roles cannot change the grants of ${role}`
    for (const sc of now?.scopes ?? []) {
      if (was?.scopes?.includes(sc)) continue
      const parts = (await provider.lexiconManager.buildTokenScope(sc, groupDid)).split(' ')
      const pinned = space ? parts.map((p) => pinToSpace(p, space, groupDid)).filter(Boolean) : parts
      if (!pinned.every((p) => covered(p, mine))) return `your roles do not hold ${sc}`
    }
    const added = (now?.assignable ?? []).filter((r) => !was?.assignable?.includes(r) && !mayAssign.has(r))
    if (added.length) return `your roles cannot assign ${[...new Set(added)].join(', ')}`
  }
  return null
}

// The checks a group write must pass before the PDS takes it (proposal.md:46, :67; the record
// lexicons). `ops` is one write, or every write of an applyWrites, checked in order against the
// state the earlier ones leave. Returns a refusal, or null.
async function checkGroupWrites(groupDid, space, ops, caller) {
  if (caller.oauth && !caller.mapped) return forbidden('this session was not issued through the group host')
  const { authority, type } = parseSpace(space)
  if (authority !== groupDid) return invalid(`${space} is not a space of ${groupDid}`)
  const g = await readGroup(groupDid)
  if (!g.access.some((a) => a.space.uri === space)) return invalid(`${space} has no access record, so the group does not write in it`)
  const roles = new Set(g.roles.map((r) => r.rkey))
  const memberships = new Map(g.memberships.map((r) => [r.rkey, r.value]))
  // The group DID itself holds every permission (proposal.md:44); a person holds their roles'.
  const mine = caller.personDid ? await grantsFor(groupDid, caller.personDid) : null
  const assignable = mine && new Set(mine.assignable)
  const grantsNow = new Map([
    [COLLECTION.access, g.access.find((a) => a.space.uri === space)?.value?.grants ?? null],
    [COLLECTION.permissions, type === MEMBERS ? (g.permissions?.grants ?? null) : null],
  ])
  for (const op of ops) {
    if (MEMBERS_ONLY.has(op.collection) && type !== MEMBERS) return invalid(`${op.collection} belongs in the members space`)
    if (op.collection === COLLECTION.role) {
      if (op.action === 'delete') {
        const users = [...memberships.values()].filter((v) => v.roles?.includes(op.rkey))
        if (users.length) return invalid(`role ${op.rkey} is held by ${users.length} member(s)`)
        roles.delete(op.rkey)
      } else roles.add(op.rkey)
    }
    if (op.collection === COLLECTION.membership) {
      const old = memberships.get(op.rkey)
      const oldRoles = old?.roles ?? []
      let added = []
      let removed = []
      if (op.action === 'delete') {
        removed = oldRoles // ejecting: every current role of the member
        memberships.delete(op.rkey)
      } else {
        const v = op.value ?? {}
        if (v.member !== op.rkey) return invalid('a membership record key is the member DID')
        if (!Array.isArray(v.roles) || new Set(v.roles).size !== v.roles.length) return invalid('roles must be a list of distinct role ids')
        const unknown = v.roles.filter((r) => !roles.has(r))
        if (unknown.length) return refuse(400, 'UnknownRole', `the group declares no role ${unknown.join(', ')}`)
        added = v.roles.filter((r) => !oldRoles.includes(r))
        removed = oldRoles.filter((r) => !v.roles.includes(r))
        memberships.set(op.rkey, v)
      }
      if (assignable) {
        const not = [...added, ...removed].filter((r) => !assignable.has(r))
        if (not.length) return forbidden(`your roles cannot assign or remove ${[...new Set(not)].join(', ')}`)
      }
    }
    if ((op.collection === COLLECTION.access || op.collection === COLLECTION.permissions) && op.action !== 'delete') {
      const grants = op.value?.grants ?? []
      const named = grants.map((gr) => gr.role)
      if (new Set(named).size !== named.length) return invalid('at most one grant per role')
      const unknown = [...named, ...grants.flatMap((gr) => gr.assignable ?? [])].filter((r) => !roles.has(r))
      if (unknown.length) return refuse(400, 'UnknownRole', `the group declares no role ${[...new Set(unknown)].join(', ')}`)
      const bad = await badScopes(grants.flatMap((gr) => gr.scopes ?? []), groupDid)
      if (bad.length) return refuse(400, 'InvalidScope', `not OAuth scopes, or do not resolve: ${bad.join(' ')}`)
    }
    if ((op.collection === COLLECTION.access || op.collection === COLLECTION.permissions) && op.rkey === 'self') {
      const after = op.action === 'delete' ? null : (op.value?.grants ?? [])
      if (mine) {
        const over = await beyondOwn(groupDid, mine, grantsNow.get(op.collection), after, op.collection === COLLECTION.access ? parseSpace(space) : null)
        if (over) return forbidden(over)
      }
      grantsNow.set(op.collection, after)
    }
  }
  return null
}

// Group writes through com.atproto.space.*: checked here, ahead of the PDS. The JSON body is
// parsed once, whatever its content type, so the gate cannot be skipped by mislabeling it; the
// PDS's own body parser sees it is done and uses it, and still refuses a non-JSON content type.
const SPACE_WRITES = ['createRecord', 'putRecord', 'deleteRecord', 'applyWrites']

// The PDS's own refusals of a write on a group session (a session cut to its person's roles that
// lacks the scope, above all) go into `refusals` beside the gate's, so the state shows each one.
const GROUP_WRITES = new Set([
  ...['createRecord', 'putRecord', 'deleteRecord', 'applyWrites', 'uploadBlob'].map((n) => `/xrpc/com.atproto.repo.${n}`),
  ...SPACE_WRITES.map((n) => `/xrpc/com.atproto.space.${n}`),
])
outer.use((req, res, next) => {
  if (req.method !== 'POST' || !GROUP_WRITES.has(req.path)) return next()
  const caller = callerOf(req)
  if (!caller.oauth) return next()
  const end = res.end
  res.end = function (chunk, ...rest) {
    // A 401 asks the client to authenticate again (a DPoP nonce, an expired token), which it
    // retries; it is not a refusal of the write.
    if (res.statusCode >= 400 && res.statusCode < 500 && res.statusCode !== 401 && !res.locals.refusalRecorded) {
      let body = null
      try {
        body = JSON.parse(Buffer.isBuffer(chunk) ? chunk.toString() : String(chunk ?? ''))
      } catch {}
      const nsid = req.path.split('.').pop()
      const refusal = { error: body?.error ?? null, message: body?.message ?? null }
      refusals.push({ at: new Date().toISOString(), by: 'pds', nsid, status: res.statusCode, group: caller.sub, personDid: caller.personDid, ...refusal })
      log('group write refused by the PDS', { nsid, personDid: caller.personDid, status: res.statusCode, error: refusal.error })
    }
    return end.call(this, chunk, ...rest)
  }
  next()
})

outer.post(
  SPACE_WRITES.map((n) => `/xrpc/com.atproto.space.${n}`),
  express.json({ limit: '5mb', type: () => true }),
  async (req, res, next) => {
    try {
      const body = req.body ?? {}
      if (!(await isHosted(body.repo))) return next()
      const caller = callerOf(req)
      if (caller.internal) return next()
      if (caller.sub && caller.sub !== body.repo) return next() // the PDS refuses a write to another repo
      const nsid = req.path.split('.').pop()
      const ops =
        nsid === 'applyWrites'
          ? (body.writes ?? []).map((w) => ({ action: String(w.$type ?? '').split('#')[1], collection: w.collection, rkey: w.rkey, value: w.value }))
          : [{ action: { createRecord: 'create', putRecord: 'put', deleteRecord: 'delete' }[nsid], collection: body.collection, rkey: body.rkey, value: body.record }]
      const refusal = await checkGroupWrites(body.repo, body.space, ops, caller)
      if (refusal) {
        refusals.push({ at: new Date().toISOString(), nsid, group: body.repo, space: body.space, personDid: caller.personDid ?? null, ...refusal })
        log('group write refused', { nsid, personDid: caller.personDid ?? null, ...refusal })
        res.locals.refusalRecorded = true
        return res.status(refusal.status).json(refusalBody(refusal))
      }
      next()
    } catch (err) {
      next(err)
    }
  },
)

// The declaration comes down when the meta space stops being public: the lexicon has a group
// publish it only while meta is public (declaration.json). Going public leaves it to the group's
// app, since a public group may stay unlisted (proposal.md: groups that wish to be discoverable
// may publish one). It is done before the write's answer goes back, so an app that
// reads after its save sees the two in step.
const DECLARATION = `${NS}.declaration`
outer.post(SPACE_WRITES.map((n) => `/xrpc/com.atproto.space.${n}`), async (req, res, next) => {
  try {
    const body = req.body ?? {}
    const group = body.repo
    const writes = req.path.endsWith('.applyWrites') ? (body.writes ?? []) : [body]
    const touchesMetaAccess = body.space === spaceUri(group, META) && writes.some((w) => w.collection === `${NS}.access` && w.rkey === 'self')
    if (!touchesMetaAccess || !(await isHosted(group))) return next()
    const end = res.end
    res.end = function (...args) {
      if (res.statusCode < 200 || res.statusCode >= 300) return end.apply(this, args)
      followMetaAccess(group)
        .catch((err) => log('declaration not brought down', { group, err: err.message }))
        .finally(() => end.apply(this, args))
      return this
    }
    next()
  } catch (err) {
    next(err)
  }
})

async function followMetaAccess(group) {
  const access = await pds.ctx.actorStore.read(group, async (actor) =>
    (await actor.space.listRecords(spaceUri(group, META), { limit: 100, collection: `${NS}.access` })).find((r) => r.rkey === 'self'),
  )
  if (access?.value?.public === true) return
  const declaration = { repo: group, collection: DECLARATION, rkey: 'self' }
  const held = await fetch(`${LOOPBACK}/xrpc/com.atproto.repo.getRecord?${new URLSearchParams(declaration)}`)
  if (held.status === 400) return // none to bring down (RecordNotFound)
  if (!held.ok) throw new Error(`reading the declaration: ${held.status}`)
  await xrpc('com.atproto.repo.deleteRecord', declaration, await groupJwt(group))
  log('declaration brought down: the meta space is not public', { group })
}

// Nobody reconfigures, wipes or migrates a group space, the group's own sessions included: a
// space's policy follows its `access` record, and only the host changes it. Wiping
// (clearRecords), pruning writers (removeWriter) and account migration are refused for now, so a
// group cannot yet move to another host: a gap to close, not a decision.
const SPACE_CHANGES = [
  'com.atproto.space.createSpace',
  'com.atproto.space.updateSpace',
  'com.atproto.space.deleteSpace',
  'com.atproto.space.clearRecords',
  'com.atproto.space.removeWriter',
  'com.atproto.memberspace.putMember',
  'com.atproto.memberspace.removeMember',
]
// The imports carry an archive, not JSON, and act on the caller's own account.
const SPACE_IMPORTS = ['com.atproto.space.importSpaceMeta', 'com.atproto.space.importRepo']
const spaceGuard = (authorityOf) => async (req, res, next) => {
  try {
    const caller = callerOf(req)
    if (caller.internal) return next()
    const authority = authorityOf(req, caller)
    if (await isHosted(authority)) {
      const nsid = req.path.split('.').pop()
      const refusal = forbidden(`group spaces change only through the group host, not ${nsid}`)
      refusals.push({ at: new Date().toISOString(), nsid, group: authority, personDid: caller.personDid ?? null, ...refusal })
      log('space change refused', { nsid, authority })
      return res.status(refusal.status).json(refusalBody(refusal))
    }
    next()
  } catch (err) {
    next(err)
  }
}
outer.post(
  SPACE_CHANGES.map((n) => `/xrpc/${n}`),
  express.json({ limit: '1mb', type: () => true }),
  spaceGuard((req, caller) => (req.body?.space ? parseSpace(req.body.space).authority : caller.sub)),
)
outer.post(
  SPACE_IMPORTS.map((n) => `/xrpc/${n}`),
  spaceGuard((req, caller) => caller.sub),
)
outer.get(
  '/xrpc/com.atproto.space.exportSpaceMeta',
  spaceGuard((req, caller) => (req.query.space ? parseSpace(String(req.query.space)).authority : caller.sub)),
)

// The managing app's answer, now from the records.
outer.get('/xrpc/com.atproto.managedspace.checkUserAccess', async (req, res) => {
  const { space, user, access: kind, clientId } = req.query
  let iss = null
  try {
    const jwt = (req.headers.authorization || '').replace(/^Bearer /, '')
    const payload = await verifyJwt(jwt, MANAGING_APP, 'com.atproto.managedspace.checkUserAccess', (did, force) =>
      pds.ctx.idResolver.did.resolveAtprotoKey(did, force),
    )
    iss = payload.iss
  } catch (err) {
    accessCalls.push({ space, user, kind, iss: null, error: err.message })
    log('checkUserAccess: bad service auth', err.message)
    return res.status(401).json({ error: 'AuthRequired', message: err.message })
  }
  // The caller must be the space's own authority.
  let decision = { authorized: false, why: 'caller is not the space authority' }
  if (iss === parseSpace(space).authority) decision = await decideAccess(String(space), String(user), String(kind))
  accessCalls.push({ space, user, kind, clientId: clientId ?? null, iss, ...decision, at: new Date().toISOString() })
  log('checkUserAccess', { space, user, kind, ...decision })
  res.json({ authorized: decision.authorized })
})

// ---- (g) a person's own acts, with service auth from their own PDS ----

class Refusal extends Error {
  constructor(status, error, message) {
    super(message)
    Object.assign(this, { status, error })
  }
}
const sendError = (res, err) =>
  err instanceof Refusal ? res.status(err.status).json({ error: err.error, message: err.message })
  : err?.payload && err?.statusCode ? res.status(err.statusCode).json(err.payload) // an XRPC error, from verifyJwt
  : err?.name === 'ScopeMissingError' ? res.status(err.statusCode).json({ error: err.name, message: err.message })
  : null

// Joining, cancelling and leaving are the person's acts, not the group's, so they carry service
// auth from the person's own account (proposal.md:102). The audience is the group: an app calls
// its own PDS with `atproto-proxy: <group>#atproto_pds`, and that PDS mints the token with the
// group's bare DID as `aud` (pds pipethrough.js, "Phase 1 of service auth updates"; it says a
// later phase may send `<group>#atproto_pds`, so that is taken too). A token made for one group
// is then refused at every other, even on the same host.
async function memberAuth(req, nsid, groupDid) {
  const jwt = /^Bearer (\S+)$/.exec(req.headers.authorization || '')?.[1]
  if (!jwt) throw new Refusal(401, 'AuthRequired', `${nsid} takes service auth from your own account`)
  const payload = await verifyJwt(jwt, null, nsid, (did, force) => pds.ctx.idResolver.did.resolveAtprotoKey(did, force))
  if (payload.aud !== groupDid && payload.aud !== `${groupDid}#atproto_pds`) {
    throw new Refusal(401, 'BadJwtAudience', `service auth for ${nsid} names the group as its audience`)
  }
  if (payload.iss.includes('#')) throw new Refusal(401, 'BadJwtIss', 'service auth from a person, not a service')
  return { member: payload.iss, aud: payload.aud }
}

const graphemes = (s) => [...new Intl.Segmenter().segment(s)].length
const requestKey = (group, member) => `${group} ${member}`
const dropRequest = (group, member) => joinRequests.delete(requestKey(group, member)) && (persist(), true)

// What every member method shares: a JSON body naming the group, service auth from the caller's
// own account for that group and that method, and a group this host holds. The handler returns
// the output, or nothing for a method with no output.
function memberMethod(name, handler) {
  const nsid = `${NS}.${name}`
  outer.post(`/xrpc/${nsid}`, express.json({ limit: '64kb', type: () => true }), async (req, res, next) => {
    const call = { at: new Date().toISOString(), nsid: name, group: req.body?.group ?? null, member: null, aud: null }
    try {
      const { group } = req.body ?? {}
      if (typeof group !== 'string' || !group.startsWith('did:')) throw new Refusal(400, 'InvalidRequest', 'group must be a DID')
      Object.assign(call, await memberAuth(req, nsid, group))
      if (!(await isHosted(group))) throw new Refusal(400, 'GroupNotFound', `${group} is not hosted here`)
      const out = await handler({ group, member: call.member, body: req.body, call })
      if (out === undefined) res.status(200).end()
      else res.json(out)
    } catch (err) {
      call.result = err.error ?? err.customErrorName ?? err.message
      if (!sendError(res, err)) next(err)
    } finally {
      methodCalls.push(call)
      if (methodCalls.length > 50) methodCalls.shift()
    }
  })
}

// requestJoin (requestJoin.json): `open` admits at once with the group's default roles,
// `approval` queues a request, anything else is closed. Invitations are not built, so this host
// treats `invite` as closed and refuses an `invite` argument. A member asking again gets their
// membership back; a pending requester asking again gets the same request.
memberMethod('requestJoin', async ({ group, member, body: { invite, message }, call }) => {
  if (message !== undefined && (typeof message !== 'string' || message.length > 20000 || graphemes(message) > 2000)) {
    throw new Refusal(400, 'InvalidRequest', 'message is a string of at most 2000 graphemes')
  }
  const g = await readGroup(group)
  const existing = g.memberships.find((m) => m.rkey === member)
  if (existing) {
    // Approved by a membership write (proposal.md:222), or already in: no request left pending.
    dropRequest(group, member)
    call.result = 'already a member'
    return { status: 'admitted', membership: { uri: existing.uri, cid: existing.cid } }
  }
  if (invite !== undefined) throw new Refusal(400, 'InvalidInvite', 'this host issues no invitations')
  const policy = g.profile?.joinPolicy
  if (policy === 'open') {
    const roles = g.roles.filter((r) => r.value?.default === true).map((r) => r.rkey)
    const record = { $type: `${NS}.membership`, member, roles, createdAt: new Date().toISOString() }
    const ref = await xrpc('com.atproto.space.createRecord', { space: spaceUri(group, MEMBERS), repo: group, collection: `${NS}.membership`, rkey: member, record }, await groupJwt(group))
    dropRequest(group, member)
    call.result = `admitted as ${roles.join(',') || 'no role'}`
    log('requestJoin admitted', { group, member, roles })
    return { status: 'admitted', membership: { uri: ref.uri, cid: ref.cid } }
  }
  if (policy === 'approval') {
    const key = requestKey(group, member)
    if (!joinRequests.has(key)) {
      joinRequests.set(key, { group, member, createdAt: new Date().toISOString(), ...(message ? { message } : {}) })
      persist()
    }
    const { group: _, ...request } = joinRequests.get(key)
    call.result = 'pending'
    log('requestJoin queued', { group, member })
    return { status: 'pending', request }
  }
  throw new Refusal(400, 'JoinClosed', policy === 'invite' ? 'this group admits by invitation only' : 'this group sets no join policy')
})

// cancelJoinRequest (cancelJoinRequest.json): withdraws a pending request. Once the requester's
// membership is written the request is approved, not pending, so there is nothing to cancel.
memberMethod('cancelJoinRequest', async ({ group, member, call }) => {
  const g = await readGroup(group)
  const approved = g.memberships.some((m) => m.rkey === member)
  const had = dropRequest(group, member)
  if (approved || !had) throw new Refusal(400, 'JoinRequestNotFound', approved ? 'your request was approved: you are a member' : 'you have no pending join request')
  call.result = 'cancelled'
  log('cancelJoinRequest', { group, member })
})

// leaveGroup (leaveGroup.json): the host deletes the caller's membership as the group. It is the
// member's own act, so no `assignable` check, and it withdraws a pending request too. Leaving when
// not a member changes nothing and succeeds. The last admin may leave: the
// proposal does not say otherwise, though a group whose remaining roles cannot assign `admin` can
// then never get one back.
memberMethod('leaveGroup', async ({ group, member, call }) => {
  const withdrew = dropRequest(group, member)
  const g = await readGroup(group)
  const m = g.memberships.find((r) => r.rkey === member)
  if (!m) {
    call.result = withdrew ? 'not a member; request withdrawn' : 'not a member'
    return
  }
  await xrpc('com.atproto.space.deleteRecord', { space: spaceUri(group, MEMBERS), repo: group, collection: `${NS}.membership`, rkey: member }, await groupJwt(group))
  call.result = `left, held ${m.value?.roles?.join(',') || 'no role'}`
  log('leaveGroup', { group, member, roles: m.value?.roles })
})

// ---- (h) the group's own methods, with a group session ----

// Nothing behind these routes checks the token, so the host runs the PDS's own check. A password
// session is the group itself and holds every permission (proposal.md:44). An OAuth token needs a
// valid DPoP proof and, after the per-request cut to its person's current roles (loadTokenClaims
// above), the method's rpc: scope (proposal.md:222-223). That scope is checked against the host's
// own service, `#group_host` in its DID document; the proposal's grants say `aud=*`.
const groupAuth = pds.ctx.authVerifier.authorization({ authorize: (permissions, { params }) => permissions.assertRpc(params) })
// For a method whose check needs the input (createSpace), the handler asserts it, as the PDS's
// own space.createSpace does.
const groupSession = pds.ctx.authVerifier.authorization({ authorize: () => {} })

function groupMethod(name, verb, handler, auth = groupAuth) {
  const nsid = `${NS}.${name}`
  const body = verb === 'POST' ? [express.json({ limit: '64kb', type: () => true })] : []
  outer[verb.toLowerCase()](`/xrpc/${nsid}`, ...body, async (req, res, next) => {
    const call = { at: new Date().toISOString(), nsid: name, group: null, person: null }
    try {
      const { credentials } = await auth({ req, res, params: { lxm: nsid, aud: MANAGING_APP } })
      const caller = callerOf(req)
      Object.assign(call, { group: credentials.did, person: caller.personDid ?? (caller.legacy ? 'the group itself' : null) })
      const out = await handler({ group: credentials.did, credentials, caller, input: verb === 'GET' ? req.query : (req.body ?? {}), call })
      if (out === undefined) res.status(200).end()
      else res.json(out)
    } catch (err) {
      call.result = err.error ?? err.customErrorName ?? err.name ?? err.message
      if (!sendError(res, err)) next(err)
    } finally {
      methodCalls.push(call)
      if (methodCalls.length > 50) methodCalls.shift()
    }
  })
}

// A request whose member now holds a membership was approved by that write (proposal.md:222):
// it is no longer pending, so it is dropped before the group sees the list.
async function pendingFor(group) {
  const g = await readGroup(group)
  const members = new Set(g.memberships.map((m) => m.rkey))
  let changed = false
  for (const [key, r] of joinRequests) {
    if (r.group === group && members.has(r.member)) changed = joinRequests.delete(key)
  }
  if (changed) persist()
  return { g, pending: [...joinRequests.values()].filter((r) => r.group === group) }
}

// listJoinRequests (listJoinRequests.json): oldest first; the cursor is the last item's
// createdAt and member.
const position = (r) => `${r.createdAt}|${r.member}`
groupMethod('listJoinRequests', 'GET', async ({ group, input, call }) => {
  const limit = Math.min(Math.max(Number.parseInt(input.limit ?? '50', 10) || 50, 1), 100)
  const after = typeof input.cursor === 'string' ? input.cursor : ''
  const { pending } = await pendingFor(group)
  const page = pending.sort((a, b) => position(a).localeCompare(position(b))).filter((r) => position(r) > after).slice(0, limit)
  call.result = `${page.length} of ${pending.length}`
  return {
    requests: page.map(({ group: _, ...r }) => r),
    ...(page.length === limit ? { cursor: position(page.at(-1)) } : {}),
  }
})

// denyJoinRequest (denyJoinRequest.json): the group comes from the session, the member from the
// input. A denial is not remembered and the person may ask again at once: the lexicons define no
// hold and no error for one, and the host does not depart from them.
groupMethod('denyJoinRequest', 'POST', async ({ group, input: { member }, call }) => {
  if (typeof member !== 'string' || !member.startsWith('did:')) throw new Refusal(400, 'InvalidRequest', 'member must be a DID')
  await pendingFor(group)
  if (!dropRequest(group, member)) throw new Refusal(400, 'JoinRequestNotFound', `${member} has no pending join request`)
  call.result = `denied ${member}`
  log('denyJoinRequest', { group, member })
})

// createSpace (createSpace.json): manage=create for the space, checked the way the PDS's own
// space.createSpace checks it (proposal.md:214-221). The host makes the space under the
// managedspace policy, so the PDS asks the host who may use it, then writes its `access` record
// and, unless `index` is false, an index entry in members. The host's own writes skip the write
// gate, so the grants are checked here first and a refused request leaves nothing behind. Errors
// are the lexicon's four; input the lexicon does not allow is InvalidRequest.
const isScopes = (a) => Array.isArray(a) && a.length <= 100 && a.every((s) => typeof s === 'string' && s.length >= 1 && s.length <= 2000)
const isGrant = (g) => typeof g?.role === 'string' && g.role.length <= 512 && isValidRecordKey(g.role) && isScopes(g.scopes)
groupMethod(
  'createSpace',
  'POST',
  async ({ group, credentials, caller, input: { type, skey = TID.nextStr(), access, index = true }, call }) => {
    if (typeof type !== 'string' || !isValidNsid(type)) throw new Refusal(400, 'InvalidRequest', 'type must be an NSID')
    if (typeof skey !== 'string' || !isValidRecordKey(skey)) throw new Refusal(400, 'InvalidRequest', 'skey must be a record key')
    if (typeof index !== 'boolean') throw new Refusal(400, 'InvalidRequest', 'index must be a boolean')
    const grants = access?.grants
    if (!Array.isArray(grants) || grants.length > 100 || !grants.every(isGrant) || !['undefined', 'boolean'].includes(typeof access.public)) {
      throw new Refusal(400, 'InvalidRequest', 'access must be an accessConfig: optional public, and grants of a role and its scopes')
    }
    // group.opensocial.access allows at most one grant per role.
    if (new Set(grants.map((g) => g.role)).size !== grants.length) throw new Refusal(400, 'InvalidRequest', 'at most one grant per role')
    const ref = new SpaceRef(group, type, skey)
    credentials.permissions?.assertSpaceRef(ref, { manage: 'create' }) // a password session is the group itself
    if (type === META || type === MEMBERS) throw new Refusal(400, 'ReservedSpace', `the ${type} space is made with the group`)
    const g = await readGroup(group)
    const declared = new Set(g.roles.map((r) => r.rkey))
    const unknown = grants.map((gr) => gr.role).filter((r) => !declared.has(r))
    if (unknown.length) throw new Refusal(400, 'UnknownRole', `the group declares no role ${unknown.join(', ')}`)
    const bad = await badScopes(grants.flatMap((gr) => gr.scopes), group)
    if (bad.length) throw new Refusal(400, 'InvalidScope', `not OAuth scopes, or do not resolve: ${bad.join(' ')}`)
    if (caller.personDid) {
      const over = await beyondOwn(group, await grantsFor(group, caller.personDid), null, grants, { uri: ref.toString(), type, skey })
      if (over) throw new Refusal(403, 'Forbidden', over)
    }
    const space = ref.toString()
    // The PDS's own check for an existing space (a deleted one included): SpaceAlreadyExists.
    await pds.ctx.spacePolicyManager.createSpace(space, MA)
    const jwt = await groupJwt(group)
    const record = { $type: `${NS}.access`, ...(access.public === undefined ? {} : { public: access.public }), grants: grants.map(({ role, scopes }) => ({ role, scopes })) }
    const accessRef = await xrpc('com.atproto.space.createRecord', { space, repo: group, collection: `${NS}.access`, rkey: 'self', record }, jwt)
    const indexRef = index
      ? await xrpc(
          'com.atproto.space.createRecord',
          { space: spaceUri(group, MEMBERS), repo: group, collection: `${NS}.space`, rkey: TID.nextStr(), record: { $type: `${NS}.space`, space, createdAt: new Date().toISOString() } },
          jwt,
        )
      : null
    call.result = `created ${type}/${skey}${indexRef ? ', indexed' : ''}`
    log('createSpace', { group, space, indexed: !!indexRef })
    return { space, access: { uri: accessRef.uri, cid: accessRef.cid }, ...(indexRef ? { index: { uri: indexRef.uri, cid: indexRef.cid } } : {}) }
  },
  groupSession,
)

// ---- test routes, for the probes ----
// They show the host's state and set up test cases, and two of them write as the group. Each takes
// the PDS's admin login, as its own admin routes do: Basic auth, user `admin`, the admin password.
const adminLogin = Buffer.from(`admin:${secrets.adminPassword}`)
const adminOnly = (req, res, next) => {
  const [kind, value] = (req.headers.authorization ?? '').split(' ')
  const given = kind === 'Basic' && value ? Buffer.from(value, 'base64') : Buffer.alloc(0)
  if (given.length === adminLogin.length && crypto.timingSafeEqual(given, adminLogin)) return next()
  res.status(401).json({ error: 'AuthRequired', message: 'the test routes take the admin login' })
}
outer.use('/test', adminOnly, express.json())
outer.get('/test/state', async (req, res) => {
  const group = req.query.group
  const deviceAccounts = group ? (await store.listDeviceAccounts({ did: group })).length : null
  const grants = group && req.query.person ? await grantsFor(group, req.query.person) : null
  res.json({
    authorizedBy,
    accessCalls: accessCalls.filter((c) => !group || String(c.space).includes(group)),
    narrowings,
    refusals: refusals.filter((r) => !group || r.group === group),
    managingApp: MANAGING_APP,
    tokens: [...tokenPerson.entries()].filter(([, v]) => !group || v.groupDid === group).map(([id, v]) => ({ id: id.slice(0, 8), ...v })),
    deviceAccounts,
    grants: grants && { roles: grants.roles, assignable: grants.assignable, scopes: [...grants.strings] },
    joinRequests: [...joinRequests.values()].filter((r) => !group || r.group === group),
    methodCalls: methodCalls.filter((c) => !group || c.group === group),
    spaces: group && (await isHosted(group)) ? (await readGroup(group)).spaces : null,
    creates: [...creates.values()],
  })
})
// A space of the group with no access record, for testing the undeclared-space refusal.
outer.post('/test/bare-space', async (req, res, next) => {
  try {
    const { group, skey } = req.body
    await xrpc('com.atproto.space.createSpace', { spaceType: META, skey, policy: MA }, await groupJwt(group))
    res.json({ space: spaceUri(group, META, skey) })
  } catch (err) {
    next(err)
  }
})

// Records written as the group itself, which holds every permission (proposal.md:44). A probe's
// setup for a role made after the group needs it: that role is in nobody's `assignable` list, so
// no person may grant it anything.
outer.post('/test/as-group', async (req, res, next) => {
  try {
    const { group, space, writes } = req.body
    res.json(await xrpc('com.atproto.space.applyWrites', { space, repo: group, writes }, await groupJwt(group)))
  } catch (err) {
    next(err)
  }
})

// A create cut short once its account exists. `fail` throws there, so the create's own clean-up
// runs; `hang` never goes on, so the create is cut by restarting the host, as a crash would cut it.
outer.post('/test/interrupted-create', async (req, res, next) => {
  try {
    const { label, creatorDid, how } = req.body
    if (how === 'fail') {
      let did = null
      const cut = (d) => {
        did = d
        throw new Error('cut short after the account, by a probe')
      }
      const error = await createGroup({ label, creatorDid, afterAccount: cut }).then(() => null, (err) => err.message)
      return res.json({ did, error })
    }
    let reached
    const did = new Promise((resolve) => (reached = resolve))
    const run = createGroup({ label, creatorDid, afterAccount: (d) => (reached(d), new Promise(() => {})) })
    res.json({ did: await Promise.race([did, run]) })
  } catch (err) {
    next(err)
  }
})

// ---- everything else: the PDS, unmodified ----
outer.use(pds.app)

// An error none of the host's routes answered: said in a line, never as a stack trace (the log
// has the stack). The PDS answers its own errors.
outer.use((err, req, res, next) => {
  if (res.headersSent) return next(err)
  log('unanswered error', req.method, req.path, err?.stack ?? err)
  if (req.path.startsWith('/xrpc/')) return res.status(500).json({ error: 'InternalServerError', message: err?.message ?? 'Internal Server Error' })
  res.status(500).type('html').send(`<!doctype html><title>Something went wrong</title><p>Something went wrong: ${esc(err?.message ?? err)}</p>`)
})
// pds.start() listens with pds.app.listen, which @atproto/xrpc-server wraps to attach the
// websocket upgrade for subscriptions (com.atproto.sync.subscribeRepos, the relay's feed). So the
// PDS's own app does the listening, and the server it makes hands every request to outer, in the
// same tick and before any request can arrive. Listening with outer instead drops the upgrade
// handler: a relay's subscribeRepos then falls through as a plain GET and gets AuthMissing.
// probe-subscribe-repos.mjs checks this end to end; rerun it on every PDS image update.
const listenWithUpgrades = pds.app.listen
pds.app.listen = (...args) => {
  const server = listenWithUpgrades(...args)
  server.removeAllListeners('request')
  server.on('request', outer)
  return server
}
await pds.start()
await settleInterruptedCreates()
log('listening', cfg.service.port, 'as', PUBLIC_URL)
