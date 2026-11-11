# How the group host works

This is the design of the host in `src/host.mjs`: what it does, how it is built on the spaces alpha
PDS, the choices it makes where the proposals say nothing, and where it runs into their limits.

Two proposals define what it implements:

- [opensocial.group](https://tangled.org/opensocial.group/proposal) (`proposal.md` and the
  `group.opensocial.*` lexicons). It defines groups, their records, roles and methods. The host
  follows its `main` branch, tested at `2b41a9b`.
- [Permissioned data](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data)
  (proposal 0016). It defines spaces, space credentials and how a space host decides access. The
  `permissioned-data-alpha` branch of `bluesky-social/atproto` implements it, and the host runs that
  build.

Where the host has to choose something the proposals leave open, it says so below. Where they are
clear, it does what they say, and it does not add refusals, error names or policies of its own.

## The parts

A group is an account with its own DID. The host is that account's PDS. It holds the group's
public repo and its space repos, and it signs their commits. Members' own records stay on their own
PDSes.

The host is one Node process:

- `@atproto/pds` from the alpha image, made with `PDS.create(cfg, secrets)` and no overrides. It
  reads the usual `PDS_*` settings.
- An outer express app in front of it. The host's own routes answer first: the sign-in pages, the
  group methods, the write gate and `checkUserAccess`. Everything else falls through to the
  unmodified PDS.
- A few wrappers on the PDS's OAuth provider, installed at runtime. No upstream file is patched.
  The wrappers reach `protected` fields, so each one has to be checked again when the alpha moves:
  the provider's hooks (`onAuthorized`), its store's `authenticateAccount`, `createToken` and
  `rotateToken`, and `tokenManager.loadTokenClaims`.

The PDS's own app does the listening, and hands each request to the outer app. That keeps the
websocket upgrade for `com.atproto.sync.subscribeRepos`, so a relay can follow the groups' repos.

What the host keeps of its own (which person stands behind each token, pending join requests,
creates in progress) is in memory and in one JSON file under `/data`. A real deployment would keep
it in tables.

## Creating a group

An app starts an ordinary OAuth flow at the host with `prompt=create`. The host shows its own page
in place of the PDS's sign-up form. It asks for two things: the group's address (its handle label)
and the creator's own handle. It turns down an address the PDS would refuse (too long, reserved,
caught by the PDS's word filter, or taken) on that page, so the creator can pick another without
starting over in the app.

The creator then signs in at their own PDS. The host is an OAuth client there, asking only for
`atproto`, to learn who they are. Then it:

1. Makes a keypair for the group's recovery, and creates the account with the public half first
   among the DID's rotation keys, ahead of the host's own key. It reads the DID back from the PLC
   and refuses the create if that key is not first.
2. Creates the `meta` and `members` spaces under a policy that sends access decisions to the host.
3. Writes the starting records: an `access` record in each space, a `profile` named after the
   address with `joinPolicy: approval`, the `admin` and `member` roles (`member` is the default),
   a `permissions` record, and the creator's `admin` membership.
4. Shows the recovery key's private half once, on its own page, before consent. It is not stored
   anywhere: not in the state file, the log or the PDS. With it the creator can move the group off
   this host without the host's help. The proposal is silent on recovery, so this is the host's
   choice.
5. Rewrites the pending OAuth request so that consent and the token are for the new group. The app
   gets a session for the group.

`createAccount` requires a password, so the account gets a random one that is thrown away. A host
that is not built on the stock PDS could create the account with none.

The `admin` role's group session grants are the proposal's four permission sets, as the proposal's
example record grants them, plus read and write in every group space (spaces made later included),
labels in any group space, `repo:*` and `blob:*/*` (so an admin's group session can write the
group's public repo and upload images), and the `rpc:` scopes for `listJoinRequests` and
`denyJoinRequest`. `member` holds no scopes for a group session.

## Acting for a group

Nobody holds the group's password. A person who wants to act for a group signs in through their own
PDS:

1. The app starts an OAuth flow for the group's DID at the host.
2. The host sends the browser to the person's own PDS, where they sign in (again `atproto` only).
3. The host checks that the person holds a role in the group, and mints a one-time ticket.
4. A page the host serves at `/oauth/authorize` submits the ticket to the PDS's own sign-in step,
   which the host's wrapper on `authenticateAccount` accepts in place of a password.
5. The host's own consent page names the group, the person, their roles, the scopes kept and the
   scopes not offered.

The ticket sign-in uses `remember: false`. The provider then returns a token good only for this
one request, so no browser stays signed in as the group, and a later request cannot skip the role
check.

The host offers a person only the requested scopes their roles grant. A scope is kept whole or
dropped. An app that wants a read to survive for members who cannot write asks for the read as a
scope of its own.

The host records which person authorized each token. It maps the authorization code to the person,
then the token to the code's person, and carries it through refresh. The table is kept on disk, so
it survives a restart. A token with no person is cut to `atproto`.

On every request, the PDS loads the token's scope from its store, and the host cuts it there to what
the person's roles grant now. Removing a member, or taking a role away, closes their open session on
its next request.

Two records grant a role things, and they are easy to mix up:

- A space's `access` record decides what a person may read and write in that space with their own
  space credential.
- The `permissions` record in `members` decides what a group session may carry for each role. The
  per-request cut uses this one.

## Enforcement

Every group space is created under the `com.atproto.managedspace` policy with the host as its
managing app. The PDS then asks the host's `checkUserAccess` on every read and write.

- **Reads.** The host issues a space credential to a person whose current roles grant read in that
  space's `access` record, or to anyone when the record is `public`.
- **Members' writes.** A member writes to their own PDS, so the host cannot refuse the write. It
  decides only whether that writer is tracked in the space and their writes forwarded. A person
  without read on the space is not tracked.
- **Group writes.** Writes through `com.atproto.space.*` with a group session pass the host's gate
  before the PDS takes them:
  - A `membership` write needs every role added or removed, and every role of a member being
    ejected, in the writer's `assignable` roles. A moderator who may write memberships can admit a
    member, but not promote to admin or eject an admin.
  - An `access` or `permissions` write grants no more than the writer holds. The writer changes
    only the entries of roles they may assign, adds only scopes their own roles cover (with
    permission sets expanded), and makes assignable only roles they may assign themselves. A role
    made after the group is in nobody's `assignable` list, so no person can grant it anything; only
    the group itself can.
  - Record rules: a membership is keyed by the member's DID and names declared roles; an `access`
    or `permissions` record has one grant per role, names declared roles, and has scopes that
    resolve; a role still held cannot be deleted.
  - The group writes only in spaces that have an `access` record.
- **Group spaces are not reconfigured.** `createSpace`, `updateSpace`, `deleteSpace`,
  `clearRecords` and `removeWriter` in `com.atproto.space`, the migration calls (`exportSpaceMeta`,
  `importSpaceMeta`, `importRepo`), and `putMember` and `removeMember` in
  `com.atproto.memberspace`, are refused for group spaces, an admin's session included. Only the
  host's own code changes a group space's policy. New spaces come through the group method
  `createSpace`.

Refusals use `InvalidRequest` for a badly formed write and `Forbidden` for one the caller's roles
or session do not allow, with the reason in the message, plus the error names the lexicons define.

When a group's `meta` space goes from public to private, the host takes down the group's public
`declaration` itself, before the write's answer goes back, so an app that reads after its save sees
the two in step. Going public leaves the declaration to the group's app, since a public group may
stay unlisted.

## Group methods

A person's own acts on a group, `requestJoin`, `cancelJoinRequest` and `leaveGroup`, come with
service auth from their own PDS. When that PDS proxies with `atproto-proxy: <group>#atproto_pds`, it
names the group's DID as the token's audience, so the host takes that audience. The lexicons do not
say which audience to use.

- `requestJoin` admits at once with the default roles when the group's `joinPolicy` is `open`,
  keeps one pending request per person when it is `approval`, and answers `JoinClosed` when it is
  `invite`. The host issues no invites, so an invitation is `InvalidInvite`.
- Writing a requester's `membership` approves their request.
- `leaveGroup` deletes the caller's membership as the group, with no `assignable` check, since it is
  the member's own act.

The group's own acts take a group session. `listJoinRequests` and `denyJoinRequest` need the
method's `rpc:` scope. `createSpace` needs `manage=create` for the space's type; it checks every
grant before writing anything, makes the space under the managing-app policy, and writes its
`access` record and, unless `index` is false, a `space` entry in `members`. The per-request cut
applies to these too, so an admin set back to member is refused on the same session.

Pending join requests are the host's own state, not records, as the proposal says.

## Choices where the proposals are silent

- **The last admin may leave.** A group whose remaining roles cannot assign `admin` then never gets
  one back.
- **`leaveGroup` for a non-member** succeeds and does nothing.
- **No hold after a denial.** A denied person may ask again at once. `requestJoin` names no error
  for a recent denial, so the host does not make one up.
- **The creator gets a recovery key** (above).
- **Hints on the sign-up link.** An app may add `gh_name` (the group's name as the person typed it)
  and `gh_person` (the person's DID) to the authorization URL. The host suggests an address from the
  name and fills in the handle it resolves for the DID. Both stay editable, and a hint is never
  trusted: the creator is whoever signs in at their own PDS.
- **Who may create a group:** anyone who can sign in.

## Where the proposals meet their limits

- **Member writes cannot be refused.** opensocial.group says the host refuses writes. Under 0016 a
  member writes into their own space repo, and the space host only chooses whether to track it.
  Keeping an unwanted member record out of what readers see is the reading app's or indexer's job.
- **opensocial.group says groups do not layer on simple spaces; this host does, inside.** Group
  spaces run on the alpha's managed-space policy. The host refuses every call that would let
  someone change a group space's policy behind its `access` record.
- **"Narrowed on every request" meets multi-use credentials.** A space credential is checked when
  it is issued and then works for its lifetime (minutes). Removing a member stops new credentials at
  once, but one issued earlier keeps working until it expires. Telling other space hosts that a
  credential is revoked is not built yet.
- **Read means write.** Anyone who can read a space may write their own records in it, so a group
  cannot have members who read a space but may not post there. What a member's record means is the
  app's rule.
- **A scope that only manages spaces also reads them all.** `space:*?manage=create&manage=delete`
  gets the default actions, `read` included, so its holder can read every space of the group.
  Adding `action=read_self` grants only the manage operations.
- **A space type's declaration enforces almost nothing.** Its `collections` are used only to fill in
  a bare `space:<type>` grant, at issue and on the consent page. No write is refused for being
  outside them. A grant that names a bare space type needs that type's lexicon published, or it
  does not resolve.

## Not built yet

- Invites, and the moderation methods (`listSubjects`, `getSubjectHistory`, `resolveSubject`,
  `createReport`, labels).
- `deleteSpace`.
- Moving a group to another host. The host refuses the migration calls for group spaces today. That
  is a gap to close, not a decision.
- Revoking a removed member's outstanding credentials at other space hosts.
- Caching. The host reads the group's records on every request.
- A consent page that shows each space type's name and each authority's handle, in place of raw
  scope strings.

## Not tested yet

- A create whose PLC does not list the recovery key first. The host removes the account, but no
  probe makes that happen.
- A creator who stays on the recovery key page past the app's sign-in window.
- Ticket replay.
- A confidential OAuth client at a real https origin.
- A person on a PDS other than the spaces alpha.
