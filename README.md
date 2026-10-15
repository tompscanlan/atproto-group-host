# atproto-group-host

A group host for atproto groups. A group is an account with its own DID. It lives on a PDS that this
host runs. People sign in through their own PDS to act for the group, and the host decides who may
read and write the group's permissioned spaces.

This repo is at the start. Today it holds only a spike in `spike/`. The spike is throwaway code that
tested whether the design can work at all.

## What the spike proved

It ran on a private https devnet against the spaces alpha PDS (`bluesky-social/atproto` branch
`permissioned-data-alpha`, commit `79d6307e1`). The first round passed all three checks, the second round
all seven, and the third all eight.

1. **The PDS works as a library.** `PDS.create(cfg, secrets)` with no overrides, mounted behind an
   outer express app in one process. Our routes answer first. Everything else falls through to the
   unmodified PDS. Sign-in is changed by wrapping one method on the OAuth provider's account store at
   runtime. That field is `protected`, so it needs a recheck on every PDS update.
2. **A person signs in as the group without the group's password.** The app starts a normal OAuth
   flow for the group DID. The host sends the browser to the person's own PDS to sign in, checks
   that the person holds a role in the group, and mints a one-time ticket. A page the host serves at
   `/oauth/authorize` submits that ticket to the provider's own sign-in step. The app gets a session
   for the group DID. A person with no role is turned away.
3. **The host decides access to group spaces.** A space with the `managing-app` read and write
   policy, naming this host, makes the PDS ask the host's `checkUserAccess` on every read and every
   write. The host's answer decides who gets read credentials and which writers are tracked.

4. **Roles come from the group's own records.** The host reads `membership`, `role`, `access`
   and `permissions` from the group's spaces. It offers a person only the requested scopes their
   roles grant, before consent. Each scope is kept whole or dropped, so an app that wants a read
   to survive for members who cannot write asks for the read as its own scope.
5. **Each token knows its person, and is cut on every request.** The host records which person
   authorized each token, and keeps that through refresh and restart. The PDS reloads a token's
   scope from its store on every request, and the host cuts it there to what the person's roles
   grant now. Removing a member closed their open session on the next request.
6. **`prompt=create` makes a group.** The creator signs in through their own PDS. The host creates
   the account, the `meta` and `members` spaces, an `access` record in each, a `profile`,
   `permissions`, the `admin` and `member` roles, and the creator's `admin` membership.
7. **The group sign-in is not remembered, and the consent page is the host's.** The ticket sign-in
   uses `remember: false`. The provider then returns a token good for this one request, and the
   host's own consent page uses it. No device stays signed in as the group.

8. **The host enforces from the records.** `checkUserAccess` answers from the space's `access`
   record and the person's roles, or from `public`. A removed member gets no credential and is not
   tracked as a writer. Group writes through `com.atproto.space.*` pass the host's checks before
   the PDS takes them:
   - a `membership` write needs every role added or removed, and every role of a member being
     ejected, in the writer's `assignable` roles. A moderator who may write memberships could admit
     a member, but not promote to admin or eject an admin;
   - the record rules: a membership is keyed by the member DID and names declared roles; an
     `access` or `permissions` record has one grant per role, names declared roles, and has
     scopes that resolve; a role still held cannot be deleted;
   - the group writes only in spaces that have an `access` record.
9. **Nobody reconfigures a group space through simplespace.** `createSpace`, `updateSpace`,
   `putMember`, `removeMember` and `deleteSpace` are refused for group spaces, an admin's session
   included. Only the host's own code changes a group space's policy.

## What the spike found

- **The host cannot block a member's write.** Members write to their own PDS, so the write lands.
  The host only decides whether that writer is tracked. Apps and indexers have to filter.
- **Group sign-in must not be remembered.** With `remember: true` the browser stays signed in as the
  group, and a later request could skip the role check. Read from the provider code, not tried.
  Fixed in the second round (point 7 above).
- **A scope that only manages spaces also reads them all.** A `space:` scope with no `action` gets
  the default actions, `read` included. So `space:*?manage=create&manage=delete` lets its holder
  read every space of the group. Add `action=read_self` to grant only the manage operations.
- **The PDS's `createAccount` needs a password.** The spike creates the group with a random one
  and drops it. A real host should create the account with no password at all.
- **The consent screen needs its own wording.** It says "your account", but the person is acting for
  the group.

## Not tested yet

Ticket replay. Telling other space hosts that a removed member's credentials are revoked: a
credential already issued keeps working until it expires. The group methods (join, leave, join
requests, `createSpace`). A confidential OAuth client at a real https origin. A person on a PDS
other than the alpha. Caching: the spike reads the group's records on every request.

## Running the spike

It needs the https devnet (PLC, an alpha PDS, nginx with a local CA). `spike/run-host.sh` starts the
host in a container made from the pinned alpha PDS image, so `@atproto/pds` is exactly that build and
nothing is built locally. `spike/probe.mjs all` drives the checks. Throwaway keys and test logins are
written to `spike/data/`, which git ignores. `spike/probe-day2.mjs` and `spike/probe-day3.mjs` drive the second and third rounds, with
`spike/lib.mjs` holding what they share. The first round's `probe.mjs` no longer runs against the
current host, which now refuses its simplespace setup calls.
