# atproto-group-host

A group host for atproto groups. A group is an account with its own DID. It lives on a PDS that this
host runs. People sign in through their own PDS to act for the group, and the host decides who may
read and write the group's permissioned spaces.

This repo is at the start. Today it holds only a spike in `spike/`. The spike is throwaway code that
tested whether the design can work at all.

## What the spike proved

It ran on a private https devnet against the spaces alpha PDS (`bluesky-social/atproto` branch
`permissioned-data-alpha`, commit `79d6307e1`). All three checks passed.

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

## What the spike found

- **The host cannot block a member's write.** Members write to their own PDS, so the write lands.
  The host only decides whether that writer is tracked. Apps and indexers have to filter.
- **Group sign-in must not be remembered.** With `remember: true` the browser stays signed in as the
  group, and a later request could skip the role check. Read from the provider code, not tried.
- **The consent screen needs its own wording.** It says "your account", but the person is acting for
  the group.

## Not tested yet

Ticket replay. Narrowing each session to the person's current roles. Creating a group through
`prompt=create`. A confidential OAuth client at a real https origin. A person on a PDS other than the
alpha.

## Running the spike

It needs the https devnet (PLC, an alpha PDS, nginx with a local CA). `spike/run-host.sh` starts the
host in a container made from the pinned alpha PDS image, so `@atproto/pds` is exactly that build and
nothing is built locally. `spike/probe.mjs all` drives the checks. Throwaway keys and test logins are
written to `spike/data/`, which git ignores.
