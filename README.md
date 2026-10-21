# atproto-group-host

A group host for atproto groups. A group is an account with its own DID. It lives on a PDS that this
host runs. People sign in through their own PDS to act for the group, and the host decides who may
read and write the group's permissioned spaces.

This repo is at the start. Today it holds a spike in `spike/`, and in `devnet/` what runs it on a
test network. The spike is throwaway code that tested whether the design can work at all.

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
   `permissions`, the `admin` and `member` roles, and the creator's `admin` membership. Its page
   asks only for the group's address and the creator's own handle, as a PDS's own sign-up asks only
   for the handle. It turns down an address the PDS would refuse (over 18 characters, reserved,
   caught by its word filter, or taken) on that page, before the creator goes to their PDS, so
   the creator picks another without starting again from the app. The starting `profile` is named
   after the address; the app names the group by writing the profile.
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

## Running it on the devnet

The host runs on a private https devnet from
[`OpenMeet-Team/atproto-devnet`](https://github.com/OpenMeet-Team/atproto-devnet): its PLC, its spaces
alpha PDS, and an nginx that serves every name with a local CA. The devnet is used as it is; nothing
for the host goes into that repo. Below, `$DEVNET` is that checkout; `devnet/host.sh` defaults to
`/workspaces/scratch/atproto-devnet`.

### 1. Bring the devnet up

The devnet README's "The https devnet" has the details. In short:

```bash
export DEVNET=/path/to/atproto-devnet
cd "$DEVNET"
export DEVNET_PROJECT=devnet-mine   # the scripts refuse the shared devnet-spaces without DEVNET_RESET_OK=1
./scripts/https-up.sh               # safe to rerun; writes data/devnet.env
```

Only one https devnet can hold port 443 on a machine, so if one is already up, use it.
`devnet/host.sh` reads the compose project, the lexicon authority and the domain (`DEVNET_DOMAIN`,
`devnet.test` unless the devnet was given another) from `$DEVNET/data/devnet.env`. The names below
use `devnet.test`.

### 2. Publish the group lexicons (a new devnet only)

The host checks every scope a group's records name against the lexicons its PDS resolves, which
come from the devnet's lexicon authority. A devnet made from scratch, or after `https-down.sh -v`,
has an empty authority. Publish the opensocial proposal's lexicons
([tangled.org/opensocial.group/proposal](https://tangled.org/opensocial.group/proposal)) into it:

```bash
"$DEVNET/scripts/https-lexicons.sh" <proposal checkout>/lexicons
```

It leaves alone a record that already holds the same document. Publishing from another checkout
replaces the lexicons for every app on the devnet.

### 3. Start the host

From this repo's root:

```bash
devnet/host.sh up     # start it, or recreate it on the current code
devnet/host.sh logs   # follow its log
devnet/host.sh down   # stop it; its data and keys stay
```

`up` runs `spike/host.mjs` in a container made from the pinned alpha PDS image, so `@atproto/pds` is
exactly that build and nothing is built locally. The container is `grouphost-spike`, in compose
project `grouphost`, on the devnet's network. The first `up` adds the route
`https://grouphost.devnet.internal` (port 7070 here) to the devnet's nginx, with every name under
`gh.devnet.test`, where the groups' handles are, and writes throwaway keys to `spike/data/keys.env`.
Routing the handles needs a devnet with handle endings in `scripts/https-app.sh`; on an older one
`up` says so, and a group's handle resolves only at the host. Each `up` waits for the host's health check. The host's accounts and groups
live on the volume `grouphost-spike-data`. Keep `keys.env`: its rotation key made every group DID the
host holds.

### 4. Make the test people

The probes sign in as two people on the alpha, `gh-alice.devnet.test` and `gh-bob.devnet.test`. The
devnet's account tool makes them and keeps their logins in `spike/data/accounts.env` (mode 600, which
git ignores). A rerun signs in and creates nothing:

```bash
ACCOUNTS_FILE="$PWD/spike/data/accounts.env" "$DEVNET/scripts/https-account.sh" gh-alice GH_ALICE
ACCOUNTS_FILE="$PWD/spike/data/accounts.env" "$DEVNET/scripts/https-account.sh" gh-bob GH_BOB
```

### 5. Run the probes

Run `npm install` in `spike/` once. Then run each probe from there under the devnet's `https-run`,
which trusts the devnet's CA and resolves its names for that one command:

```bash
cd spike
"$DEVNET/scripts/https-run" node probe-day2.mjs   # 8 checks; restarts the host once
"$DEVNET/scripts/https-run" node probe-day3.mjs   # 8 checks
"$DEVNET/scripts/https-run" node probe-day4.mjs   # 16 checks
"$DEVNET/scripts/https-run" node probe-signup.mjs # 4 checks; needs a group on the host, so day 2 first
"$DEVNET/scripts/https-run" node probe-hints.mjs  # 9 checks; the hints on the link; needs a group, so day 2 first
"$DEVNET/scripts/https-run" node probe-in-step.mjs # 6 checks; restarts the host once
"$DEVNET/scripts/https-run" node probe-public-signin.mjs # 2 checks; the sign-in runs by name alone
"$DEVNET/scripts/https-run" node probe-subscribe-repos.mjs # 3 checks; a group's write arrives on subscribeRepos, the feed a relay follows
DEVNET=$DEVNET DEVNET_PROJECT=$DEVNET_PROJECT ./remote-signin.sh # the same probe from a container with its own network, as a browser on another machine
```

Each prints its checks and ends with a summary and a pass count. `spike/lib.mjs` holds what they
share. It needs two things outside this repo:

- **A Chromium launcher that trusts the devnet.** `DEVNET_BROWSER` names it. The default is
  `sandbox/opensocial/devnet-browser.mjs` from the `sandbox/opensocial-lexicons` branch of
  `tompscanlan/atproto`.
- **Playwright,** which `lib.mjs` loads from a fixed install path. Change that line on another machine.

The day-2 and day-3 probes save consent screenshots under `spike/shots/<time>-<probe>/`, a folder per
run that git ignores, so a run never overwrites an earlier one or the committed shots in `spike/`. To
update a committed shot, copy the new one over it on purpose. The first round's `probe.mjs` no longer runs, because the host now
refuses its setup calls.

### Using the host from an app

- **Where it is:** `https://grouphost.devnet.internal`. atmo reads it from `GROUP_HOST_URL`.
- **Running the app:** run it under `"$DEVNET/scripts/https-run"`. If the devnet's PDSes must reach
  the app, for example to fetch its OAuth client metadata, give it a route with
  `"$DEVNET/scripts/https-app.sh" <name> <port>`; it is then `https://<name>.devnet.internal`.
- **Group handles:** a group's handle is `<label>.gh.devnet.test`, and it resolves anywhere on the
  devnet: the devnet's nginx sends the name to the host, which answers
  `/.well-known/atproto-did`. `https-run` maps only the names it knows when it starts, so for a group
  made later, start the app with `HTTPS_RUN_EXTRA_NAMES='<label>.gh.devnet.test'`.
- **Sign-up page:** it opens at the host's own name, `https://grouphost.devnet.internal/signin/start`, so
  it works from any browser that can reach the host, not only one on the host's machine. The host signs
  people in as a public web client whose id is `https://grouphost.devnet.internal/signin/client-metadata.json`
  (authentication only, scope `atproto`, no key). It asks for the group's address and the creator's own handle, not a display name: write the
  group's `profile` after the create to name it.
- **Hints for that page:** an app may add `gh_name` (the group's name as the person typed it, a
  create only) and `gh_person` (the person's DID) to the authorization URL it sends the browser to;
  they do not go in the pushed request, whose unknown fields the PDS drops. The host suggests an
  address from the name (lowercase, each run of other characters one dash, no dash at either end,
  cut to 18; under 3 characters suggests nothing) and fills in the handle its own resolver finds for
  the DID. Both fields stay editable and are checked on Continue as anything typed is. A name over
  256 characters, a DID over 2048 or malformed, or one that does not resolve leaves its field empty.
  A hint is never trusted: the creator is whoever signs in at their own PDS. This is our own
  addition; the proposal is silent on it.

### A second host beside the shared one

`devnet/host.sh` also runs a host for a second copy of the devnet (another checkout, another compose
project and domain, `DEVNET_BIND` for the address its nginx listens on). Set `DEVNET` to that copy and
`HOST_PROJECT`, `HOST_CONTAINER`, `HOST_VOLUME` and `HOST_PORT` to names and a port the shared host does
not use; the defaults are the shared host's. Give the probes the same `HOST_CONTAINER`, and `DEVNET_BIND`
and `DEVNET_DOMAIN` for their browser (`spike/devnet-browser.mjs`). `probe-public-signin.mjs` checks that
the sign-in ran by name alone.

### A group host from a devnet's snowglobe.yml

A devnet can run group hosts itself, built from this checkout: `grouphosts:` in its `snowglobe.yml`,
with `SNOWGLOBE_OPENSOCIAL_BUILD` (or the entry's `build:`) naming this repo. Each one is
`https://<name>.<domain>`, its groups' handles are under that name, and its container is
`<project>-grouphost-<name>-1`. The probes take it from the environment:

```bash
cd spike
DEVNET=<that devnet checkout> GROUP_HOST_URL=https://gh.<domain> \
  GH_ACCOUNTS_FILE=<that devnet checkout>/data/accounts.env HOST_CONTAINER=<project>-grouphost-gh-1 \
  "$DEVNET/bin/snowglobe.mjs" run node probe-signup.mjs
```

- `GROUP_HOST_URL` is the host; the groups' handle ending is then its name (`GROUP_HANDLE_DOMAIN`
  sets another).
- `GH_ACCOUNTS_FILE` holds `GH_ALICE_*` and `GH_BOB_*`; `accounts: [gh-alice@alpha, gh-bob@alpha]`
  in the file makes them there.
- The browser takes the domain and nginx's address from `$DEVNET/data/devnet.env`.

The domain's top-level name has to suit both a handle and an OAuth client. The host signs people in
as a client at its own name, and the PDS refuses a client there under `.test`, `.local`,
`.localhost`, `.invalid` or `.example`, while a handle cannot end in `.internal`. So a globe at a
`.test` domain runs the host, but nobody can sign in through it. A globe's default domain,
`local.snowglobe.at`, suits both. Checked 2026-10-20 on a globe that named no domain:
`probe-signup.mjs` passed 4 of 4 at `gh.local.snowglobe.at` (the first run on a fresh host fails u1,
which needs a group already there), as it did earlier on two hosts at `ghcheck.lan`.

### Restarts and resets

- **A devnet restart** (`https-down.sh`, then `https-up.sh`, no `-v`): nothing to do. The host stays
  on the devnet's network through it and comes back with its groups.
- **A Docker restart:** the host has `restart: unless-stopped`, as the devnet's services do, so it
  should come back on its own. Not tried yet.
- **After `https-down.sh -v`:** every DID is gone from the devnet's PLC, so the host's groups are dead.
  Run `devnet/host.sh down`, then `docker volume rm grouphost-spike-data`, and delete
  `spike/data/accounts.env`. Then do steps 2 to 4 again; the next `up` picks up the new authority.
- **Removing the host:** run `devnet/host.sh down` and `docker volume rm grouphost-spike-data`. Then
  delete the `grouphost` line from `$DEVNET/data/https/apps`, and rerun `https-app.sh` for any other
  app listed there, so nginx reloads its routes.
