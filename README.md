# atproto-group-host

A group host for atproto groups, following the
[opensocial.group proposal](https://tangled.org/opensocial.group/proposal).

A group is an account with its own DID, and this host is its PDS. People sign in through their own
PDS to act for the group, so nobody holds the group's password. The host decides who may read and
write the group's spaces, from the group's own records.

It is built on the spaces alpha PDS (`bluesky-social/atproto`, branch `permissioned-data-alpha`),
which it runs as a library. [docs/design.md](docs/design.md) explains how it works, the choices it
makes where the proposals are silent, and where it runs into their limits.

## Status

Early and experimental. It runs on test networks, not on the public atproto network.

- It is pinned to one spaces alpha build: the image in the [Dockerfile](Dockerfile),
  `permissioned-data-alpha` at `11c5d98cd` (2026-10-29). The alpha changes, and the host reaches
  into parts of the PDS that are not public API, so each move to a newer alpha is checked by hand.
- It is one process. What it keeps of its own is in memory and in one file under `/data`. It reads
  a group's records on every request, with no caching.
- It follows the opensocial.group proposal's `main` branch, tested at `2b41a9b`.

## What it does

- **Creates groups.** OAuth with `prompt=create` at the host makes a group: its account, its `meta`
  and `members` spaces and their starting records, with the creator as admin. The creator gets the
  group's recovery key, shown once and kept nowhere.
- **Lets people act for a group without its password.** The person signs in at their own PDS; the
  host checks their role and signs the app in as the group.
- **Cuts every session to the person's roles.** The host offers only the scopes a person's roles
  grant, and on every request cuts the session to what they grant now. Removing a member closes their
  session on its next request.
- **Enforces from the group's records.** It answers the PDS's access checks for group spaces from
  each space's `access` record, and checks every group write against the record rules and the
  writer's `assignable` roles. Nobody grants more than they hold.
- **Serves the group methods:** `requestJoin`, `cancelJoinRequest`, `leaveGroup`,
  `listJoinRequests`, `denyJoinRequest` and `createSpace`.
- **Serves `subscribeRepos`,** so a relay can follow the groups' repos.

Not built yet: invites, the moderation methods, `deleteSpace`, and moving a group to another host.
[docs/design.md](docs/design.md#not-built-yet) has the full list.

## Running it

The host ships as a Docker image built from the [Dockerfile](Dockerfile): the pinned spaces alpha
PDS image with `src/host.mjs` and its three dependencies added. Nothing is fetched when it starts.

```bash
docker build -t atproto-group-host .
```

It takes a PDS's usual `PDS_*` settings, and three of its own:

| Setting | What it is |
| --- | --- |
| `HOST_PUBLIC_URL` | The host's https address. Its `did:web`, and the OAuth issuer, come from it. |
| `HOST_LOOPBACK_URL` | How the host calls its own PDS: `http://127.0.0.1:<PDS_PORT>`. |
| `HOST_PLC_URL` | The PLC directory the host resolves people's DIDs from when it signs them in. |

Of the PDS settings, these matter most here:

- `PDS_HOSTNAME`: the host's name, the same as in `HOST_PUBLIC_URL`.
- `PDS_SERVICE_HANDLE_DOMAINS`: the groups' handle ending, such as `.<the host's name>`.
- `PDS_DATA_DIRECTORY`: `/data`. The host keeps its own state file there too, so mount a volume
  there.
- `PDS_LEXICON_AUTHORITY_DID`: an authority that publishes the `group.opensocial.*` lexicons. The
  host checks every scope a group's records name against the lexicons its PDS resolves.
- `PDS_INVITE_REQUIRED=false`: the host makes its groups' accounts itself.

Health is `GET /xrpc/_health`, as on any PDS.

### In a snowglobe

[snowglobe](https://github.com/OpenMeet-Team/snowglobe) runs a whole atproto network on one machine
for testing, and it can run this host. List it under `grouphosts` in a `snowglobe.yml`:

```yaml
grouphosts:
  - name: gh
    kind: opensocial
    build: ../atproto-group-host   # this checkout, from the file's folder
```

The host is then at `https://gh.<domain>`, and its groups' handles end in `.gh.<domain>`. Instead of
`build:`, `SG_OPENSOCIAL_BUILD=<this checkout>` names it for every file, or `image:` names a built
image.

### Test routes

The host serves a few routes under `/test/` for its probes: one shows its state, and others write
as a group or interrupt a create. They take the PDS's admin login (HTTP Basic auth, user `admin`,
password `PDS_ADMIN_PASSWORD`), as the PDS's own admin routes do. Anyone with that password already
controls the host, so they add no new power, but keep them unreachable from outside on a host people
use.

## Testing

The probes in [probes/](probes) drive the host end to end on a snowglobe: a browser signs people in
at their own PDS, an OAuth client acts for the group, and each check prints PASS or FAIL. Each
probe's header lists its checks.

You need Node 20 or later (tested on 22), Docker, and the snowglobe command (`npm install -g @openmeet/snowglobe`).

1. Install the probes' dependencies and Chromium:

   ```bash
   npm ci
   npx playwright install chromium
   ```

2. Copy the opensocial lexicons into `probes/lexicons/` (git ignores it). The snowglobe publishes
   them, and the host checks scopes against them:

   ```bash
   git clone https://tangled.org/opensocial.group/proposal ../opensocial-proposal
   mkdir -p probes/lexicons && cp -r ../opensocial-proposal/lexicons/group probes/lexicons/
   ```

3. Bring the snowglobe up from `probes/`. It runs a spaces alpha PDS with two test people, alice
   and bob, and the host built from this checkout. Run `snowglobe up` again after changing the host
   to rebuild it.

   ```bash
   cd probes
   snowglobe up
   ```

4. Run a probe with `snowglobe run`, which hands it the snowglobe's addresses and logins:

   ```bash
   snowglobe run node sessions.mjs
   ```

| Probe | What it checks |
| --- | --- |
| `sessions.mjs` | Creating a group; each token knows its person; sessions cut to roles; restart |
| `enforcement.mjs` | Access, record rules and `assignable` roles, enforced from the records |
| `group-methods.mjs` | Join, cancel, leave, join requests and `createSpace` |
| `member-oauth.mjs` | A member's own acts through OAuth at their own PDS |
| `grants.mjs` | Nobody grants more than they hold |
| `public-repo.mjs` | An admin writes the group's public repo and uploads images |
| `in-step.mjs` | The host keeps related records in step, and cleans up a create cut short |
| `recovery-key.mjs` | The creator's recovery key: shown once, first in the PLC, kept nowhere |
| `signup-page.mjs` | The sign-up page turns down bad addresses before the person leaves it |
| `hints.mjs` | The hints an app may put on the sign-up link |
| `cancel.mjs` | Saying no at your own PDS ends the app's request cleanly |
| `public-signin.mjs` | The sign-in runs by name alone, from any browser |
| `subscribe-repos.mjs` | A group's write arrives on `subscribeRepos` |

`signup-page.mjs` and `hints.mjs` need a group on the host already, so run `sessions.mjs` first on a
new snowglobe. `sessions.mjs` and `in-step.mjs` restart the host's container. Screenshots of the
consent pages go to `probes/shots/<time>-<probe>/`. No probe captures the recovery key page, which
holds a private key.

When you are done, `snowglobe down -v` stops the snowglobe and drops its data.

## Using it from an app

- **Make a group:** start OAuth at the host with `prompt=create`. The host's page asks for the
  group's address and the creator's own handle, and the app gets a session for the new group. Name
  the group by writing its `profile`.
- **Act for a group:** start OAuth for the group's DID. The host signs the person in through their
  own PDS and offers the scopes their roles grant.
- **Hints:** an app may add `gh_name` (the group's name as the person typed it) and `gh_person` (the
  person's DID) to the authorization URL. The host fills in its page from them. A hint is never
  trusted.
- **A person's own acts** (`requestJoin`, `cancelJoinRequest`, `leaveGroup`) go to their own PDS,
  proxied to the group with `atproto-proxy: <group DID>#atproto_pds`.
- The host signs people in as a public OAuth client at
  `<HOST_PUBLIC_URL>/signin/client-metadata.json`, so its name must be one a PDS accepts for a
  client: not under `.test`, `.local`, `.localhost`, `.invalid` or `.example`.
