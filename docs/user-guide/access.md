# Access (policy)

The **Access** screen is where an admin decides **who can reach what**. It's the engine
behind every member's [Services](services.md) list. *Team tier; admins author, members
see it read-only.*

## Default-deny

Nothing is allowed unless a rule says so. An empty policy means members can reach
**nothing**. (As the admin/owner you always reach your own mesh.) This is the safe
default: you grant access deliberately, you never have to remember to take it away.

## Read a rule

Each rule reads **who → what**:

```
role=member,tag=engineer  →  service=epos
```

- **left (who)** — a *principal* selector: `role` (admin/member) and/or a `tag`.
- **right (what)** — a *resource* selector: a `service` name and/or a resource `tag`.
- `*` means "any".

A member is allowed to reach a service if **some rule's left side matches them and its
right side matches the service**.

## Add a rule (admin)

1. Under **Add a rule**, pick **Who** (a role, optionally a tag).
2. Set **What** (a service name, or `*` for any; optionally a resource tag).
3. Click **+ Add rule**. Repeat for as many grants as you need.
4. Click **Publish policy** to make it live.

Members' Services lists update to match on their next load.

## Why some fields are missing

You can only select on **real identity attributes** (role, tags, assurance level,
owner, service name, tier). You *cannot* base access on cosmetic things like a device's
display name — those fields aren't offered, and the server rejects them outright. This
keeps access decisions auditable and prevents accidental backdoors.

## Tamper-evidence

Every publish appends a new, hash-chained **version** of your policy. The banner shows
the version and **chain intact ✓** — proof the history hasn't been altered. If it ever
read **BROKEN**, that's a signal to investigate.

> Coming next: grouping services by zone (yours vs. teammates') needs device-ownership
> tagging, which is on the roadmap.
