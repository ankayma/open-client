# Services

The **Services** screen is your catalog: the private services *you* are allowed to
reach, right now. It's the answer to "what can I get to on this mesh?"

## What you see

Each card shows:

- **the service name** and its full private address,
- the **node** it lives on,
- **via …** — the reason you can reach it (which access rule grants it).

Click **Open ↗** to launch a service in your browser.

## Where the list comes from

The list is **derived from your team's access policy** — it is not a separate list
someone maintains by hand, so it can never drift out of sync. Specifically:

- If you're an **admin / the owner**, you see everything in your mesh.
- If you're a **member**, you see exactly what the policy in [Access](access.md)
  grants your role — nothing more (default-deny).

So if a teammate's services don't appear, an admin hasn't granted that access yet.

## Empty list?

Two common reasons:

1. No services have been named yet → create one under [Subdomains](subdomains.md).
2. You're a member and no rule grants you access yet → ask an admin to add a rule in
   [Access](access.md).

## Privacy

Your Services list is **self-scoped**: it only ever shows what you personally may
reach. It does not reveal the whole topology, and it isn't a live map of who's
connected.
