# Devices

Every machine on your mesh is a **device** (also called a node). The Devices screen
lists them with a live status dot and the overlay address each one holds.

## Enroll a device

1. Open the app and **sign in** (GitHub).
2. On **Devices**, click **Add a device**.
3. To bring this machine onto the mesh, connect it — the app hands your identity to a
   privileged helper that opens the secure tunnel (macOS will ask for your password
   the first time, because a network device needs admin rights).

Each device keeps a stable identity, so reconnecting **reuses the same node** instead
of creating a duplicate.

## Add another of your machines

Click **Add a device → create a join link**. Open that link on the second machine
(it signs in automatically into the same account) and connect. No second GitHub login.

## The overlay address

Each device gets a random **overlay IP** (an IPv6 ULA address by default, e.g.
`fd00:…`). It's how your devices reach each other privately. The address is random and
can rotate — it is *not* a stable identifier, by design.

## Remove a device

Click the **✕** next to a device. It's removed from your mesh immediately and recorded
in your audit ledger. A removed device can't reach anything until it re-enrolls.

## Status dot

- **Green** — up and reachable.
- **Grey** — enrolled but not currently connected.

> Note: bringing the tunnel up is macOS-first today. Other desktop platforms are on
> the way; iOS/Android need additional OS plumbing.
