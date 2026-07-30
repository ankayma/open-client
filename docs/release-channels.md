# Release channels — test a real build before anyone receives it

> **Why this exists.** On 2026-07-30 four consecutive macOS releases (1.1.29–1.1.32)
> shipped an agent that macOS killed on exec. The tunnel never started. Every one of
> them reached every user the moment CI finished, because publishing an artifact and
> delivering it to users were the same step. Nobody noticed until the owner happened to
> open the app.
>
> The builds were also *installable*: dragging the DMG in worked fine. What was broken
> was the delivery path — the updater tarball, its signature, the entitlements on the
> nested binaries. So "someone installed it and it looked OK" was never going to catch
> this. A tester has to arrive at the build the same way a user does.

## The shape of it

```
git push github v1.1.34
        │
        ├─ CI builds, signs, notarizes, gates
        ├─ publishes to  get.ankayma.com/macos/beta/latest.json
        └─ GitHub Release created as PRERELEASE
                │
                ▼
   stable users:  nothing. Their app still reads /macos/latest.json,
                  which still points at the last promoted version.

   test machines: auto-update to 1.1.34 over the real update path —
                  tarball, minisign signature, notarization, entitlements.
                  Confirm the tunnel comes up and step-up still works.
                │
                ▼
   gh workflow run promote.yml -f tag=v1.1.34
        │
        ├─ re-verifies what is sitting in the beta bucket
        ├─ copies beta/ → stable, rewriting the manifest URL
        └─ flips the GitHub Release to Latest
                │
                ▼
        everyone receives it
```

The bytes promoted are the bytes tested. Nothing is rebuilt between the two, because a
rebuild would put an untested artifact in front of users — which is the failure this
whole mechanism exists to prevent.

## Putting a machine on the beta channel

```bash
echo beta > ~/.ankayma/update-channel     # opt in
rm ~/.ankayma/update-channel              # back to stable
```

Restart the app. `check_for_update` reads that file and overrides the updater endpoint;
absent or empty means stable. A typo falls back to stable and logs a warning rather than
leaving the machine with no updates at all.

Deliberately **not** a switch in Settings. A machine on beta receives builds nobody has
confirmed yet, so opting in should be an act, not a stray tap. Keeping it out of the UI
also keeps one binary serving both channels — if the endpoint were baked in at build
time, the build under test would not be the build that gets promoted.

## What promotion actually checks

`promote.yml` is a gate, not a copy step. A promote job that only copied would have
promoted all four broken builds just as quickly. Before anything moves it:

- confirms the beta channel holds the version you asked for — not a later one someone
  pushed while you were testing
- unpacks the updater tarball and **execs the sidecars out of it**; exit 137 is SIGKILL,
  which is what a binary carrying entitlements it cannot use looks like from outside, and
  is invisible to every static signature check
- confirms the tarball has a signature — a missing or stale `.sig` does not merely ship
  wrong bytes, the updater rejects the artifact and the machine cannot move forward at all
- confirms the DMG is stapled and Gatekeeper-accepted

## Rolling back

Re-run `promote.yml` with the previous tag. That copies the older artifacts back over the
stable path; no rebuild involved. The beta channel is untouched, so the bad build stays
available for diagnosis.

## Honest limits

This catches a broken *delivery*. It does not catch a broken *feature* unless someone
exercises the feature on a beta machine — the mechanism does not answer "who confirms the
new build still works", only "who gets the chance to, and before whom".

It is also only worth the extra step while machines actually sit on the beta channel. With
none, it is a delay that verifies nothing, and worse than no gate, because it looks like
one.

macOS is wired today. Windows uses the same updater and the same manifest scheme, so it
follows the same shape when someone gets to it. Linux would need a separate apt/yum
component. iOS already has TestFlight, which is this idea with Apple's plumbing; Android
has Play's internal testing track.
