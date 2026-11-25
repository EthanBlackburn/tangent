# sensor

The pack's Endpoint Security client: what plugin `macos` reads.

```yaml
sources:
  mac:
    type: macos
    sensor: build/Tangent.app/Contents/MacOS/tangent-sensor
```

`sensor:` names a build of your own, as here. Left out, tangent runs its
release's, which it fetches and checks itself (the pack's
[README](../README.md)).

It subscribes to ten events (`exec fork exit open close create rename unlink
btm_launch_item_add tcc_modify`) and writes each as one JSON line to stdout.
The lines are in the shape of `eslogger`'s, Apple's own Endpoint Security
tool, with its field names: they hold what the plugin reads and leave out the
rest (the stat blocks, the code hashes), so a line is about half the size of
eslogger's. Nothing is filtered yet: every event of the ten kinds is written.
A `macos` source starts it, as root through `sudo`, with the rest of the
capture ([examples/macos](/examples/macos)).

Each line is written as its event arrives. When the reader is too slow the
kernel drops events, and the sensor says on stderr how many of each kind, by
the gaps in the numbers the kernel gives them. Of the ten, only `tcc_modify`
may be missing (it came with macOS 15.4) and the sensor goes on without it;
any other event refused, it stops.

Two Swift files, no dependencies. As the sensor it needs root and, for the
terminal that starts it, Full Disk Access.

## Notifications

The bundle is also the app `tangent watch` shows its notifications through
(`notify.swift`). macOS shows a notification under an app's name and icon,
and asks the Mac's owner once whether that app may show any, so it takes a
signed app to show one, and this is the one tangent has. The name is the
bundle's file name, which is why it is `Tangent.app`: macOS names an app
that has no translations by its file, whatever its Info.plist says.

```bash
build/Tangent.app/Contents/MacOS/tangent-sensor notify < notifications.ndjson
```

It runs as you, never as root. Each line of stdin is one notification, a
JSON object: `title`, `subtitle` and `body` are the banner, `detail` is the
text shown in a dialog when the banner is clicked, and `sound` (true or
false) says whether it makes one. With `feedback` it has three buttons,
"Not me", "Not sure" and "That was me", on the banner and in the dialog:
the answer is added to the file `feedback.file` names, as the object
`feedback.line` with `answer` (`not_mine`, `unsure` or `mine`) and `ts`
put in. It ends when stdin
does, once any dialog that is open has been closed. `tangent watch`
starts it once and keeps it for as long as it runs: macOS takes its question
back when the process that asked ends, and counts that as a no. When the
answer is no, it says so and ends. macOS never asks again, so each later
start that finds them off opens System Settings at Tangent's notifications,
where Allow notifications turns them on, says so and ends (`tangent watch
--no-notify` starts none). When macOS will not ask at all, as for an app
that is not signed, it says what macOS said.

A click on a notification whose process has ended has macOS start the app,
which deals with that one click, a button's answer or the dialog, and ends.
macOS hands it the click only once AppKit says the app has finished
launching, so this is the one part of it that runs AppKit's loop. Started as
the sensor it does neither: it tells the two apart by its first argument and
by how macOS names an app it starts.

## What it needs from Apple

An Endpoint Security client
needs `com.apple.developer.endpoint-security.client`, which Apple grants to a
developer team on request and macOS checks against a provisioning profile.
Without both the binary is not allowed to start. Once, for a team:

1. Ask for the entitlement: the Account Holder of a paid Developer Program
   team, at <https://developer.apple.com/contact/request/system-extension/>
   (Endpoint Security Entitlement). Apple answers by email.
2. In Certificates, Identifiers & Profiles: an App ID with the Endpoint
   Security capability on, an Apple Development certificate, this Mac as a
   device (its Provisioning UDID, from System Information), and a macOS App
   Development profile of the three. Download the profile.

A development profile runs on the Macs registered in it and no others.

## Build

```bash
./build.sh /path/to/the.provisionprofile    # build/Tangent.app, signed "Apple Development"
./build.sh                                   # signed ad hoc: it shows notifications, and is not the sensor
```

A profile has to sit in a bundle, so the binary is built inside one, with the
profile beside it, and is signed with the entitlements the profile lists. The
bundle's identifier and the team are read from the profile: neither is in
this directory, and `*.provisionprofile` is ignored by git.

## Hand it out

The entitlement is the signer's, not the Mac's: a build signed with the
team's Developer ID, with a Developer ID profile in it, runs on any Mac, and
whoever downloads it asks Apple for nothing. In the developer account that
takes a Developer ID Application certificate and a Developer ID profile for
the same App ID; then

```bash
./build.sh developer-id.provisionprofile "Developer ID Application"   # both architectures, timestamped
./notarize.sh --keychain-profile NAME                                 # or --key FILE --key-id ID --issuer UUID
```

`notarize.sh` sends the bundle to Apple's notary, staples the ticket on and
writes `build/tangent-sensor-macos.zip`, which Gatekeeper lets through on a
Mac that has never seen it. `.github/workflows/sensor.yml` does the same on
a release, from six secrets it lists, and uploads the zip beside the
binaries; where the secrets are not set it builds nothing. The bundle's
version is tangent's, from the workspace's Cargo.toml.

A build from source, or a fork's, cannot be signed with another team's
entitlement: it needs its own grant from Apple.

## Limits

- Tangent starts it under sudo, with your password, each run. It is not yet
  a launch daemon.
- No filtering at the source: the plugin still drops most `open` events
  after they have crossed the pipe.
- `btm_launch_item_add` and `tcc_modify` are written from Apple's headers
  and eslogger's field names; neither has occurred in a run yet.
- The notarized build has been through Gatekeeper on the Mac that built it,
  as a quarantined download. It has not been run on a second Mac.
- Endpoint Security reports no network. The `macos` source reads it from
  tcpdump.
