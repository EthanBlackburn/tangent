# sensor

An Endpoint Security client of the pack's own, in `eslogger`'s place:

```bash
sudo eslogger exec fork exit open close create rename unlink btm_launch_item_add tcc_modify | nc -U es.sock
sudo build/TangentSensor.app/Contents/MacOS/tangent-sensor | nc -U es.sock
```

are the same to plugin `macos`. It subscribes to the same ten events and
writes each as one JSON line in eslogger's shape, holding what the plugin
reads and leaving out the rest (the stat blocks, the code hashes), so a line
is about half the size. Nothing is filtered yet: every event of the ten kinds
is written, as eslogger writes them. `examples/macos/run.sh` takes it as
`SENSOR=/path/to/tangent-sensor ./run.sh`.

One Swift file, no dependencies. It needs root and, for the terminal that
starts it, Full Disk Access, as eslogger does.

## What it needs from Apple

`eslogger` is Apple's, and carries Apple's entitlement. A client of your own
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
./build.sh /path/to/the.provisionprofile    # build/TangentSensor.app, signed "Apple Development"
./build.sh                                   # unsigned: it compiles, and says so when run
```

A profile has to sit in a bundle, so the binary is built inside one, with the
profile beside it, and is signed with the entitlements the profile lists. The
bundle's identifier and the team are read from the profile: neither is in
this directory, and `*.provisionprofile` is ignored by git.

## Check it against eslogger

```bash
./compare.sh        # both at once for a minute, then compare.py over the two
```

`compare.py` takes the events both saw in the time both ran, matches them by
time, kind and pid, and compares every field plugin `macos` reads. It prints
counts and field names, never a value.

## Limits

- It is started by hand or by `run.sh`, under sudo, as eslogger is. It is not
  yet a launch daemon.
- No filtering at the source: the plugin still drops most `open` events
  after they have crossed the socket.
- `btm_launch_item_add` and `tcc_modify` are written from Apple's headers
  and eslogger's field names; neither occurred in the minute it was compared
  over.
- Endpoint Security reports no network. `net/net.py` stays.
