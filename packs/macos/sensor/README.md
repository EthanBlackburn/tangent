# sensor

The pack's Endpoint Security client: what plugin `macos` reads.

```bash
sudo build/TangentSensor.app/Contents/MacOS/tangent-sensor | nc -U es.sock
```

It subscribes to ten events (`exec fork exit open close create rename unlink
btm_launch_item_add tcc_modify`) and writes each as one JSON line to stdout.
The lines are in the shape of `eslogger`'s, Apple's own Endpoint Security
tool, with its field names: they hold what the plugin reads and leave out the
rest (the stat blocks, the code hashes), so a line is about half the size of
eslogger's. Nothing is filtered yet: every event of the ten kinds is written.
`examples/macos/run.sh` starts it with the rest of the capture.

One Swift file, no dependencies. It needs root and, for the terminal that
starts it, Full Disk Access.

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
./build.sh /path/to/the.provisionprofile    # build/TangentSensor.app, signed "Apple Development"
./build.sh                                   # unsigned: it compiles, and says so when run
```

A profile has to sit in a bundle, so the binary is built inside one, with the
profile beside it, and is signed with the entitlements the profile lists. The
bundle's identifier and the team are read from the profile: neither is in
this directory, and `*.provisionprofile` is ignored by git.

## Limits

- It is started by hand or by `run.sh`, under sudo. It is not yet a launch
  daemon.
- No filtering at the source: the plugin still drops most `open` events
  after they have crossed the socket.
- `btm_launch_item_add` and `tcc_modify` are written from Apple's headers
  and eslogger's field names; neither has occurred in a run yet.
- Endpoint Security reports no network. `net/net.py` stays.
