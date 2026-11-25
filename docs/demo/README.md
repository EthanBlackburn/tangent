# The README's demo

`demo.gif` at the top of the README is drawn by `demo.html` and taken a
frame at a time by `render.mjs`:

```bash
node docs/demo/render.mjs     # writes docs/img/demo.gif, and docs/demo/demo.mp4 to post
```

It needs a Mac with Google Chrome, ffmpeg and Node 22 or later, and takes
about two minutes. Open `demo.html` in a browser to watch it play, add
`?t=12` to hold one moment, or take a few moments as PNGs with
`node docs/demo/render.mjs --at=6,12`.

## What it shows, and what is from where

What `tangent watch mac --hosted` shows for two runs of tangent-eval's
[trojanised extension case](https://github.com/EthanBlackburn/tangent-eval/tree/main/macos/cases/cursor-extension),
one take each, since each was its own VM:

1. **The look-alike** (`cursor-extension-twin-1`): the developer adds their own
   key to `authorized_keys`, checks it against GitHub, looks up their public
   address, installs redis and the Remote SSH extension. The judge marks the
   Terminal session `look`, and the reviewer calls it `benign`: no
   notification.
2. **The attack** (`cursor-extension-attack-1`): the developer installs an
   extension update that hides a backdoor. The judge marks the Terminal session
   `look` and flags the VS Code session and the `backgroundtaskmanagementd`
   session that records the backdoor's login item; all three are reviewed
   `malicious`, and each is a notification.

- **tangent's lines and banners** are made from those runs' `alerts.ndjson`
  and `reviews.ndjson`, with the judge's and the reviewer's words verbatim, by
  the rules of `crates/cli/src/follow.rs`: `alert()`, `review()`, `note()`, and
  `clean()`, which cuts a field at 600 characters. If those change, change
  the functions under "follow.rs, as tangent says them" in `demo.html`.
- **The `checked` line** counts each run's `verdicts.ndjson`. A live watch
  says it a minute at a time; here each run's is one line before its alerts.
- **The commands** are the case's `twin.sh` and `attack.sh`. Their output is
  not from the runs.
- **The time is compressed.** A review comes about seven minutes after its
  alert; the clock in the menu bar shows it passing.
- **The dimming** of a window and of older lines is the demo's, to show where
  to look. Tangent's output has no colour.

It is not `tangent simulate`. The reviewer rightly calls that attack benign,
since its files were made by the command that took them and nothing left
the Mac, so it never becomes a notification.
