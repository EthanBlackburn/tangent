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
  the rules of `crates/cli/src/follow.rs`, in its colours: `alert()`,
  `review()`, `tally()`, `progress()`, `note()`, `brief()`, which keeps a
  waiting alert to its first sentence or 100 characters, and `clean()`,
  which cuts a finding at 600. If those change, change the functions under
  "follow.rs, as tangent says them" in `demo.html`. The words before the
  first alert are `watch.rs`'s.
- **The `checked` line** counts each run's `verdicts.ndjson`. A live watch
  says it a minute at a time; here each run's is one line, with its alerts.
- **The commands** are the case's `twin.sh` and `attack.sh`. Their output is
  not from the runs.
- **The time is compressed**, and when each line comes is the demo's. An
  alert comes about 25 seconds after its session's last event, and its review
  about half a minute after the alert: tangent-eval's medians on today's
  settings (#277). The clock in the menu bar, and the `reviewing` lines a
  live watch says every 15 seconds, show it passing.
- **The runs were judged on 2026-11-13**, when a session was judged after a
  minute of quiet and a review read 400 seconds past its alert. Today's are 15
  seconds (#277) and 10 (#263, #264). The outcome is the same on them:
  #277's runs at 15 seconds had an alert standing after review in every
  attack run, this case's three among them, and in no look-alike run. The
  words would not be these, since a review now sees less of what came after
  its alert.
  Judging the two recordings again and putting their records in `demo.html`
  brings them up to date.
- **The dimming** of a window and of older lines is the demo's, to show where
  to look.

It is not `tangent simulate`. The reviewer rightly calls that attack benign,
since its files were made by the command that took them and nothing left
the Mac, so it never becomes a notification.
