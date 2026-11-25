<p align="center">
  <img src="https://github.com/user-attachments/assets/7da02584-0a4e-4e41-af6d-61cb081029c4" alt="Tangent logo" height=170>
</p>
<h1 align="center">Tangent</h1>
<p align="center"><strong>Have an LLM watch your Mac and cloud accounts for break-ins.</strong></p>
<p align="center"><em>Catch poisoned packages, rogue AI-agent actions, and stolen-key abuse — locally on Apple Silicon or with your own API key. No SIEM. No rules to write.</em></p>

<p align="center">
  <a href="https://github.com/EthanBlackburn/tangent/actions">
  <img height="20" src="https://img.shields.io/github/actions/workflow/status/EthanBlackburn/tangent/scaffold_test.yml?label=build&logo=github" alt="Build status"></a>
  <a href="https://twitter.com/telophasehq">
  <img src="https://img.shields.io/twitter/follow/telophasehq?style=social" alt="X">
  </a>
</p>

<p align="center">
  <a href="/docs/try-it.md">Quickstart</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="/docs/reference.md">Runtime Reference</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://discord.gg/ZUHB3BRa8c">Discord</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://github.com/EthanBlackburn/tangent/issues/new">Issues</a>
</p>

<p align="center">
  <img src="docs/img/demo.gif" alt="Two runs of tangent watch mac. In the first, a developer adds their own SSH key, installs redis and an editor extension; Tangent's judge marks the session and its reviewer clears it as benign, with no notification. In the second, an editor extension update hides a backdoor; the judge flags the editor, the terminal and the login item the backdoor adds, all three are reviewed malicious, and each becomes a macOS notification.">
  <br>
  <sub>What <code>tangent watch mac</code> shows for <a href="https://github.com/EthanBlackburn/tangent-eval/tree/main/macos/cases/cursor-extension">two recorded runs</a>, re-created from their records and sped up.</sub>
</p>

---

Modern compromises start on a developer's laptop — a poisoned npm or PyPI package, a trojanised editor extension, a fake take-home repo, or a prompt-injected coding agent grabbing `~/.aws`, `~/.ssh`, Keychain, or browser tokens — and finish in your cloud accounts. At most startups, nothing watches either side.

Tangent is a single binary that watches both. A fast model reads your activity and flags anything suspicious; a second model investigates every alert against the full local log before paging you, and tells you in plain English what happened and what to check first.

## Quickstart

### 1. Install

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/EthanBlackburn/tangent/releases/latest/download/tangent-cli-installer.sh | sh
```

Also available via Homebrew (`brew tap ethanblackburn/tangent && brew install tangent-cli`) and Cargo (`cargo install --git https://github.com/EthanBlackburn/tangent tangent-cli`).

### 2. Watch your Mac (100% local by default)

Grant your terminal Full Disk Access (System Settings → Privacy & Security, then restart the terminal) and run:

```bash
tangent watch mac
```

- **Local by default:** On Apple Silicon (32 GB+ RAM), Tangent downloads a SHA-256-verified local server (its own copy of Ollama) and Inkling 2 Mini (~20 GB) into `~/.cache/tangent/models` after asking, starts it automatically, and stops it when you exit. Nothing leaves your Mac.
- **Zero manual sensor setup:** Tangent downloads the Apple-signed, notarized Endpoint Security sensor once per version and verifies its signature and notarization before each start. It asks for `sudo` once to start the sensor and `tcpdump`.
- **Hosted option:** Pass `--hosted` with `ANTHROPIC_API_KEY` set to use Claude Haiku 5.5 + Claude Sonnet 5.5 instead (works on any Mac, regardless of RAM). On an Intel Mac or one with under 32 GB, `tangent watch mac` stops before downloading anything and tells you to add it; it never switches to a hosted model on its own.
- **What it sees:** Every program run and its process tree, reads/writes of credentials, AI-agent configs, and login items, per-process outbound connections, and what you ask Claude Code (from `~/.claude` transcripts).

### 3. Watch your cloud & SaaS accounts

Watch [AWS CloudTrail](/packs/cloudtrail), [GitHub](/packs/github), [Okta](/packs/okta), [Google Workspace](/packs/google_workspace), and [Supabase](/packs/supabase) with read-only credentials:

```bash
export ANTHROPIC_API_KEY=...
tangent watch cloud --sources okta,github
```

- **Test on the last 24 hours of AWS CloudTrail:**
  ```bash
  tangent init cloud --sources cloudtrail
  tangent replay --config tangent.yaml --from 1d
  ```
- **Choose any model or run locally:** Add `--local` to keep every cloud record on your Mac with Inkling 2 Mini, `--local --model <name>` for your own local server (`llama-server`, `mlx_lm.server`, Ollama, vLLM), or `--provider openrouter|openai|bedrock --model <judge>,<reviewer>`.

While `tangent watch` runs, what it checked, each alert and each settled review stream to your terminal:

```text
checked   41 (deploy-bot x30, ana@acme.example x9, 2 more): 1 flagged
flagged   2026-11-24 03:09Z  okta  ana@acme.example
          a sign-in from a Tor exit, with no second factor
          sent to review
reviewed  ana@acme.example, 3 alerts: malicious
          ...
          check: ...
```

Want to edit the prompts, route alerts to Slack, or customize the pipeline? Run `tangent init mac` or `tangent init cloud` with the same flags to write a standalone `tangent.yaml` and prompt files in your current directory. See [docs/try-it.md](/docs/try-it.md) for full details and required credentials.

## What an alert actually looks like

Not a cryptic rule ID and a severity score. Here is Tangent's review of a recreated trojanised Claude Code extension run on a Mac (shortened):

> VS Code's Code Helper (Plugin) process, acting on behalf of the extension `acme-tools.acme-assist-2.1.3`, ran a hidden script `~/.config/.mtr` […] contacted `ifconfig.me` and `api.ipify.org`, created `~/.ssh/authorized_keys` and a LaunchAgent masquerading as `~/Library/LaunchAgents/com.apple.sysstatd.plist`, and ran `/usr/sbin/systemsetup -setremotelogin on` […] opening a persistent reverse SSH tunnel to an external host. This was not requested by the owner and was triggered purely by the extension loading.
>
> **What to check first:** Disable remote login, inspect `~/.ssh/authorized_keys` for the injected key, remove the LaunchAgent, kill any reverse-tunnel `ssh` processes, and remove `acme-tools.acme-assist`.

And here is what Tangent said of a benign look-alike on the same Mac — a developer adding their own SSH key, testing GitHub SSH access, and installing Redis via Homebrew:

> That key is this Mac's own public key, so it grants login only to someone who already holds the owner's private key. […] Homebrew installed redis and created its `sh.brew.redis` LaunchAgent, which is Homebrew's normal service setup. `ssh -T git@github.com` checked GitHub access.

**Result: cleared — no alert.** Both sessions wrote `authorized_keys`, ran `ssh`, and created a LaunchAgent. Static rules fire on both or neither; Tangent's reviewer inspects the session history and files and tells them apart.

## How it works

1. **Collect & compress.** On a Mac, Tangent joins Endpoint Security events, per-process network connections, and Claude Code prompts into compact per-session summaries. In the cloud, source packs normalize provider audit logs and annotate what is new for each actor (new API, country, client, network, OAuth app).
2. **Judge fast, then investigate.** A fast judge reads every window and marks anything suspicious freely (`pass`, `look`, `flag`). A second reviewer investigates each alert by running read-only SQL over your local Parquet log lake — and on a Mac, reading scripts or agent settings an alert points to (never credentials or transcripts) — to confirm real attacks and drop ordinary work.
3. **Keep everything local.** Raw logs stay on your machine as zstd-compressed Parquet files you can query anytime with `tangent query`.

## What it has caught

### On the Mac

We recreated seven real-world developer attacks inside a Mac VM with Tangent watching, alongside seven benign developer look-alikes doing similar things for legitimate reasons. Each recording was run three times with Claude Haiku 5.5 (judge) and Claude Sonnet 5.5 (reviewer):

| Attack | What it does on the Mac |
|---|---|
| **Shai-Hulud** | An `npm` install script sweeps tokens and keys and republishes the developer's packages with itself added |
| **axios compromise** | An `npm` install script drops a remote-access tool disguised as an Apple daemon |
| **LiteLLM compromise** | A PyPI package installs a hook that runs on every Python startup and harvests credentials |
| **Contagious Interview (CLI)** | A fake recruiter's take-home repo exfiltrates wallets, browser data, and Keychain, and installs a backdoor |
| **Contagious Interview (editor)** | Opening the repo folder triggers a hidden editor task that pipes a script into `bash` |
| **GlassWorm** | An editor extension steals Keychain, wallets, and credentials and adds a login item |
| **Trojanised Claude Code extension** | An editor extension injects an SSH key, opens a reverse tunnel, and installs a LaunchAgent |

- **Caught:** **7 of 7** attacks in all 3 runs.
- **False alarms:** The judge alone marked look-alikes in 16 of 21 runs; after the reviewer investigated, **0 of 7** stood.
- All recordings and harness code: [tangent-eval/macos](https://github.com/EthanBlackburn/tangent-eval/tree/main/macos). *(Note: local Inkling 2 Mini results on this Mac suite are not published yet.)*

### In the cloud

Evaluated against 59,342 records across ~13.5 months of a synthetic startup's AWS, Okta, GitHub, Google Workspace, and CI logs with 71 planted attacks (35 AWS techniques from Stratus Red Team + 36 cases we wrote). Models read the 6,832 records in the hours around those attacks (5,304 ordinary):

| Setup | Attacks caught (of 71) | Ordinary records flagged (of 5,304) |
|---|---|---|
| **Tangent: Claude Haiku 5.5 + Sonnet 5.5** *(1 run; default hosted)* | **70** | **40** after review *(462 before)* |
| **Tangent: DeepSeek V4 Flash** *(2 runs via OpenRouter)* | **71** | **10–13** after review *(~220 before)* |
| **Tangent: GPT-6 Luna + GPT-6.1 Terra** *(1 run via OpenAI)* | **71** | **20** after review |
| Elastic public detection rules *(350 rules)* | 51 | 43 |
| Sigma public detection rules *(102 rules)* | 13 | 121 |

**Being candid about what this doesn't prove yet:**
- The cloud logs are synthetic, and our 36 custom cases were written while developing the judge's brief.
- Elastic's rules matched Tangent on the Mac suite and caught all 35 Stratus AWS techniques — the difference is that Tangent gets there with one binary and no detection-engineering team.
- False-alarm volume across a real company's working week has not been benchmarked yet.

## Privacy & cost

**Where your data goes:** Raw logs never leave your machine unless you route them somewhere. When running locally (`tangent watch mac` default, or `tangent watch cloud --local`), **nothing leaves your machine at all**. With a hosted model, only the compiled summaries/records (and the queries/files the reviewer inspects during an alert) are sent directly to the model provider you chose.

**Cost:** Tangent is Apache-2.0 licensed with no subscription. Running locally costs $0 in API fees. On hosted models, you pay only your model provider's token usage — rough cloud judge estimates for a 50-person company on Claude Haiku 5.5:

| Source | Estimated judge fees / day |
|---|---|
| AWS (CloudTrail) | $2 – $20 |
| Okta | ~$0.60 |
| Google Workspace | $0.35 – $0.70 |
| GitHub | ~$0.30 |

Reviewer fees depend on how often the judge flags (roughly matching the judge's fees with DeepSeek, and several times the judge's fees with Sonnet in the cloud eval). See [Volume and cost](/docs/reference.md#volume-and-cost) for the token math.

## What Tangent is not

- **Not a SIEM.** No dashboards, no search UI, no case management.
- **Not a blocker.** It investigates and tells you what happened; it does not kill processes or revoke keys.
- **Not deterministic.** LLMs vary from run to run — every benchmark above states how many runs it came from.
- **Not fleet-managed yet.** Mac monitoring is set up one machine at a time today.

## Under the hood: a Rust + WASM stream processor

Everything above is built on a single generic Rust runtime: sandboxed WASM plugins (Rust, Go, Python), transactional SQLite state, shared in-memory enrichment tables, Parquet lakes (`tangent query`), and built-in model/agent nodes. Every provider integration is just a [pack](/packs/README.md) — so you can add your own logs or build custom streaming pipelines without touching a DSL.

- [Quickstart & watch/init guide](/docs/try-it.md)
- [Runtime & plugin manual](/docs/reference.md)
- [Packs & examples](/packs/README.md)

## License

Apache-2.0. See [`LICENSE`](/LICENSE).
