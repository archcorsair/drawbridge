# Release gate: what blocks the release after the 2026-10-28 P0s

Source: the "Before the next release" items in
[docs/security-audit-2026-10-28-eval.md](../security-audit-2026-10-28-eval.md)
§"Recommended order of work" (step 1) and the P0 ledger,
[audit-2026-10-28-p0.md](audit-2026-10-28-p0.md). The P0 fixes are on `main`
(PR #2, merge cc27a11); no release contains them or PR #1 yet.

Rules for whoever works an item: the same as the P0 ledger. Read AGENTS.md
first and keep every invariant; touch only your item's files; one commit per
item (two where the item says so), Conventional Commits, no AI attribution
lines; Mac validation (`go build ./...`, `go vet ./...`, `GOOS=linux go vet
./...`, `go test ./...` for touched packages) is required; never claim a guest
leg passed without running it; do not edit this ledger. The lead reviews every
diff before it lands on `release-gate`.

## RG-1: E7, release and CI toolchain (M28, NEW-T1, audit #11, #24)

**Owner decision (2026-10-29): approved as recommended in E7.**

**Problem.** `release.yml` builds with `go-version-file: go.mod`, which
setup-go reads as exactly go1.25.0: govulncheck finds 35 to 36 reachable stdlib
advisories in the release binaries, including the root daemon and the root
guest agent. The mise pin go1.26.5 has 15 (NEW-T1). No job runs govulncheck.
No job checks that the committed bpf2go objects match the C source (audit
#11). Builds carry no `-trimpath` (audit #24). `release.yml`'s header still
says the workflow is dormant because the repo is private; it has been public
since 2026-08-02.

**Change.**
- Pin release builds to an exact Go patch: `go1.26.10`, the current 1.26
  release (go.dev/dl, checked 2026-10-29; go1.27.3 also exists, moving to 1.27
  is a separate call). Same pin in `mise.toml`.
- A govulncheck job, source mode, both `GOOS=darwin` and `GOOS=linux`, on the
  pinned toolchain, failing on reachable findings.
- A BPF regeneration job: regenerate with bpf2go on the runner and fail on
  any diff from the committed output. Only if regeneration is byte-for-byte
  deterministic across the dev VM and the runner; if it is not, report what
  differs instead of weakening the check.
- `-trimpath` on every release build.
- Fix the stale "dormant" header in `release.yml`.
- Checksum signing stays a separate decision.

**Verify.** Workflow syntax and SHA pins checked locally; govulncheck run
locally on go1.26.10 for both GOOS; the regeneration diff run in the dev VM
against the committed objects; the jobs pass on the branch push.

## RG-2: L5 + NEW-B4, the guest kernel floor

**Problem.** The gateway needs `SO_NETNS_COOKIE` (v5.14, e8b9eab99232, also
queued for some 5.12.y and 5.13.y stable kernels) and the agent has needed
5.8 since the tracker landed (NEW-B4). Doctor check 2, the docs and the README
still gate at 5.7, and plain `up` checks no kernel version at all. The agent
does refuse to load on an error or a zero cookie, so an unsupported kernel
fails at agent start with no up-front explanation.

**Change.** A feature probe, not a version compare (eval §Decisions). `up`
and doctor check 2 ask the guest whether `SO_NETNS_COOKIE` works and say so
plainly when it does not; a version check remains only as a fallback where no
probe can run, with 5.12/5.13 reported as "cannot confirm" rather than fail.
README and docs state the real floor. Doctor stays read-only.

**Verify.** Unit tests for the classifier; the probe run live in the dev VM
(kernel 6.8).

## RG-3: e2e helper hardening (`waitBindArbitrationLive`)

**Problem.** The helper (internal/e2e/e2e_test.go, since v0.0.1) picks one
Mac-free port and retries a guest bind on it for 20 s, discarding the probe's
error. On 2026-10-29 every try on :52954 failed although the agent answered
`ok` each time; the likely cause is a guest socket holding that port (it is in
the guest's ephemeral range, and forwarder connections arrive from guest
loopback ephemeral ports). Not reproduced on two re-runs.

**Change.** A fresh Mac-free port per attempt; on timeout, report the last
probe's errno and error.

**Verify.** `just e2e` passes repeatedly against the dev VM.

## RG-4: release notes and the last doc drift

**Change.** Draft `docs/releases/<next tag>.md` covering PR #1 and PR #2 for
users: the wrapper refresh on a plain `up` (P0-6), the upgrade path (`drawbridge
up <vm>` then `sudo drawbridge install` with no flags, which now keeps the
installed VM), L49 (the first restart onto the fd-store agent drops running
containers' listeners), the new fail-closed and root-only behaviors, and
RG-1/RG-2. Fix `docs/doctor.md:337`, which still quotes the agent-skew remedy
without the wrapper that `up` now refreshes. Written last, once RG-1 to RG-3
land. The tag name is the owner's call.

## Tracker

| Item | Findings | Model | Status | Commit | Mac validation | Guest | Notes |
|---|---|---|---|---|---|---|---|
| RG-1 | M28, NEW-T1, #11, #24 | Opus | open | | | | |
| RG-2 | L5, NEW-B4 | Opus | open | | | | |
| RG-3 | e2e helper | Sonnet | open | | | | |
| RG-4 | L49, release notes, doctor.md | Sonnet | open | | | | after RG-1 to RG-3 |

## Decisions log

| Date | Item | Decision | By |
|---|---|---|---|
| 2026-10-29 | E7 | Approved as recommended: exact Go patch for releases and mise, govulncheck and BPF-regeneration jobs (SHA-pinned), `-trimpath`; signing separate. | owner |
| 2026-10-29 | RG-1 | Pin go1.26.10, not 1.27: E7 approved "the current 1.26 patch"; 1.27 is a separate call. | lead |
