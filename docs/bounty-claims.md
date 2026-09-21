# SN118 bounty claims, reservations, and contributor identity

Status: **proposed**. This is the claim contract for the maintenance treasury in
[maintenance-treasury.md](maintenance-treasury.md). The parent epic is #2054.
#2046 owns acceptance and payout, and #2047 owns the board and contributor
guide.

A claim does one job: it binds a piece of scoped work to a verifiable subnet
identity and a payment destination, for a limited time, under rules that were
public before the work began. A claim does not approve work, promise payment,
or move funds.

## Principles

1. **The hotkey decides who you are; GitHub is only a label.** Every claim
   action is signed by a hotkey or by the coldkey that owns it on chain. A
   GitHub login is recorded for display and for linking PRs, but it can never
   choose, change, or approve a payment destination.
2. **Payment goes to the coldkey the chain says owns the hotkey.** The payee
   coldkey is signed into the claim and re-checked against
   `SubtensorModule.Owner` at payout time. The request can't simply assert it.
3. **Every signature is used once, for one purpose.** Each signature binds a
   domain tag, the netuid, the repository, the issue, the bounty revision, the
   contributor, a nonce, the time it was issued, and an expiry.
4. **The rules are fixed before work starts.** Concurrency mode, reservation
   length, renewal limits, and reward range are part of the signed bounty
   revision. Changing them creates a new revision, and existing claims keep the
   terms they signed.
5. **The Platform API is the only authority.** Claims are submitted to the
   Platform API and appended to the treasury ledger. GitHub comments and labels
   mirror that state. A signature pasted into a GitHub comment is not a claim.

These rules reuse the signed-action pattern already used for owner links
(`apps/platform/ditto/api_server/attestation.py`) and handle claims
(`apps/platform/ditto/api_server/name_claim.py`).

## The bounty revision

A bounty is identified as `{owner}/{repo}#{issue}`, for example
`ditto-assistant/ditto-subnet#2045`. Before it can be claimed, a maintainer
publishes a **bounty revision** through Platform. The revision is an integer
that starts at 1, plus a `spec_digest`: the SHA-256 of the canonical JSON of
these fields.

| Field | Meaning |
|---|---|
| `scope` | What is in and out of scope |
| `acceptance_evidence` | The objective evidence the reviewer will check (tests, receipts, live behavior) |
| `reward_min_tao`, `reward_max_tao` | The reward range, in TAO rao |
| `reviewer` | The named reviewer; must not be conflicted (see the treasury contract) |
| `dependencies` | Bounties or PRs that must land first |
| `bounty_expires_at` | After this time, no new claims or renewals |
| `concurrency` | `exclusive` or `open` (see [Concurrency](#concurrency)) |
| `max_open_claims` | For `open` only: the maximum number of simultaneous reservations |
| `reservation_days` | Length of the first reservation and of each renewal (default 7) |
| `max_renewals` | Renewals allowed without reviewer approval (default 2) |
| `policy_revision` | The treasury policy revision this bounty is governed by |

The board (#2047) shows the revision and the digest on the issue. Editing the
issue text does not change the terms: only a new Platform revision does. That
new revision applies to new claims, and to existing claimants only when they
opt in by renewing against it.

## Identity

- **Claimant hotkey.** Any hotkey with an on-chain owner. At a finalized block,
  `SubtensorModule.Owner(hotkey)` must resolve to a coldkey. An SN118 UID is
  **not** required, so outside contributors don't need to buy a registration
  (decision C1).
- **Payee coldkey.** It must equal `Owner(claimant_hotkey)` at the claim block,
  and it is signed into the claim. At payout, #2046 checks `Owner` again. If
  ownership has moved, payment is blocked until the contributor completes a
  [payee rebind](#example-key-rotation-payee-rebind).
- **Key kind.** Each action is proved with the hotkey itself or with its
  on-chain owner coldkey. Handle claims use the payment-record coldkey instead,
  but outside contributors have no payment record, and the chain owner is
  authoritative anyway.
- **GitHub login.** It is signed into the claim so reviewers can match PRs to
  claimants. A PR opened by another account is still linkable through a signed
  `submit` action. A PR opened by the claimed login but never signed-linked is
  not submitted work.
- **Teams.** A team claim names one payee coldkey and lists its members. Each
  member signs a membership half over the team digest. The payee and the members
  are public. Working as a team is allowed and expected; an undisclosed payee is
  what counts as a conflict.

## Signed actions

Each action signs the exact UTF-8 bytes of its fields joined by `:`. The
format matches `claim_message` in `name_claim.py`:

- `issued_at` and the expiry timestamps are UTC ISO-8601 with microseconds.
- `nonce` is a UUIDv4.
- `key_kind` is `hotkey` or `coldkey`.
- `signer` is the SS58 address that signed.
- `repo` is `owner/name`. GitHub logins and repository names can't contain `:`.

Platform never parses a message it receives. It rebuilds the bytes from the
structured request fields and checks the signature against them.

| Action | Domain | Fields after the domain |
|---|---|---|
| Claim | `ditto-bounty-claim:v1` | `netuid:repo:issue:bounty_revision:spec_digest:claimant_hotkey:payee_coldkey:github_login:team_digest:reservation_expires_at:nonce:issued_at:key_kind:signer` |
| Team member | `ditto-bounty-member:v1` | `netuid:repo:issue:bounty_revision:team_digest:member_hotkey:nonce:issued_at:key_kind:signer` |
| Renew | `ditto-bounty-renew:v1` | `netuid:claim_id:claimant_hotkey:bounty_revision:spec_digest:reservation_expires_at:nonce:issued_at:key_kind:signer` |
| Submit (link PR) | `ditto-bounty-submit:v1` | `netuid:claim_id:claimant_hotkey:repo:pr_number:head_sha:nonce:issued_at:key_kind:signer` |
| Handoff half | `ditto-bounty-handoff:v1` | `netuid:claim_id:from_hotkey:to_hotkey:to_payee_coldkey:nonce:issued_at:side:key_kind:signer` |
| Withdraw | `ditto-bounty-withdraw:v1` | `netuid:claim_id:claimant_hotkey:nonce:issued_at:key_kind:signer` |
| Payee rebind | `ditto-bounty-payee:v1` | `netuid:claim_id:claimant_hotkey:old_payee_coldkey:new_payee_coldkey:nonce:issued_at:key_kind:signer` |
| Appeal | `ditto-bounty-appeal:v1` | `netuid:claim_id:claimant_hotkey:subject_entry_hash:reason_digest:nonce:issued_at:key_kind:signer` |

Notes:

- `team_digest` is the SHA-256 of canonical JSON
  `{"payee_coldkey": ..., "members": [{"hotkey": ..., "github_login": ...}, ...]}`,
  with members sorted by hotkey. A solo claim uses the digest of a one-member
  team, so every claim has the same shape.
- `claim_id` is the server-issued UUID returned by the claim. Every follow-up
  action binds it, so a signature for one claim can't be reused on another.
  This is the same approach as `ditto-name-endorse:v1` and
  `ditto-name-withdraw:v1`.
- `head_sha` binds the exact commit submitted for review. #2046 approves that
  commit, not a branch name that can be rewritten.
- `side` is `from` or `to`. A handoff needs **both** halves, just as an owner
  link needs both endpoints. That way no one can hand themselves someone else's
  reservation, and no one can be handed work they didn't accept.
- `subject_entry_hash` is the treasury ledger entry being appealed, for example
  a revocation. `reason_digest` is the SHA-256 of the appeal text, which is
  stored beside the entry.

### Replay protection

| Guard | Rule |
|---|---|
| Domain tag and version | A signature can't be replayed into the upload, owner-link, name-claim, or validator lanes |
| `netuid` | A signature from another deployment is rejected |
| Repository, issue, bounty revision, `spec_digest` | A claim can't be moved to another bounty or to changed terms |
| `claim_id` | Follow-up actions can't be moved to another claim |
| `nonce` | Unique across **all** bounty actions (one table with a unique constraint). A second submission gets `409` |
| `issued_at` | Uses the owner-link window: at most `MAX_ISSUED_AT_SKEW` (5 minutes) in the future, and at most `MAX_ATTESTATION_AGE` (24 hours) old |
| `reservation_expires_at` | Must be at most `reservation_days` after the server's accept time and no later than `bounty_expires_at`. The server stores the earlier of the signed and computed expiry |

## Reservations

### States

```
active ──submit──▶ submitted ──▶ (acceptance and payout: #2046)
  │  ▲                │
  │  └──renew         └──changes requested──▶ active (clock restarts)
  ├──▶ expired
  ├──▶ withdrawn
  ├──▶ revoked (audited reason; appealable)
  └──▶ handed_off (a new active claim for the recipient)
```

- **Accepted claim.** The server verifies the signature, identity, freshness,
  nonce, and concurrency rules. It then appends a `reservation` entry to the
  treasury ledger and returns `claim_id`. The entry records the bounty revision
  and digest, both keys, the GitHub login, the team, and the expiry.
- **Renew.** Allowed only in the last 48 hours before expiry, at most
  `max_renewals` times. More renewals need reviewer approval, recorded with the
  reviewer as actor. Renewing against a newer bounty revision is how a claimant
  accepts its terms.
- **Submit.** Links a PR and its exact head commit, and pauses the expiry
  clock. Review delay is the reviewer's responsibility, not the contributor's.
  If the reviewer requests changes, the claim goes back to `active` with a fresh
  `reservation_days` window.
- **Expire.** Handled by the server clock. The reservation is released and the
  ledger records `reservation_release` with reason `expired`. The same payee
  coldkey can't claim the same bounty again for 72 hours, so a contributor
  can't squat on a bounty by cycling hotkeys.
- **Withdraw.** Signed by the claimant, and takes effect immediately.
- **Revoke.** Done by a maintainer, with a reason from a fixed set and free
  text. The reasons are `inactive`, `scope_violation`, `undisclosed_conflict`,
  `misconduct`, `bounty_cancelled`, and `superseded_by_revision`. Revocation
  appends a ledger entry with actor and reason and can be appealed. A GitHub
  label change is never a revocation.

### Concurrency

The bounty revision shows its mode on the board before anyone starts work.

- **`exclusive`** (default): one `active` or `submitted` reservation per bounty.
  A partial unique index in the database enforces this, the same way active
  handle claims are enforced, so the rule doesn't depend on application logic.
  A second claim gets `409` with the holder's public reservation and its expiry.
- **`open`**: up to `max_open_claims` concurrent reservations. Proposals compete.
  The reviewer accepts one, or makes partial or shared awards under #2046. The
  other reservations are released with reason `superseded`. That is not a
  rejection of the contributor.
- **Per-payee limit:** at most two `exclusive` reservations in `active` state
  per payee coldkey. `open` claims and `submitted` claims don't count.

### Public visibility

The bounty's public reservation view lists:

- claim ID, state, and expiry;
- claimant hotkey, payee coldkey, and GitHub login;
- team members;
- the bounty revision;
- the linked PR and its head commit.

These are already public on chain or on GitHub. The board (#2047) reads this
view to answer "stale" and "blocked" queries. Appeal text is published only if
the appellant chooses to.

## Examples

The CLI surface proposed below follows `ditto name`. It prints every key and
digest before asking for confirmation, and signing never transfers TAO. The
addresses are Substrate development keys used for illustration only.

### Example: claim

```sh
uv run ditto --network finney bounty claim \
  --repo ditto-assistant/ditto-subnet --issue 2045 --revision 1 \
  --coldkey alice --hotkey default --github-login alice-dev
```

Signed bytes (one line):

```
ditto-bounty-claim:v1:118:ditto-assistant/ditto-subnet:2045:1:<spec_digest>:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY:5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty:alice-dev:<team_digest>:2026-09-28T12:00:00.000000+00:00:1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b:2026-09-21T12:00:00.000000+00:00:hotkey:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
```

Platform then checks these, in order:

1. `Owner(5Grw…)` equals `5FHn…` at a finalized block.
2. The bounty revision 1 digest matches.
3. The bounty is `exclusive` and has no live reservation.
4. The nonce is unused.

It returns `claim_id` and the ledger entry hash. The board mirrors the issue to
**Claimed**.

### Example: renew

Within 48 hours of expiry:

```sh
uv run ditto --network finney bounty renew --claim-id <claim_id> \
  --coldkey alice --hotkey default
```

This signs `ditto-bounty-renew:v1:118:<claim_id>:5Grw…:1:<spec_digest>:<new_expires_at>:…`.
The third renewal is refused with `reviewer approval required` unless the
reviewer has recorded an extension.

### Example: submit a PR

```sh
uv run ditto --network finney bounty submit --claim-id <claim_id> \
  --pr 2061 --head-sha 3f9c2a1… --coldkey alice --hotkey default
```

The reservation moves to `submitted`. If a new commit is pushed after
submitting, the contributor must submit again with the new `head_sha`.
Otherwise the reviewer reviews the commit that was signed.

### Example: handoff

Alice can't finish, and Bob agrees to take over:

```sh
# Alice signs the "from" half and shares the printed JSON with Bob.
uv run ditto --network finney bounty handoff --claim-id <claim_id> --side from \
  --to-hotkey 5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y \
  --coldkey alice --hotkey default
# Bob signs the "to" half and submits both halves.
uv run ditto --network finney bounty handoff --claim-id <claim_id> --side to \
  --from-hotkey 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY \
  --coldkey bob --hotkey default --submit
```

Alice's claim becomes `handed_off`. Bob gets a new `active` claim with a fresh
expiry, on the same bounty revision. Alice's work before the handoff is not
paid automatically. The reviewer may propose a shared award under #2046, and
both parties see that decision in the ledger.

### Example: appeal a revocation

```sh
uv run ditto --network finney bounty appeal --claim-id <claim_id> \
  --entry <revocation_entry_hash> --reason-file appeal.md \
  --coldkey alice --hotkey default
```

The appeal is assigned to a maintainer who didn't make the revocation and isn't
conflicted, and it must be decided within 14 days. The decision is a
`dispute_resolution` ledger entry that references the revocation. If upheld,
the reservation is restored with its remaining time plus the time the appeal
took.

### Example: key rotation (payee rebind)

Alice moves her hotkey to a new coldkey, so `Owner` has changed. A payout
against the old payee is blocked. Alice signs with the **new** owner coldkey:

```sh
uv run ditto --network finney bounty rebind-payee --claim-id <claim_id> \
  --coldkey alice-new --hotkey default --key-kind coldkey
```

Platform accepts the rebind only if the signer is `Owner(hotkey)` at a
finalized block and the old payee in the message matches the recorded one. If
Alice rotated the *hotkey* instead, the old claim is handed off from the old
hotkey to the new one, with both halves signed.

## Threat model

| Threat | Mitigation |
|---|---|
| GitHub account takeover redirects payment | The payee comes from the signed claim and the chain `Owner`. GitHub can't sign a submit, handoff, or rebind |
| Replay of a captured claim or follow-up action | Domain, netuid, bounty revision, digest, claim ID, a nonce that can't be reused, and a 24-hour freshness window |
| Terms changed after work began | The claim binds `spec_digest`. New revisions apply only when the claimant opts in by renewing |
| Squatting on bounties | Limited reservation length, renewal limits, a limit on exclusive claims per payee, and a 72-hour cooldown after expiry keyed on the payee coldkey |
| Someone takes over another person's reservation | A handoff needs both halves. Revocation needs an audited maintainer action and can be appealed |
| A PR is rewritten after review | `submit` binds `head_sha`. New commits need a new signed submit |
| A hotkey or coldkey leaks | The attacker can claim or withdraw, but the payee stays `Owner(hotkey)`. Rotating on chain and rebinding moves the payee, and the payout check blocks mismatches |
| Undisclosed shared payee | The team digest and payee are public, and conflict findings are ledger entries |

## Acceptance mapping (#2045)

| Acceptance item | Where it is satisfied |
|---|---|
| Claims can't be replayed and are bound to repository, issue, contributor, revision, and expiry | [Signed actions](#signed-actions), [Replay protection](#replay-protection) |
| GitHub identity alone can't redirect payment | Principles 1–2, [Identity](#identity), payee rebind, threat model |
| Reservation and concurrency rules are visible before work begins | [The bounty revision](#the-bounty-revision), [Concurrency](#concurrency), [Public visibility](#public-visibility) |
| Claim, renew, handoff, and appeal examples are documented | [Examples](#examples) |

## Decisions that need approval

- **C1:** whether any chain-owned hotkey may claim, or only SN118-registered
  hotkeys. The first is recommended, so outside contributors can take part.
- **C2:** default `reservation_days` (7), `max_renewals` (2), the per-payee limit
  on exclusive claims (2), and the cooldown after expiry (72 hours).
- **C3:** whether `exclusive` is the default mode, or `open` for documentation
  and incident bounties.

## Implementation handoff

A single Platform and CLI stack implements this contract:

- a `bounty_claims` table with a status `CHECK`, paired timestamps, and a
  partial unique index for `exclusive` bounties;
- a nonce table shared by every bounty action;
- message builders and verification, reusing `verify_signature` and the
  owner-link freshness constants;
- the `ditto bounty` CLI;
- ledger appends for each action;
- a public reservation read;
- Backroom MCP read tools for reservations, revocations, and appeals.

Payout-time `Owner` re-checks and acceptance live in #2046.
