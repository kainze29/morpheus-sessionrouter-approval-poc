# Morpheus SessionRouter — provider approval not bound to user

Foundry PoC for a Medium-severity bug in the Morpheus Lumerin diamond on Base
(`0x6aBE1d282f72B474E54527D93b979A4f64d3030a`): a provider approval is signed for
ONE specific user (`msg = abi.encode(bidId, chainId, user, timestamp)`), but
`SessionRouter._extractProviderApproval` decodes the address field and discards
it, checking only `chainId` and the 10-minute TTL. Anyone who observes a valid
(approval, signature) pair — e.g. in the public mempool — can front-run the
intended user and open a session for THEMSELVES with it. The approval is
single-use, so the victim's own call then reverts with `SessionDuplicateApproval`.
No user funds are directly stolen; the provider's per-user gating is defeated and
the victim is griefed. The full one-page report is in `REPORT-LEAD1.md`.

## Contents

- `src/SessionRouterHarness.sol` — `_extractProviderApproval` and
  `_isValidProviderReceipt` copied verbatim from `SessionRouter.sol` (storage
  reads replaced by mock mappings), plus a fixed variant for the control test.
- `test/SessionRouterApproval.t.sol` — logic-level PoC, 4/4 pass.
- `test/SessionRouterFork.t.sol` — full reproduction against the LIVE diamond on
  a Base fork (block 59525896): registers a provider + model + bid, signs an
  approval for user A, opens a session as user B, then shows A's call reverting.
- `fork-test-output.txt` — full `forge test -vvvv` trace of the fork run.
- `REPORT-LEAD1.md` — the one-page report (TARGET / INVARIANT / IMPACT /
  PRECONDITIONS / ATTACK / POC / FIX).

## Run

```bash
# logic-level PoC (no RPC needed)
forge test --match-contract SessionRouterApprovalTest

# live-diamond fork reproduction (needs a Base RPC URL)
forge test --match-contract SessionRouterForkTest \
  --fork-url <base-rpc> --fork-block-number 59525896 -vvv
```

Requires [Foundry](https://getfoundry.sh/). `forge-std` is vendored under `lib/`.
