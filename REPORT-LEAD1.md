# [BOUNTY] SessionRouter — provider approval not bound to user

Severity: Medium. Program: Morpheus Bug Bounty Program ($100,000), v2. Venue: direct disclosure, devs@mor.org. PoC: https://github.com/kainze29/morpheus-sessionrouter-approval-poc

## TARGET

- Contract: `SessionRouter` facet of the Lumerin diamond on Base, `0x6aBE1d282f72B474E54527D93b979A4f64d3030a` (facet `0x3a3952F0e57B343F00B31f7da039Ef16389B7260`).
- Source: `MorpheusAIs/Morpheus-Lumerin-Node`, `smart-contracts/contracts/diamond/facets/SessionRouter.sol`, `_extractProviderApproval` (lines ~190-206), called from `openSession` (~95-120). The approval is built off-chain by `smart-contracts/utils/provider-helper.ts` (`getProviderApproval`): `msg = abi.encode(bidId, chainId, user.address, timestamp)`, `sig = provider.signMessage(keccak256(msg))`. The provider signs an approval for ONE specific user.
- Fork pin: Base block 59525896 (2026-11-19). MOR price $0.702784 (CoinGecko by contract address, 2026-11-19).

## INVARIANT

A provider approval signed for user A must only be usable to open a session for user A. The `address` field inside the signed approval exists precisely to bind it to that user.

## IMPACT

The invariant is broken. `_extractProviderApproval` decodes the address field and DISCARDS it:

```solidity
(bytes32 bidId_, uint256 chainId_, , uint128 timestamp_) = abi.decode(
    providerApproval_, (bytes32, uint256, address, uint128));
```

Only `chainId` and the 10-minute TTL (`SIGNATURE_TTL = 10 minutes`) are checked. The address is never compared to `user_`. Notably, the interface already defines `error SessionApprovedForAnotherUser();` but no implementation ever uses it: the intended check was never wired in.

Consequences: (a) a provider's per-user gating is defeated, an unapproved attacker receives compute service; (b) the intended user's open reverts, they must request a fresh approval. No user funds are directly stolen: the attacker pays their own stake (escrowed, returned on close when `isDirectPaymentFromUser` is false) and gas, and the provider is still paid. Quantified impact per stolen approval: one session of up to `maxSessionDuration` = 7 days (604,800 s), provider paid `duration x pricePerSecond` MOR from the compute pool. On-chain bid price bounds are 1e10-1e16 wei MOR/s, so one stolen approval is worth 0.006048-6,048 MOR ($0.004-$4,250 at $0.7028/MOR) of provider payment, depending on the bid. The victim loses one failed transaction (gas) plus a re-approval round trip. Medium because there is no direct token theft, but the allowlist bypass is complete and the griefing is reliable.

## PRECONDITIONS

- Attacker can observe a valid (approval, signature) pair before it is used (public mempool pending transaction, or any channel where the approval is transmitted).
- The approval is within its 10-minute TTL and not yet used (single-use: `isProviderApprovalUsed` is set on first successful open).
- The attacker holds MOR for their own session stake and a bid is active.

## ATTACK

1. Victim A requests a session approval from provider P (via the provider's proxy-router). P signs `(bidId, chainId, A, timestamp)`.
2. A submits `openSession(A, amount, false, approvalForA, sig)` to the mempool.
3. Attacker B sees the pending transaction, copies `approvalForA` and `sig`, submits `openSession(B, amount, false, approvalForA, sig)` with higher gas.
4. B's transaction is mined first. `_extractProviderApproval` returns the bidId, the signature recovers to P, the approval is marked used, and a session opens for B.
5. A's transaction reverts with `SessionDuplicateApproval`. A must request a new approval.

## POC

Full Foundry PoC (logic-level harness + live-diamond fork reproduction), 5/5 tests pass: https://github.com/kainze29/morpheus-sessionrouter-approval-poc

- `test/SessionRouterFork.t.sol`: fork Base at block 59525896, register provider + model + bid with keys I control, sign an approval for user A, call `openSession` as user B. Result: `SessionOpened` emitted for B (session `0x632f3b038b859cf89b0e9bc62a2cb6dd070f696abfe5f64665c262cfe5cd836a`), `getSession` shows `user == B`, `isActive == true`, `getIsProviderApprovalUsed(approval) == true`, B holds exactly 1 session and A holds 0, then A's `openSession` reverts with `SessionDuplicateApproval`. Run: `forge test --fork-url <base-rpc> --fork-block-number 59525896 -vvv` (full trace in `fork-test-output.txt`).
- `test/SessionRouterApproval.t.sol` + `src/SessionRouterHarness.sol`: logic-level PoC with `_extractProviderApproval` copied verbatim, 4/4 pass, including a control showing the one-line fix blocks B while A's own use still works.

## FIX

In `_extractProviderApproval`, return the decoded address and compare it to the session user in `openSession` (or pass `user_` into the extractor):

```solidity
(bytes32 bidId_, uint256 chainId_, address approvedUser_, uint128 timestamp_) =
    abi.decode(providerApproval_, (bytes32, uint256, address, uint128));
if (approvedUser_ != user_) revert SessionApprovedForAnotherUser();
```

(The error already exists in `ISessionRouter` and can be reused as-is.)
