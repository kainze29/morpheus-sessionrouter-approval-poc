// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SessionRouterHarness
/// @notice Logic-level reproduction of the provider-approval validation from
/// Morpheus Lumerin SessionRouter (Base diamond 0x6aBE1d282f72B474E54527D93b979A4f64d3030a).
/// `_extractProviderApproval` and `_isValidProviderReceipt` are copied VERBATIM
/// from contracts/diamond/facets/SessionRouter.sol (only the storage reads are
/// replaced by the mock mappings below, so the contract runs standalone).
/// The point of the harness: prove that the `address` field inside a provider
/// approval is decoded and then DISCARDED, so an approval signed for user A
/// is accepted when user B opens a session with it.
contract SessionRouterHarness {
    uint32 public constant SIGNATURE_TTL = 10 minutes; // SessionStorage.sol:35

    // ---- mock diamond storage (replaces LibSessionRouter / LibMarketplace reads) ----
    mapping(bytes => bool) public isProviderApprovalUsed;
    mapping(bytes32 => address) public bidProvider;
    mapping(bytes32 => bool) public bidActive;
    mapping(bytes32 => address) public sessionUser;
    uint256 public sessionNonce;

    error SessionApprovedForAnotherChainId();
    error SessionApproveExpired();
    error SessionProviderSignatureMismatch();
    error SessionDuplicateApproval();
    error SessionBidNotFound();
    error SessionApprovalNotForUser(address expected, address actual); // only used by the FIXED variant

    function mockSetBid(bytes32 bidId_, address provider_) external {
        bidProvider[bidId_] = provider_;
        bidActive[bidId_] = true;
    }

    // ---- VERBATIM from SessionRouter.sol (lines ~190-206) ----
    // NOTE the third decoded element (address) is bound to nothing and discarded.
    function _extractProviderApproval(bytes calldata providerApproval_) private view returns (bytes32) {
        (bytes32 bidId_, uint256 chainId_, , uint128 timestamp_) = abi.decode(
            providerApproval_,
            (bytes32, uint256, address, uint128)
        );
        if (chainId_ != block.chainid) revert SessionApprovedForAnotherChainId();
        if (block.timestamp > timestamp_ + SIGNATURE_TTL) revert SessionApproveExpired();
        return bidId_;
    }

    // ---- VERBATIM from SessionRouter.sol (lines ~537-548), delegation branch omitted ----
    function _isValidProviderReceipt(
        address provider_,
        bytes calldata receipt_,
        bytes calldata signature_
    ) private pure returns (bool) {
        bytes32 receiptHash_ = _toEthSignedMessageHash(keccak256(receipt_));
        address signer_ = _recover(receiptHash_, signature_);
        return signer_ == provider_;
    }

    // OpenZeppelin ECDSA.toEthSignedMessageHash(bytes32) + ECDSA.recover, inlined
    // so this harness needs no external dependency.
    function _toEthSignedMessageHash(bytes32 hash_) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash_));
    }

    function _recover(bytes32 hash_, bytes calldata signature_) private pure returns (address) {
        require(signature_.length == 65, "bad sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature_.offset)
            s := calldataload(add(signature_.offset, 0x20))
            v := byte(0, calldataload(add(signature_.offset, 0x40)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "bad v");
        return ecrecover(hash_, v, r, s);
    }

    /// @notice Mirrors openSession() validation order (SessionRouter.sol ~lines 95-120),
    /// minus the token transfer and the delegatee check (caller == user_ is enforced
    /// by the test via vm.prank, same as the real contract's _validateDelegatee).
    /// The `user_` argument is the session owner. The approval's embedded address
    /// is NEVER compared to `user_`.
    function openSession(
        address user_,
        bytes calldata approvalEncoded_,
        bytes calldata signature_
    ) external returns (bytes32) {
        bytes32 bidId_ = _extractProviderApproval(approvalEncoded_);
        if (!bidActive[bidId_]) revert SessionBidNotFound();
        if (!_isValidProviderReceipt(bidProvider[bidId_], approvalEncoded_, signature_)) {
            revert SessionProviderSignatureMismatch();
        }
        if (isProviderApprovalUsed[approvalEncoded_]) revert SessionDuplicateApproval();

        bytes32 sessionId_ = keccak256(abi.encodePacked(user_, bidProvider[bidId_], bidId_, sessionNonce++));
        sessionUser[sessionId_] = user_;
        isProviderApprovalUsed[approvalEncoded_] = true;
        return sessionId_;
    }

    /// @notice Same as openSession(), but with the one-line fix: the approval's
    /// embedded address MUST equal the session user. Used as the control case.
    function openSessionFixed(
        address user_,
        bytes calldata approvalEncoded_,
        bytes calldata signature_
    ) external returns (bytes32) {
        (bytes32 bidId_, uint256 chainId_, address approvedUser_, uint128 timestamp_) = abi.decode(
            approvalEncoded_,
            (bytes32, uint256, address, uint128)
        );
        if (chainId_ != block.chainid) revert SessionApprovedForAnotherChainId();
        if (block.timestamp > timestamp_ + SIGNATURE_TTL) revert SessionApproveExpired();
        if (approvedUser_ != user_) revert SessionApprovalNotForUser(approvedUser_, user_);
        if (!bidActive[bidId_]) revert SessionBidNotFound();
        if (!_isValidProviderReceipt(bidProvider[bidId_], approvalEncoded_, signature_)) {
            revert SessionProviderSignatureMismatch();
        }
        if (isProviderApprovalUsed[approvalEncoded_]) revert SessionDuplicateApproval();

        bytes32 sessionId_ = keccak256(abi.encodePacked(user_, bidProvider[bidId_], bidId_, sessionNonce++));
        sessionUser[sessionId_] = user_;
        isProviderApprovalUsed[approvalEncoded_] = true;
        return sessionId_;
    }
}
