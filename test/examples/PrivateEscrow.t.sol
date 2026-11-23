// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PoolTest } from "../utils/PoolTest.sol";
import { PrivateEscrow } from "../../src/examples/PrivateEscrow.sol";
import { IShieldedPool, TransactPublic, ExtData } from "../../src/interfaces/IShieldedPool.sol";

/// @notice Example-composability tests: {PrivateEscrow} genuinely drives the real
///         {ShieldedPool} (wired to mock verifiers, as the Ring tests are) — it proves the
///         state machine (Open → Funded → Claimed|Refunded), the hashlock + timelock gates,
///         and that a successful claim/refund forwards a real join-split that spends
///         nullifiers and settles a withdrawal in the pool.
contract PrivateEscrowTest is PoolTest {
    PrivateEscrow internal escrow;

    bytes32 internal constant PREIMAGE = keccak256("deal-secret");
    bytes32 internal HASHLOCK = keccak256(abi.encodePacked(PREIMAGE));
    bytes32 internal constant DEAL = keccak256("deal-1");

    address internal depositor = makeAddr("depositor");
    address internal beneficiary = makeAddr("beneficiary");

    function setUp() public override {
        super.setUp();
        escrow = new PrivateEscrow(IShieldedPool(address(pool)));
    }

    /// @dev Build a withdraw-to-`to` join-split against the current pool root. With the mock
    ///      verifier this settles when forwarded; it represents the escrow's pre-built leg.
    function _leg(address to, uint256 amount)
        internal
        returns (bytes memory proof, TransactPublic memory pub, ExtData memory ext)
    {
        pub.root = pool.currentRoot();
        pub.publicAsset = nativeAssetId;
        pub.publicAmount = _publicAmount(-int256(amount), 0);
        pub.nullifiers = _nullifiers(2);
        pub.outputCommitments = _outputs();
        ext = _extData(to, -int256(amount), address(0), 0);
        proof = PROOF;
    }

    function _open() internal {
        vm.prank(depositor);
        escrow.open(DEAL, beneficiary, HASHLOCK, uint64(block.timestamp + 1 days));
    }

    function test_open_setsDealOpen() public {
        _open();
        PrivateEscrow.Deal memory d = escrow.getDeal(DEAL);
        assertEq(d.depositor, depositor);
        assertEq(d.beneficiary, beneficiary);
        assertEq(uint8(d.status), uint8(PrivateEscrow.Status.Open));
    }

    function test_open_rejectsDuplicate() public {
        _open();
        vm.prank(depositor);
        vm.expectRevert(PrivateEscrow.DealExists.selector);
        escrow.open(DEAL, beneficiary, HASHLOCK, uint64(block.timestamp + 1 days));
    }

    function test_open_rejectsPastDeadline() public {
        vm.prank(depositor);
        vm.expectRevert(PrivateEscrow.DeadlineInPast.selector);
        escrow.open(DEAL, beneficiary, HASHLOCK, uint64(block.timestamp));
    }

    function test_fund_onlyDepositor() public {
        _open();
        vm.prank(beneficiary);
        vm.expectRevert(PrivateEscrow.NotDepositor.selector);
        escrow.fund(DEAL, 0x1234);
    }

    function test_claim_releasesToBeneficiary() public {
        // Seed the pool with custody + a real root the leg spends against.
        _shieldNative(10 ether);
        _open();
        vm.prank(depositor);
        escrow.fund(DEAL, 0xabcd);

        (bytes memory proof, TransactPublic memory pub, ExtData memory ext) =
            _leg(beneficiary, 3 ether);

        uint256 balBefore = beneficiary.balance;
        // Anyone holding the preimage can claim (standard HTLC).
        escrow.claim(DEAL, PREIMAGE, proof, pub, ext);

        assertEq(beneficiary.balance - balBefore, 3 ether, "beneficiary paid");
        assertTrue(pool.isSpent(pub.nullifiers[0]), "nullifier spent in pool");
        assertEq(uint8(escrow.getDeal(DEAL).status), uint8(PrivateEscrow.Status.Claimed));
    }

    function test_claim_rejectsBadPreimage() public {
        _shieldNative(10 ether);
        _open();
        vm.prank(depositor);
        escrow.fund(DEAL, 0xabcd);
        (bytes memory proof, TransactPublic memory pub, ExtData memory ext) =
            _leg(beneficiary, 3 ether);

        vm.expectRevert(PrivateEscrow.BadPreimage.selector);
        escrow.claim(DEAL, keccak256("wrong"), proof, pub, ext);
    }

    function test_claim_requiresFunded() public {
        _shieldNative(10 ether);
        _open(); // not funded
        (bytes memory proof, TransactPublic memory pub, ExtData memory ext) =
            _leg(beneficiary, 3 ether);
        vm.expectRevert(PrivateEscrow.DealNotFunded.selector);
        escrow.claim(DEAL, PREIMAGE, proof, pub, ext);
    }

    function test_claim_rejectedAfterDeadline() public {
        _shieldNative(10 ether);
        _open();
        vm.prank(depositor);
        escrow.fund(DEAL, 0xabcd);
        (bytes memory proof, TransactPublic memory pub, ExtData memory ext) =
            _leg(beneficiary, 3 ether);

        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(PrivateEscrow.Expired.selector);
        escrow.claim(DEAL, PREIMAGE, proof, pub, ext);
    }

    function test_claim_cannotClaimTwice() public {
        _shieldNative(10 ether);
        _open();
        vm.prank(depositor);
        escrow.fund(DEAL, 0xabcd);
        (bytes memory proof, TransactPublic memory pub, ExtData memory ext) =
            _leg(beneficiary, 3 ether);
        escrow.claim(DEAL, PREIMAGE, proof, pub, ext);

        (bytes memory p2, TransactPublic memory pub2, ExtData memory ext2) =
            _leg(beneficiary, 1 ether);
        vm.expectRevert(PrivateEscrow.DealNotFunded.selector);
        escrow.claim(DEAL, PREIMAGE, p2, pub2, ext2);
    }

    function test_refund_afterDeadline() public {
        _shieldNative(10 ether);
        _open();
        vm.prank(depositor);
        escrow.fund(DEAL, 0xabcd);
        (bytes memory proof, TransactPublic memory pub, ExtData memory ext) =
            _leg(depositor, 4 ether);

        vm.warp(block.timestamp + 2 days);
        uint256 balBefore = depositor.balance;
        vm.prank(depositor);
        escrow.refund(DEAL, proof, pub, ext);

        assertEq(depositor.balance - balBefore, 4 ether, "depositor refunded");
        assertEq(uint8(escrow.getDeal(DEAL).status), uint8(PrivateEscrow.Status.Refunded));
    }

    function test_refund_rejectedBeforeDeadline() public {
        _shieldNative(10 ether);
        _open();
        vm.prank(depositor);
        escrow.fund(DEAL, 0xabcd);
        (bytes memory proof, TransactPublic memory pub, ExtData memory ext) =
            _leg(depositor, 4 ether);

        vm.prank(depositor);
        vm.expectRevert(PrivateEscrow.NotYetExpired.selector);
        escrow.refund(DEAL, proof, pub, ext);
    }

    function test_refund_onlyDepositor() public {
        _shieldNative(10 ether);
        _open();
        vm.prank(depositor);
        escrow.fund(DEAL, 0xabcd);
        (bytes memory proof, TransactPublic memory pub, ExtData memory ext) =
            _leg(depositor, 4 ether);

        vm.warp(block.timestamp + 2 days);
        vm.prank(beneficiary);
        vm.expectRevert(PrivateEscrow.NotDepositor.selector);
        escrow.refund(DEAL, proof, pub, ext);
    }
}
