// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PoolTest } from "../utils/PoolTest.sol";
import { PrivateSwap } from "../../src/examples/PrivateSwap.sol";
import { IShieldedPool, TransactPublic, ExtData } from "../../src/interfaces/IShieldedPool.sol";

/// @notice Example-composability tests: {PrivateSwap} atomically forwards TWO shielded legs
///         (cross-asset) to the real {ShieldedPool}. Proves the state machine, the hashlock +
///         timelock, cross-asset settlement, and — critically — all-or-nothing atomicity: if
///         the second leg reverts, the first is rolled back and nothing settles.
contract PrivateSwapTest is PoolTest {
    PrivateSwap internal swapC;

    bytes32 internal constant PREIMAGE = keccak256("swap-secret");
    bytes32 internal HASHLOCK = keccak256(abi.encodePacked(PREIMAGE));
    bytes32 internal constant SWAP = keccak256("swap-1");

    address internal partyA = makeAddr("partyA");
    address internal partyB = makeAddr("partyB");

    function setUp() public override {
        super.setUp();
        swapC = new PrivateSwap(IShieldedPool(address(pool)));
    }

    function _leg(uint256 assetId, uint256 root, address to, uint256 amount)
        internal
        returns (PrivateSwap.Leg memory leg)
    {
        leg.proof = PROOF;
        leg.pub.root = root;
        leg.pub.publicAsset = assetId;
        leg.pub.publicAmount = _publicAmount(-int256(amount), 0);
        leg.pub.nullifiers = _nullifiers(2);
        leg.pub.outputCommitments = _outputs();
        leg.ext = _extData(to, -int256(amount), address(0), 0);
    }

    function _open() internal {
        vm.prank(partyA);
        swapC.open(SWAP, partyA, partyB, HASHLOCK, uint64(block.timestamp + 1 days));
    }

    function test_execute_atomicCrossAssetSwap() public {
        // Seed both asset custodies + roots. A pays native→B, B pays token→A.
        _shieldNative(10 ether);
        _shieldToken(10 ether);
        uint256 root = pool.currentRoot();
        _open();

        PrivateSwap.Leg memory legA = _leg(nativeAssetId, root, partyB, 2 ether);
        PrivateSwap.Leg memory legB = _leg(tokenAssetId, root, partyA, 5 ether);

        uint256 bNative = partyB.balance;
        uint256 aToken = token.balanceOf(partyA);

        swapC.execute(SWAP, PREIMAGE, legA, legB);

        assertEq(partyB.balance - bNative, 2 ether, "B got native");
        assertEq(token.balanceOf(partyA) - aToken, 5 ether, "A got token");
        assertTrue(pool.isSpent(legA.pub.nullifiers[0]) && pool.isSpent(legB.pub.nullifiers[0]));
        assertEq(uint8(swapC.getSwap(SWAP).status), uint8(PrivateSwap.Status.Executed));
    }

    function test_execute_atomicity_badLegBRevertsWhole() public {
        _shieldNative(10 ether);
        _shieldToken(10 ether);
        uint256 root = pool.currentRoot();
        _open();

        PrivateSwap.Leg memory legA = _leg(nativeAssetId, root, partyB, 2 ether);
        PrivateSwap.Leg memory legB = _leg(tokenAssetId, root, partyA, 5 ether);
        // Make leg B invalid: unknown root → pool reverts UnknownRoot on the second leg.
        legB.pub.root = uint256(keccak256("not-a-root")) % P;

        uint256 bNative = partyB.balance;
        vm.expectRevert(); // UnknownRoot inside legB unwinds the whole execute
        swapC.execute(SWAP, PREIMAGE, legA, legB);

        // Nothing settled: leg A was rolled back with leg B.
        assertEq(partyB.balance, bNative, "no partial settlement");
        assertFalse(pool.isSpent(legA.pub.nullifiers[0]), "legA nullifier NOT spent");
        assertEq(uint8(swapC.getSwap(SWAP).status), uint8(PrivateSwap.Status.Open));
    }

    function test_execute_rejectsBadPreimage() public {
        _shieldNative(10 ether);
        _shieldToken(10 ether);
        uint256 root = pool.currentRoot();
        _open();
        PrivateSwap.Leg memory legA = _leg(nativeAssetId, root, partyB, 2 ether);
        PrivateSwap.Leg memory legB = _leg(tokenAssetId, root, partyA, 5 ether);

        vm.expectRevert(PrivateSwap.BadPreimage.selector);
        swapC.execute(SWAP, keccak256("nope"), legA, legB);
    }

    function test_execute_rejectedAfterDeadline() public {
        _shieldNative(10 ether);
        _shieldToken(10 ether);
        uint256 root = pool.currentRoot();
        _open();
        PrivateSwap.Leg memory legA = _leg(nativeAssetId, root, partyB, 2 ether);
        PrivateSwap.Leg memory legB = _leg(tokenAssetId, root, partyA, 5 ether);

        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(PrivateSwap.Expired.selector);
        swapC.execute(SWAP, PREIMAGE, legA, legB);
    }

    function test_open_rejectsSameParty() public {
        vm.prank(partyA);
        vm.expectRevert(PrivateSwap.SameParty.selector);
        swapC.open(SWAP, partyA, partyA, HASHLOCK, uint64(block.timestamp + 1 days));
    }

    function test_cancel_afterDeadline() public {
        _open();
        vm.warp(block.timestamp + 2 days);
        vm.prank(partyB);
        swapC.cancel(SWAP);
        assertEq(uint8(swapC.getSwap(SWAP).status), uint8(PrivateSwap.Status.Cancelled));
    }

    function test_cancel_rejectedBeforeDeadline() public {
        _open();
        vm.prank(partyA);
        vm.expectRevert(PrivateSwap.NotYetExpired.selector);
        swapC.cancel(SWAP);
    }

    function test_cancel_onlyCounterparty() public {
        _open();
        vm.warp(block.timestamp + 2 days);
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(PrivateSwap.NotCounterparty.selector);
        swapC.cancel(SWAP);
    }
}
