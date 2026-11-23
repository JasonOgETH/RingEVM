// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PoolTest } from "./utils/PoolTest.sol";
import { ShieldedPool } from "../src/ShieldedPool.sol";
import { IShieldedPool, TransactPublic, ExtData } from "../src/interfaces/IShieldedPool.sol";
import { Field } from "../src/libraries/Field.sol";
import { MockERC20, FeeOnTransferERC20, ReentrantRecipient } from "./utils/Mocks.sol";

contract ShieldedPoolTest is PoolTest {
    // ------------------------------------------------------------------
    // registration
    // ------------------------------------------------------------------

    function test_NativePreregistered() public view {
        (address t, bool reg) = pool.tokenForAsset(nativeAssetId);
        assertEq(t, address(0));
        assertTrue(reg);
    }

    function test_RegisterAsset_Idempotent() public {
        uint256 id1 = pool.registerAsset(address(token));
        uint256 id2 = pool.registerAsset(address(token));
        assertEq(id1, id2);
        assertEq(id1, tokenAssetId);
        (address t, bool reg) = pool.tokenForAsset(id1);
        assertEq(t, address(token));
        assertTrue(reg);
    }

    // ------------------------------------------------------------------
    // shield
    // ------------------------------------------------------------------

    function test_ShieldNative_HappyPath() public {
        uint256 amount = 5 ether;
        uint256 commitment = _uniq();

        assertEq(pool.nextLeafIndex(), 0);
        vm.expectEmit(true, false, false, true, address(pool));
        emit IShieldedPool.Commitment(0, commitment, "");

        vm.prank(alice);
        pool.shield{ value: amount }(PROOF, nativeAssetId, amount, commitment, "");

        assertEq(address(pool).balance, amount);
        assertEq(pool.custodyOf(nativeAssetId), amount);
        assertEq(pool.nextLeafIndex(), 1);
        assertTrue(pool.isKnownRoot(pool.currentRoot()));
    }

    function test_ShieldToken_HappyPath() public {
        uint256 amount = 100 ether;
        uint256 commitment = _uniq();
        uint256 balBefore = token.balanceOf(alice);

        vm.startPrank(alice);
        token.approve(address(pool), amount);
        pool.shield(PROOF, tokenAssetId, amount, commitment, "");
        vm.stopPrank();

        assertEq(token.balanceOf(address(pool)), amount);
        assertEq(token.balanceOf(alice), balBefore - amount);
        assertEq(pool.custodyOf(tokenAssetId), amount);
    }

    function test_Shield_RevertsZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.ZeroAmount.selector);
        pool.shield{ value: 0 }(PROOF, nativeAssetId, 0, _uniq(), "");
    }

    function test_Shield_RevertsAmountTooLarge() public {
        uint256 big = Field.AMOUNT_MAX; // == 2^128, not < 2^128
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.AmountTooLarge.selector);
        pool.shield(PROOF, tokenAssetId, big, _uniq(), "");
    }

    function test_Shield_RevertsUnregisteredAsset() public {
        uint256 bogus = _uniq();
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.AssetNotRegistered.selector);
        pool.shield{ value: 1 ether }(PROOF, bogus, 1 ether, _uniq(), "");
    }

    function test_Shield_RevertsNativeValueMismatch() public {
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.NativeValueMismatch.selector);
        pool.shield{ value: 1 ether }(PROOF, nativeAssetId, 2 ether, _uniq(), "");
    }

    function test_Shield_RevertsUnexpectedNativeValueForToken() public {
        vm.startPrank(alice);
        token.approve(address(pool), 1 ether);
        vm.expectRevert(ShieldedPool.UnexpectedNativeValue.selector);
        pool.shield{ value: 1 ether }(PROOF, tokenAssetId, 1 ether, _uniq(), "");
        vm.stopPrank();
    }

    function test_Shield_RevertsOnBadProof() public {
        vShield.setResult(false);
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.shield{ value: 1 ether }(PROOF, nativeAssetId, 1 ether, _uniq(), "");
    }

    function test_Shield_RejectsFeeOnTransferToken() public {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20(100); // 1%
        uint256 fotAsset = pool.registerAsset(address(fot));
        fot.mint(alice, 1_000 ether);

        vm.startPrank(alice);
        fot.approve(address(pool), 100 ether);
        vm.expectRevert(ShieldedPool.FeeOnTransferToken.selector);
        pool.shield(PROOF, fotAsset, 100 ether, _uniq(), "");
        vm.stopPrank();
    }

    // ------------------------------------------------------------------
    // deposit-only circuit breaker + caps
    // ------------------------------------------------------------------

    function test_PauseDeposits_BlocksShield() public {
        vm.prank(guardian);
        pool.pauseDeposits();

        vm.prank(alice);
        vm.expectRevert(ShieldedPool.DepositsPaused.selector);
        pool.shield{ value: 1 ether }(PROOF, nativeAssetId, 1 ether, _uniq(), "");
    }

    function test_Pause_OnlyGuardian() public {
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.NotGuardian.selector);
        pool.pauseDeposits();
    }

    function test_DepositCap_Enforced() public {
        vm.prank(guardian);
        pool.setDepositCap(nativeAssetId, 3 ether);

        _shieldNative(2 ether);

        vm.prank(alice);
        vm.expectRevert(ShieldedPool.DepositCapExceeded.selector);
        pool.shield{ value: 2 ether }(PROOF, nativeAssetId, 2 ether, _uniq(), "");
    }

    // ------------------------------------------------------------------
    // transact — internal transfer
    // ------------------------------------------------------------------

    function test_Transact_InternalTransfer() public {
        _shieldNative(10 ether);
        uint256 root = pool.currentRoot();

        TransactPublic memory pub = TransactPublic({
            root: root,
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(0, 0),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        ExtData memory ext = _extData(address(0), 0, address(0), 0);

        uint256 custodyBefore = pool.custodyOf(nativeAssetId);
        uint256 leafBefore = pool.nextLeafIndex();

        pool.transact(PROOF, pub, ext);

        assertTrue(pool.isSpent(pub.nullifiers[0]));
        assertTrue(pool.isSpent(pub.nullifiers[1]));
        assertEq(pool.nextLeafIndex(), leafBefore + 2);
        assertEq(pool.custodyOf(nativeAssetId), custodyBefore); // no value left the pool
        assertTrue(pool.isKnownRoot(pool.currentRoot()));
    }

    function test_Transact_4x2_Variant() public {
        _shieldNative(10 ether);
        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(0, 0),
            nullifiers: _nullifiers(4),
            outputCommitments: _outputs()
        });
        pool.transact(PROOF, pub, _extData(address(0), 0, address(0), 0));
        assertTrue(pool.isSpent(pub.nullifiers[3]));
    }

    function test_Transact_InternalWithRelayerFee() public {
        _shieldNative(10 ether);
        uint256 fee = 0.1 ether;

        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(0, fee),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        ExtData memory ext = _extData(address(0), 0, relayer, fee);

        uint256 relBefore = relayer.balance;
        pool.transact(PROOF, pub, ext);

        assertEq(relayer.balance, relBefore + fee);
        assertEq(pool.custodyOf(nativeAssetId), 10 ether - fee);
        assertEq(address(pool).balance, 10 ether - fee);
    }

    // ------------------------------------------------------------------
    // transact — withdraw (unshield)
    // ------------------------------------------------------------------

    function test_Withdraw_Native() public {
        _shieldNative(10 ether);
        uint256 W = 3 ether;
        uint256 fee = 0.2 ether;

        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(-int256(W), fee),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        ExtData memory ext = _extData(recipient, -int256(W), relayer, fee);

        vm.expectEmit(true, true, false, true, address(pool));
        emit IShieldedPool.Withdrawal(nativeAssetId, W, recipient);

        pool.transact(PROOF, pub, ext);

        assertEq(recipient.balance, W);
        assertEq(relayer.balance, fee);
        assertEq(pool.custodyOf(nativeAssetId), 10 ether - W - fee);
        assertEq(address(pool).balance, 10 ether - W - fee);
    }

    function test_Withdraw_Token() public {
        _shieldToken(100 ether);
        uint256 W = 40 ether;

        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: tokenAssetId,
            publicAmount: _publicAmount(-int256(W), 0),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        ExtData memory ext = _extData(recipient, -int256(W), address(0), 0);

        pool.transact(PROOF, pub, ext);

        assertEq(token.balanceOf(recipient), W);
        assertEq(token.balanceOf(address(pool)), 100 ether - W);
        assertEq(pool.custodyOf(tokenAssetId), 100 ether - W);
    }

    function test_Withdraw_NotPausableByGuardian() public {
        _shieldNative(10 ether);
        vm.prank(guardian);
        pool.pauseDeposits(); // deposits paused ...

        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(-int256(2 ether), 0),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        // ... withdrawal still works (exit is never pausable).
        pool.transact(PROOF, pub, _extData(recipient, -int256(2 ether), address(0), 0));
        assertEq(recipient.balance, 2 ether);
    }

    // ------------------------------------------------------------------
    // transact — reverts
    // ------------------------------------------------------------------

    function test_Transact_RevertsBadNullifierCount() public {
        _shieldNative(10 ether);
        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(0, 0),
            nullifiers: _nullifiers(3),
            outputCommitments: _outputs()
        });
        vm.expectRevert(ShieldedPool.BadNullifierCount.selector);
        pool.transact(PROOF, pub, _extData(address(0), 0, address(0), 0));
    }

    function test_Transact_RevertsBadOutputCount() public {
        _shieldNative(10 ether);
        uint256[] memory outs = new uint256[](3);
        outs[0] = _uniq();
        outs[1] = _uniq();
        outs[2] = _uniq();
        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(0, 0),
            nullifiers: _nullifiers(2),
            outputCommitments: outs
        });
        vm.expectRevert(ShieldedPool.BadOutputCount.selector);
        pool.transact(PROOF, pub, _extData(address(0), 0, address(0), 0));
    }

    function test_Transact_RevertsUnknownRoot() public {
        _shieldNative(10 ether);
        TransactPublic memory pub = TransactPublic({
            root: _uniq(), // never a real root
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(0, 0),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        pool.transact(PROOF, pub, _extData(address(0), 0, address(0), 0));
    }

    function test_Transact_RevertsNullifierReuse() public {
        _shieldNative(10 ether);
        uint256[] memory nfs = _nullifiers(2);

        TransactPublic memory pub1 = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(0, 0),
            nullifiers: nfs,
            outputCommitments: _outputs()
        });
        pool.transact(PROOF, pub1, _extData(address(0), 0, address(0), 0));

        TransactPublic memory pub2 = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(0, 0),
            nullifiers: nfs, // reuse
            outputCommitments: _outputs()
        });
        vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
        pool.transact(PROOF, pub2, _extData(address(0), 0, address(0), 0));
    }

    function test_Transact_RevertsIntraTxDuplicateNullifier() public {
        _shieldNative(10 ether);
        uint256 dup = _uniq();
        uint256[] memory nfs = new uint256[](2);
        nfs[0] = dup;
        nfs[1] = dup;
        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(0, 0),
            nullifiers: nfs,
            outputCommitments: _outputs()
        });
        vm.expectRevert(ShieldedPool.NullifierAlreadySpent.selector);
        pool.transact(PROOF, pub, _extData(address(0), 0, address(0), 0));
    }

    function test_Transact_RevertsPublicAmountMismatch() public {
        _shieldNative(10 ether);
        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: 12345, // not field(extAmount - fee)
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.transact(PROOF, pub, _extData(recipient, -int256(3 ether), address(0), 0));
    }

    function test_Transact_RevertsDepositDirection() public {
        _shieldNative(10 ether);
        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: 1,
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        vm.expectRevert(ShieldedPool.DepositsOnlyDirection.selector);
        pool.transact(PROOF, pub, _extData(address(0), int256(1 ether), address(0), 0));
    }

    function test_Transact_RevertsRecipientRequired() public {
        _shieldNative(10 ether);
        uint256 W = 2 ether;
        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(-int256(W), 0),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        // withdraw with recipient == 0
        vm.expectRevert(ShieldedPool.RecipientRequired.selector);
        pool.transact(PROOF, pub, _extData(address(0), -int256(W), address(0), 0));
    }

    function test_Transact_RevertsOnBadProof() public {
        _shieldNative(10 ether);
        vTransact2x2.setResult(false);
        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(0, 0),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.transact(PROOF, pub, _extData(address(0), 0, address(0), 0));
    }

    function test_Transact_RevertsInsolventWithdraw() public {
        _shieldNative(5 ether);
        uint256 W = 20 ether; // more than custody
        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(-int256(W), 0),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        // custody underflow guards solvency (arithmetic revert)
        vm.expectRevert();
        pool.transact(PROOF, pub, _extData(recipient, -int256(W), address(0), 0));
    }

    // ------------------------------------------------------------------
    // public-input ordering (the shared contract with S1)
    // ------------------------------------------------------------------

    function test_Transact_PublicInputOrdering() public {
        _shieldNative(10 ether);
        uint256 root = pool.currentRoot();
        uint256[] memory nfs = _nullifiers(2);
        uint256[] memory outs = _outputs();
        uint256 fee = 0.1 ether;
        int256 extAmount = -int256(1 ether);

        ExtData memory ext = _extData(recipient, extAmount, relayer, fee);
        uint256 pa = _publicAmount(extAmount, fee);

        TransactPublic memory pub = TransactPublic({
            root: root,
            publicAsset: nativeAssetId,
            publicAmount: pa,
            nullifiers: nfs,
            outputCommitments: outs
        });

        pool.transact(PROOF, pub, ext);

        uint256 expectedExtDataHash = uint256(
            keccak256(
                abi.encode(
                    ext.recipient,
                    ext.extAmount,
                    ext.relayer,
                    ext.fee,
                    ext.ringId,
                    ext.encryptedOutputs
                )
            )
        ) % P;

        assertEq(vTransact2x2.lastInputsLength(), 8);
        assertEq(vTransact2x2.lastPublicInput(0), root, "idx0 root");
        assertEq(vTransact2x2.lastPublicInput(1), nativeAssetId, "idx1 publicAsset");
        assertEq(vTransact2x2.lastPublicInput(2), pa, "idx2 publicAmount");
        assertEq(vTransact2x2.lastPublicInput(3), expectedExtDataHash, "idx3 extDataHash");
        assertEq(vTransact2x2.lastPublicInput(4), nfs[0], "idx4 nf0");
        assertEq(vTransact2x2.lastPublicInput(5), nfs[1], "idx5 nf1");
        assertEq(vTransact2x2.lastPublicInput(6), outs[0], "idx6 out0");
        assertEq(vTransact2x2.lastPublicInput(7), outs[1], "idx7 out1");
    }

    function test_Shield_PublicInputOrdering() public {
        uint256 amount = 2 ether;
        uint256 commitment = _uniq();
        vm.prank(alice);
        pool.shield{ value: amount }(PROOF, nativeAssetId, amount, commitment, "");

        assertEq(vShield.lastInputsLength(), 3);
        assertEq(vShield.lastPublicInput(0), commitment, "idx0 commitment");
        assertEq(vShield.lastPublicInput(1), nativeAssetId, "idx1 assetId");
        assertEq(vShield.lastPublicInput(2), amount, "idx2 amount");
    }

    // ------------------------------------------------------------------
    // reentrancy
    // ------------------------------------------------------------------

    function test_Reentrancy_NativeWithdrawGuarded() public {
        _shieldNative(10 ether);
        ReentrantRecipient attacker = new ReentrantRecipient();

        // Arm the attacker with a second, independently-valid transact.
        TransactPublic memory inner = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(-int256(1 ether), 0),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        attacker.arm(
            pool, PROOF, inner, _extData(address(attacker), -int256(1 ether), address(0), 0)
        );

        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _publicAmount(-int256(2 ether), 0),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        pool.transact(PROOF, pub, _extData(address(attacker), -int256(2 ether), address(0), 0));

        // The outer withdrawal completed; the reentrant inner call was blocked by the guard.
        assertEq(address(attacker).balance, 2 ether);
        assertTrue(attacker.reentryReverted());
    }
}
