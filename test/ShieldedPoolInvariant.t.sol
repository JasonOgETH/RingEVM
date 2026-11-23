// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test } from "forge-std/Test.sol";
import { ShieldedPool } from "../src/ShieldedPool.sol";
import { IShieldedPool, TransactPublic, ExtData } from "../src/interfaces/IShieldedPool.sol";
import { IVerifier } from "../src/interfaces/IVerifier.sol";
import { IHasher } from "../src/interfaces/IHasher.sol";
import { IRingRegistry } from "../src/interfaces/IRingRegistry.sol";
import { MockHasher } from "../src/mocks/MockHasher.sol";
import { MockVerifier } from "../src/mocks/MockVerifier.sol";
import { Field } from "../src/libraries/Field.sol";
import { MockERC20 } from "./utils/Mocks.sol";

/// @dev Drives the pool with randomized shield/withdraw/internal actions while tracking
///      ghost totals, so the invariants can check custody conservation and append-only
///      tree growth across long call sequences.
contract Handler is Test {
    ShieldedPool public pool;
    MockERC20 public token;
    MockHasher public hasher;

    uint256 public nativeAssetId;
    uint256 public tokenAssetId;

    // ghost accounting (what SHOULD be held per asset)
    uint256 public ghostNative; // deposited - withdrawn - fees
    uint256 public ghostToken;

    // monotonicity witness
    uint256 public lastIndex;

    uint256 private seed;
    bytes internal constant PROOF = hex"01";
    address internal constant SINK = address(0xBEEF);
    address internal constant RELAYER = address(0xFEE);

    constructor(
        ShieldedPool _pool,
        MockERC20 _token,
        MockHasher _hasher,
        uint256 _nativeAssetId,
        uint256 _tokenAssetId
    ) {
        pool = _pool;
        token = _token;
        hasher = _hasher;
        nativeAssetId = _nativeAssetId;
        tokenAssetId = _tokenAssetId;
        vm.deal(address(this), 1_000_000 ether);
        token.mint(address(this), 1_000_000_000 ether);
    }

    function _uniq() internal returns (uint256) {
        seed += 1;
        return uint256(keccak256(abi.encode("h", seed, block.timestamp))) % Field.P;
    }

    function _nullifiers(uint256 n) internal returns (uint256[] memory a) {
        a = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            a[i] = _uniq();
        }
    }

    function _outputs() internal returns (uint256[] memory a) {
        a = new uint256[](2);
        a[0] = _uniq();
        a[1] = _uniq();
    }

    function _pubAmount(uint256 magnitude) internal pure returns (uint256) {
        // publicAmount = Σin − Σout (POSITIVE when value exits); see ShieldedPool S3 fix.
        return magnitude;
    }

    function shieldNative(uint256 amount) public {
        amount = bound(amount, 1, 50 ether);
        uint256 c = _uniq();
        pool.shield{ value: amount }(PROOF, nativeAssetId, amount, c, "");
        ghostNative += amount;
        lastIndex = pool.nextLeafIndex();
    }

    function shieldToken(uint256 amount) public {
        amount = bound(amount, 1, 50 ether);
        token.approve(address(pool), amount);
        pool.shield(PROOF, tokenAssetId, amount, _uniq(), "");
        ghostToken += amount;
        lastIndex = pool.nextLeafIndex();
    }

    function withdrawNative(uint256 wSeed, uint256 fSeed) public {
        if (ghostNative < 2) return;
        uint256 w = bound(wSeed, 0, ghostNative / 2);
        uint256 fee = bound(fSeed, 0, ghostNative - w);
        if (w + fee == 0) return;

        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _pubAmount(w + fee),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        ExtData memory ext;
        ext.recipient = w > 0 ? SINK : address(0);
        ext.extAmount = -int256(w);
        ext.relayer = fee > 0 ? RELAYER : address(0);
        ext.fee = fee;
        ext.encryptedOutputs = new bytes[](0);

        pool.transact(PROOF, pub, ext);
        ghostNative -= (w + fee);
        lastIndex = pool.nextLeafIndex();
    }

    function withdrawToken(uint256 wSeed, uint256 fSeed) public {
        if (ghostToken < 2) return;
        uint256 w = bound(wSeed, 0, ghostToken / 2);
        uint256 fee = bound(fSeed, 0, ghostToken - w);
        if (w + fee == 0) return;

        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: tokenAssetId,
            publicAmount: _pubAmount(w + fee),
            nullifiers: _nullifiers(4),
            outputCommitments: _outputs()
        });
        ExtData memory ext;
        ext.recipient = w > 0 ? SINK : address(0);
        ext.extAmount = -int256(w);
        ext.relayer = fee > 0 ? RELAYER : address(0);
        ext.fee = fee;
        ext.encryptedOutputs = new bytes[](0);

        pool.transact(PROOF, pub, ext);
        ghostToken -= (w + fee);
        lastIndex = pool.nextLeafIndex();
    }

    function internalNative(uint256 fSeed) public {
        if (ghostNative < 1) return;
        uint256 fee = bound(fSeed, 0, ghostNative);

        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: _pubAmount(fee),
            nullifiers: _nullifiers(2),
            outputCommitments: _outputs()
        });
        ExtData memory ext;
        ext.extAmount = 0;
        ext.relayer = fee > 0 ? RELAYER : address(0);
        ext.fee = fee;
        ext.encryptedOutputs = new bytes[](0);

        pool.transact(PROOF, pub, ext);
        ghostNative -= fee;
        lastIndex = pool.nextLeafIndex();
    }

    receive() external payable { }
}

contract ShieldedPoolInvariantTest is Test {
    ShieldedPool internal pool;
    MockHasher internal hasher;
    MockERC20 internal token;
    Handler internal handler;

    uint256 internal nativeAssetId;
    uint256 internal tokenAssetId;

    function setUp() public {
        hasher = new MockHasher();
        pool = new ShieldedPool(
            IHasher(address(hasher)),
            IVerifier(address(new MockVerifier(3))),
            IVerifier(address(new MockVerifier(8))),
            IVerifier(address(new MockVerifier(10))),
            address(this),
            IRingRegistry(address(0))
        );
        nativeAssetId = hasher.hash2(block.chainid, 0);
        token = new MockERC20();
        tokenAssetId = pool.registerAsset(address(token));

        handler = new Handler(pool, token, hasher, nativeAssetId, tokenAssetId);
        targetContract(address(handler));
    }

    /// @notice Native custody ledger exactly equals the pool's native balance (solvency).
    function invariant_NativeSolvency() public view {
        assertEq(address(pool).balance, pool.custodyOf(nativeAssetId));
    }

    /// @notice ERC-20 custody ledger exactly equals the pool's token balance (solvency).
    function invariant_TokenSolvency() public view {
        assertEq(token.balanceOf(address(pool)), pool.custodyOf(tokenAssetId));
    }

    /// @notice The custody ledger equals the independently-tracked net flows (no value
    ///         created or destroyed inside the pool).
    function invariant_CustodyMatchesGhost() public view {
        assertEq(pool.custodyOf(nativeAssetId), handler.ghostNative());
        assertEq(pool.custodyOf(tokenAssetId), handler.ghostToken());
    }

    /// @notice The tree only ever grows (append-only) and its current root is always known.
    function invariant_TreeMonotonicAndRootKnown() public view {
        assertGe(pool.nextLeafIndex(), handler.lastIndex());
        assertTrue(pool.isKnownRoot(pool.currentRoot()));
    }
}
