// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test } from "forge-std/Test.sol";

import { ShieldedPool } from "../../src/ShieldedPool.sol";
import { IShieldedPool, TransactPublic, ExtData } from "../../src/interfaces/IShieldedPool.sol";
import { IVerifier } from "../../src/interfaces/IVerifier.sol";
import { IHasher } from "../../src/interfaces/IHasher.sol";
import { IRingRegistry } from "../../src/interfaces/IRingRegistry.sol";
import { MockHasher } from "../../src/mocks/MockHasher.sol";
import { MockVerifier } from "../../src/mocks/MockVerifier.sol";
import { Field } from "../../src/libraries/Field.sol";
import { MockERC20 } from "./Mocks.sol";

/// @dev Shared fixture: a ShieldedPool wired to a deterministic hasher and mock verifiers.
abstract contract PoolTest is Test {
    uint256 internal constant P = Field.P;

    ShieldedPool internal pool;
    MockHasher internal hasher;
    MockVerifier internal vShield;
    MockVerifier internal vTransact2x2;
    MockVerifier internal vTransact4x2;
    MockERC20 internal token;

    address internal guardian = makeAddr("guardian");
    address internal alice = makeAddr("alice");
    address internal relayer = makeAddr("relayer");
    address internal recipient = makeAddr("recipient");

    uint256 internal nativeAssetId;
    uint256 internal tokenAssetId;

    bytes internal constant PROOF = hex"abcd"; // mock verifiers ignore content

    uint256 private salt;

    function setUp() public virtual {
        hasher = new MockHasher();
        vShield = new MockVerifier(3);
        vTransact2x2 = new MockVerifier(8);
        vTransact4x2 = new MockVerifier(10);
        pool = new ShieldedPool(
            IHasher(address(hasher)),
            IVerifier(address(vShield)),
            IVerifier(address(vTransact2x2)),
            IVerifier(address(vTransact4x2)),
            guardian,
            IRingRegistry(address(0)) // Default-Ring-only: existing S0–S3 behavior
        );

        nativeAssetId = hasher.hash2(block.chainid, 0);

        token = new MockERC20();
        tokenAssetId = pool.registerAsset(address(token));

        vm.deal(alice, 1_000 ether);
        token.mint(alice, 1_000_000 ether);
    }

    // ---- unique field-element generators (kept well under P) ----
    function _uniq() internal returns (uint256) {
        salt += 1;
        return uint256(keccak256(abi.encode("uniq", salt))) % P;
    }

    // ---- shield helpers ----
    function _shieldNative(uint256 amount) internal returns (uint256 commitment) {
        commitment = _uniq();
        vm.prank(alice);
        pool.shield{ value: amount }(PROOF, nativeAssetId, amount, commitment, "");
    }

    function _shieldToken(uint256 amount) internal returns (uint256 commitment) {
        commitment = _uniq();
        vm.startPrank(alice);
        token.approve(address(pool), amount);
        pool.shield(PROOF, tokenAssetId, amount, commitment, "");
        vm.stopPrank();
    }

    // ---- transact builders ----
    function _nullifiers(uint256 count) internal returns (uint256[] memory nfs) {
        nfs = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            nfs[i] = _uniq();
        }
    }

    function _outputs() internal returns (uint256[] memory outs) {
        outs = new uint256[](2);
        outs[0] = _uniq();
        outs[1] = _uniq();
    }

    /// @dev publicAmount = Σin − Σout = |extAmount| + fee (POSITIVE when value exits).
    ///      Matches the LOCKED circuit + SPEC §8.2 (S3 integration fix; see ShieldedPool).
    function _publicAmount(int256 extAmount, uint256 fee) internal pure returns (uint256) {
        return uint256(-extAmount) + fee;
    }

    function _extData(address _recipient, int256 extAmount, address _relayer, uint256 fee)
        internal
        pure
        returns (ExtData memory ext)
    {
        ext.recipient = _recipient;
        ext.extAmount = extAmount;
        ext.relayer = _relayer;
        ext.fee = fee;
        ext.ringId = 0;
        ext.encryptedOutputs = new bytes[](0);
    }
}
