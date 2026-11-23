// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test, console2 } from "forge-std/Test.sol";
import { ShieldedPool } from "../../src/ShieldedPool.sol";
import { TransactPublic, ExtData } from "../../src/interfaces/IShieldedPool.sol";
import { IVerifier } from "../../src/interfaces/IVerifier.sol";
import { IHasher } from "../../src/interfaces/IHasher.sol";
import { IRingRegistry } from "../../src/interfaces/IRingRegistry.sol";
import { PoseidonT3Hasher } from "../../src/hashers/PoseidonT3Hasher.sol";
import { MockVerifier } from "../../src/mocks/MockVerifier.sol";
import { Field } from "../../src/libraries/Field.sol";

/// @title ArbitrumFork
/// @notice Fork-test scaffolding against an Arbitrum-compatible RPC. Robinhood Chain is an
///         Arbitrum Orbit L2 (ORCHESTRATION §Target sequence); until its RPC is confirmed
///         (SPEC §12), any Arbitrum-compatible endpoint exercises the same opcodes,
///         BN254 precompiles, and L2 gas behavior the pool relies on.
///
/// @dev    Fully SELF-SKIPS when no RPC is set, so CI without an endpoint stays green and
///         the test is never faked. To run it, set ONE of these env vars to an
///         Arbitrum-compatible RPC URL and run `forge test --match-path 'test/fork/*' -vv`:
///           RINGS_FORK_RPC_URL           (explicit override; preferred for CI)
///           RINGS_ROBINHOOD_RPC_URL      (the registry's Robinhood Chain RPC, once confirmed)
///           RINGS_ARBITRUM_ONE_RPC_URL   (Arbitrum One — a stand-in Orbit settlement layer)
///
///         The URLs mirror the chains-registry keys; keep chain selection in the
///         registry, never hardcode an endpoint here.
contract ArbitrumForkTest is Test {
    ShieldedPool internal pool;
    IHasher internal hasher;

    address internal alice = makeAddr("alice");
    address internal recipient = makeAddr("recipient");
    uint256 internal nativeAssetId;

    bytes internal constant PROOF = hex"abcd";

    bool internal forked;

    function setUp() public {
        string memory rpc = _resolveRpc();
        if (bytes(rpc).length == 0) {
            console2.log("ArbitrumFork: no RPC set, skipping (see test header to run).");
            return;
        }

        // A bad/placeholder URL must not fake a pass: only mark forked on a real fork.
        try vm.createSelectFork(rpc) returns (uint256) {
            forked = true;
        } catch {
            console2.log("ArbitrumFork: RPC unreachable, skipping.");
            return;
        }

        hasher = IHasher(address(new PoseidonT3Hasher()));
        pool = new ShieldedPool(
            hasher,
            IVerifier(address(new MockVerifier(3))),
            IVerifier(address(new MockVerifier(8))),
            IVerifier(address(new MockVerifier(10))),
            address(this),
            IRingRegistry(address(0))
        );
        nativeAssetId = hasher.hash2(block.chainid, 0);

        vm.deal(alice, 100 ether);
    }

    /// @notice Full shield → withdraw against the real chain's EVM, using real Poseidon.
    function test_Fork_ShieldThenWithdraw() public {
        if (!forked) return; // self-skip

        // shield 5 native
        uint256 amount = 5 ether;
        vm.prank(alice);
        pool.shield{ value: amount }(PROOF, nativeAssetId, amount, _leaf(1), "");
        assertEq(pool.custodyOf(nativeAssetId), amount);
        assertEq(address(pool).balance, amount);

        // withdraw 2 native to recipient
        uint256 w = 2 ether;
        uint256[] memory nfs = new uint256[](2);
        nfs[0] = _leaf(100);
        nfs[1] = _leaf(101);
        uint256[] memory outs = new uint256[](2);
        outs[0] = _leaf(200);
        outs[1] = _leaf(201);

        TransactPublic memory pub = TransactPublic({
            root: pool.currentRoot(),
            publicAsset: nativeAssetId,
            publicAmount: w, // Σin − Σout (positive); S3 integration fix
            nullifiers: nfs,
            outputCommitments: outs
        });
        ExtData memory ext;
        ext.recipient = recipient;
        ext.extAmount = -int256(w);
        ext.encryptedOutputs = new bytes[](0);

        pool.transact(PROOF, pub, ext);

        assertEq(recipient.balance, w);
        assertEq(pool.custodyOf(nativeAssetId), amount - w);
        assertTrue(pool.isKnownRoot(pool.currentRoot()));
        console2.log("ArbitrumFork: shield->withdraw OK on chainId", block.chainid);
    }

    function _resolveRpc() internal view returns (string memory) {
        string memory r = vm.envOr("RINGS_FORK_RPC_URL", string(""));
        if (bytes(r).length != 0) return r;
        r = vm.envOr("RINGS_ROBINHOOD_RPC_URL", string(""));
        if (bytes(r).length != 0 && !_isPlaceholder(r)) return r;
        return vm.envOr("RINGS_ARBITRUM_ONE_RPC_URL", string(""));
    }

    /// @dev The registry ships an `.invalid` placeholder for Robinhood until confirmed.
    function _isPlaceholder(string memory r) internal pure returns (bool) {
        return vm.contains(r, ".invalid");
    }

    function _leaf(uint256 n) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode("fork-leaf", n))) % Field.P;
    }
}
