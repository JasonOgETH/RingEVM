// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test } from "forge-std/Test.sol";
import { IncrementalMerkleTree } from "../src/IncrementalMerkleTree.sol";
import { IHasher } from "../src/interfaces/IHasher.sol";
import { MockHasher } from "../src/mocks/MockHasher.sol";

/// @dev Exposes the tree's internal insert primitives for testing.
contract TreeHarness is IncrementalMerkleTree {
    constructor(IHasher h) IncrementalMerkleTree(h) { }

    function insert(uint256 leaf) external returns (uint256 idx, uint256 root) {
        return _insert(leaf);
    }

    function insertMany(uint256[] calldata leaves) external returns (uint256 idx, uint256 root) {
        uint256[] memory m = new uint256[](leaves.length);
        for (uint256 i = 0; i < leaves.length; i++) {
            m[i] = leaves[i];
        }
        return _insertMany(m);
    }

    function filled(uint256 i) external view returns (uint256) {
        return filledSubtrees[i];
    }
}

contract IncrementalMerkleTreeTest is Test {
    MockHasher internal hasher;
    TreeHarness internal tree;

    function setUp() public {
        hasher = new MockHasher();
        tree = new TreeHarness(IHasher(address(hasher)));
    }

    function test_InitialState() public view {
        assertEq(tree.nextIndex(), 0);
        assertTrue(tree.isKnownRoot(tree.currentRoot()));
        assertFalse(tree.isKnownRoot(0));
        assertFalse(tree.isKnownRoot(uint256(keccak256("not a root"))));
    }

    function test_InsertAssignsSequentialIndices() public {
        (uint256 i0,) = tree.insert(111);
        (uint256 i1,) = tree.insert(222);
        (uint256 i2,) = tree.insert(333);
        assertEq(i0, 0);
        assertEq(i1, 1);
        assertEq(i2, 2);
        assertEq(tree.nextIndex(), 3);
    }

    function test_RootChangesAndIsKnown() public {
        uint256 r0 = tree.currentRoot();
        (, uint256 r1) = tree.insert(111);
        assertTrue(r1 != r0);
        assertEq(tree.currentRoot(), r1);
        assertTrue(tree.isKnownRoot(r1));
        assertTrue(tree.isKnownRoot(r0)); // still in history
    }

    /// @notice A batch of K leaves yields the same tree state as K sequential single inserts,
    ///         but pushes only one root (append-only ordering preserved — Threat #7).
    function test_BatchEqualsSequential() public {
        TreeHarness seq = new TreeHarness(IHasher(address(hasher)));
        TreeHarness bat = new TreeHarness(IHasher(address(hasher)));

        uint256[] memory leaves = new uint256[](5);
        for (uint256 i = 0; i < 5; i++) {
            leaves[i] = uint256(keccak256(abi.encode("leaf", i))) % P();
        }

        for (uint256 i = 0; i < 5; i++) {
            seq.insert(leaves[i]);
        }
        bat.insertMany(leaves);

        assertEq(seq.nextIndex(), bat.nextIndex(), "nextIndex");
        assertEq(seq.currentRoot(), bat.currentRoot(), "root");
        for (uint256 lvl = 0; lvl < tree.DEPTH(); lvl++) {
            assertEq(seq.filled(lvl), bat.filled(lvl), "filledSubtrees mismatch");
        }
    }

    function test_BatchPushesOneRoot() public {
        // Batch of 2 → nextIndex +2, but currentRootIndex +1.
        uint256 ri0 = tree.currentRootIndex();
        uint256[] memory leaves = new uint256[](2);
        leaves[0] = 7;
        leaves[1] = 9;
        tree.insertMany(leaves);
        assertEq(tree.nextIndex(), 2);
        assertEq(tree.currentRootIndex(), ri0 + 1);
    }

    /// @notice Roots older than ROOT_HISTORY_SIZE are evicted from the ring buffer.
    function test_RingBufferEviction() public {
        uint256 size = tree.ROOT_HISTORY_SIZE();
        uint256[] memory seen = new uint256[](size + 5);

        for (uint256 i = 0; i < size + 3; i++) {
            (, uint256 r) = tree.insert(uint256(keccak256(abi.encode("l", i))) % P());
            seen[i] = r;
        }
        // Most recent root is known.
        assertTrue(tree.isKnownRoot(tree.currentRoot()));
        // The root from the first insert has been pushed out (only last `size` kept).
        assertFalse(tree.isKnownRoot(seen[0]), "oldest root should be evicted");
        assertFalse(tree.isKnownRoot(seen[1]), "second-oldest root should be evicted");
        // A root within the window is still known.
        assertTrue(tree.isKnownRoot(seen[size + 2]));
    }

    /// @notice nextIndex is strictly monotonic across arbitrary inserts (append-only).
    function testFuzz_MonotonicIndex(uint8 count) public {
        vm.assume(count > 0 && count < 40);
        uint256 prev = tree.nextIndex();
        for (uint256 i = 0; i < count; i++) {
            tree.insert(uint256(keccak256(abi.encode("f", i))) % P());
            assertEq(tree.nextIndex(), prev + 1);
            prev = tree.nextIndex();
        }
    }

    function P() internal pure returns (uint256) {
        return 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    }
}
