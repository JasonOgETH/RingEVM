// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IHasher } from "./interfaces/IHasher.sol";

/// @title IncrementalMerkleTree
/// @notice Append-only incremental Merkle tree with a root-history ring buffer and
///         BATCHED inserts. Node hash is `Poseidon(left, right)` via the injected
///         {IHasher}; depth and history size are LOCKED by SPEC §5.
///
/// @dev    Batching (SPEC §5, S2's to design): {_insertMany} walks each leaf up the tree
///         exactly as a sequence of single inserts would (same `filledSubtrees` updates,
///         so append-only ordering is preserved — Threat #7), but pushes only ONE new root
///         into the history per batch instead of one per leaf. That amortizes the
///         root-history SSTORE and the `nextIndex`/`currentRootIndex` reads across the
///         batch — the join-split's two output commitments cost one root update, not two.
///
///         Only pool-verified leaves ever reach {_insert}/{_insertMany}; roots in the
///         ring buffer are therefore all pool-computed (no attacker-injected root).
abstract contract IncrementalMerkleTree {
    /// @notice Tree depth (SPEC §5, LOCKED). Capacity `2^24` leaves.
    uint256 public constant DEPTH = 24;
    /// @notice Number of recent roots a proof may verify against (SPEC §5, LOCKED).
    uint256 public constant ROOT_HISTORY_SIZE = 128;
    /// @notice Empty-leaf value (SPEC §5, LOCKED).
    uint256 public constant ZERO_VALUE = 0;

    /// @notice The node hash. Immutable so the Poseidon implementation is fixed per deploy.
    IHasher public immutable hasher;

    /// @dev Precomputed empty-subtree root at each level (`zeros[i]` = root of an all-empty
    ///      subtree of height `i`). Computed from {hasher} at construction.
    uint256[DEPTH] internal zeros;
    /// @dev Left-sibling cache per level (standard incremental-tree state).
    uint256[DEPTH] internal filledSubtrees;
    /// @dev Root history ring buffer.
    uint256[ROOT_HISTORY_SIZE] internal roots;

    /// @notice Index of the most recent root in {roots}.
    uint256 public currentRootIndex;
    /// @notice Next free leaf index (also the count of inserted leaves). Monotonic.
    uint256 public nextIndex;

    error TreeFull();
    error EmptyBatch();

    constructor(IHasher _hasher) {
        hasher = _hasher;
        uint256 currentZero = ZERO_VALUE;
        for (uint256 i = 0; i < DEPTH; i++) {
            zeros[i] = currentZero;
            filledSubtrees[i] = currentZero;
            currentZero = _hasher.hash2(currentZero, currentZero);
        }
        // Root of the all-empty tree of height DEPTH.
        roots[0] = currentZero;
    }

    /// @notice Insert a single leaf as a batch of one.
    function _insert(uint256 leaf) internal returns (uint256 firstIndex, uint256 newRoot) {
        uint256[] memory one = new uint256[](1);
        one[0] = leaf;
        return _insertMany(one);
    }

    /// @notice Insert `leaves` in order, pushing exactly one new root for the whole batch.
    /// @return firstIndex Leaf index assigned to `leaves[0]`.
    /// @return newRoot    The tree root after the batch.
    function _insertMany(uint256[] memory leaves)
        internal
        returns (uint256 firstIndex, uint256 newRoot)
    {
        uint256 count = leaves.length;
        if (count == 0) revert EmptyBatch();

        uint256 _nextIndex = nextIndex;
        if (_nextIndex + count > (1 << DEPTH)) revert TreeFull();
        firstIndex = _nextIndex;

        for (uint256 j = 0; j < count; j++) {
            uint256 currentIndex = _nextIndex;
            uint256 currentLevelHash = leaves[j];
            uint256 left;
            uint256 right;
            for (uint256 i = 0; i < DEPTH; i++) {
                if (currentIndex & 1 == 0) {
                    left = currentLevelHash;
                    right = zeros[i];
                    filledSubtrees[i] = currentLevelHash;
                } else {
                    left = filledSubtrees[i];
                    right = currentLevelHash;
                }
                currentLevelHash = hasher.hash2(left, right);
                currentIndex >>= 1;
            }
            newRoot = currentLevelHash;
            unchecked {
                _nextIndex += 1;
            }
        }

        nextIndex = _nextIndex;
        uint256 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = newRoot;
    }

    /// @notice Latest root.
    function currentRoot() public view virtual returns (uint256) {
        return roots[currentRootIndex];
    }

    /// @notice True iff `root` is one of the last {ROOT_HISTORY_SIZE} roots. Never true for 0.
    function isKnownRoot(uint256 root) public view virtual returns (bool) {
        if (root == 0) return false;
        uint256 i = currentRootIndex;
        // Walk backwards through the ring buffer once.
        for (uint256 scanned = 0; scanned < ROOT_HISTORY_SIZE; scanned++) {
            if (roots[i] == root) return true;
            if (i == 0) {
                i = ROOT_HISTORY_SIZE;
            }
            i--;
        }
        return false;
    }
}
