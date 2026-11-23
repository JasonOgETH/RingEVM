// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IHasher
/// @notice 2-input field hash used by the on-chain incremental Merkle tree (node hash,
///         empty-subtree roots) and by assetId derivation. LOCKED to Poseidon(left,right)
///         over the circomlib parameter set (SPEC §5, §3.1) so the on-chain tree root and
///         the circuit's Merkle-membership proof agree.
///
/// @dev    Injected into {ShieldedPool} as an immutable, so the concrete Poseidon
///         implementation (which must match S1's exact circomlib version — see SPEC §12)
///         is swapped in without touching pool logic. {PoseidonT3Hasher} is the production
///         binding; tests may inject a cheaper deterministic hasher to exercise tree logic
///         independently of the Poseidon parameter choice.
interface IHasher {
    /// @return The field element `Poseidon(left, right)`.
    function hash2(uint256 left, uint256 right) external view returns (uint256);
}
