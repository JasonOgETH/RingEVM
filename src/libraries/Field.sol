// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Field
/// @notice BN254 scalar field (`Fr`) constants shared by the pool and hashers.
library Field {
    /// @dev `p`, the BN254 scalar field modulus (SPEC §1). Every public input and field
    ///      value must be < P; the pool rejects anything >= P so a malicious caller cannot
    ///      smuggle an unreduced value past the verifier.
    uint256 internal constant P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Amounts are range-checked to 128 bits (SPEC §1, §8). Keeps `Σ` sums and the
    ///      signed publicAmount encoding far from field wrap.
    uint256 internal constant AMOUNT_MAX = 2 ** 128;

    /// @notice True iff `x` is a canonical field element (`x < P`).
    function isValid(uint256 x) internal pure returns (bool) {
        return x < P;
    }
}
