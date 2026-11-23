// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IHasher } from "../interfaces/IHasher.sol";
import { Field } from "../libraries/Field.sol";

/// @title MockHasher
/// @notice Deterministic field hash for tests: `keccak256(left, right) mod P`. Lets the
///         incremental-tree and custody logic be exercised independently of the exact
///         Poseidon parameter set (which is S1's to pin — SPEC §12).
/// @dev    NOT Poseidon — never deploy to production. Production uses {PoseidonT3Hasher},
///         which must match S1's circomlib Poseidon so on-chain roots equal in-circuit roots.
contract MockHasher is IHasher {
    /// @inheritdoc IHasher
    function hash2(uint256 left, uint256 right) external pure returns (uint256) {
        return uint256(keccak256(abi.encode(left, right))) % Field.P;
    }
}
