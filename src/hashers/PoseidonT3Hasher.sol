// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IHasher } from "../interfaces/IHasher.sol";
import { PoseidonT3 } from "poseidon-solidity/PoseidonT3.sol";

/// @title PoseidonT3Hasher
/// @notice Production {IHasher}: `Poseidon(left, right)` over the circomlib t=3 parameter
///         set, via poseidon-solidity's `PoseidonT3`.
///
/// @dev    INTEGRATION CONTRACT (S1 ⇄ S2): poseidon-solidity's PoseidonT3 implements the
///         canonical circomlib Poseidon for two inputs. S1 MUST record the exact circomlib
///         version its circuits use (SPEC §12); this hasher must match it, or on-chain
///         Merkle roots and assetIds will diverge from the circuit's. A one-shot
///         cross-check (hash a known pair here and in-circuit) is part of S2↔S1
///         integration. The pool holds this behind {IHasher} so swapping the concrete
///         Poseidon never touches pool logic.
contract PoseidonT3Hasher is IHasher {
    /// @inheritdoc IHasher
    function hash2(uint256 left, uint256 right) external pure returns (uint256) {
        return PoseidonT3.hash([left, right]);
    }
}
