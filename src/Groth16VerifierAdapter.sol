// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IVerifier } from "./interfaces/IVerifier.sol";

/// @title Groth16VerifierAdapter
/// @notice Adapts a snarkjs-generated Groth16 verifier (fixed-arity ABI) to the pool's
///         uniform {IVerifier} ABI, so S1's real verifiers drop in without changing
///         ShieldedPool.
///
/// @dev    snarkjs emits
///         `verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[N] input) view returns (bool)`.
///         The function selector embeds N, so each circuit's verifier has a different
///         selector — precomputed here from `numPublicInputs` at construction.
///
///         This adapter:
///           1. requires `publicInputs.length == numPublicInputs`,
///           2. decodes `proof` as `abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c)`
///              (the LOCKED proof encoding — exactly 256 bytes),
///           3. builds the fixed-arity calldata and STATICCALLs the raw verifier,
///           4. returns its boolean result.
///
///         Integration (S1 → S2): deploy S1's raw `Groth16Verifier`, deploy one adapter
///         per circuit `new Groth16VerifierAdapter(rawVerifier, N)` with N from SPEC §8.5
///         (shield 3, transact 2x2 8, transact 4x2 10), and pass the adapters to the pool.
contract Groth16VerifierAdapter is IVerifier {
    /// @notice The snarkjs-generated verifier being wrapped.
    address public immutable rawVerifier;
    /// @notice Number of public inputs this circuit takes (SPEC §8.5).
    uint256 public immutable numPublicInputs;
    /// @notice Precomputed selector of `verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[N])`.
    bytes4 public immutable rawSelector;

    error WrongInputLength(uint256 got, uint256 expected);
    error BadProofEncoding();
    error RawVerifierCallFailed();

    constructor(address _rawVerifier, uint256 _numPublicInputs) {
        require(_rawVerifier != address(0), "adapter: zero verifier");
        require(_numPublicInputs > 0, "adapter: zero inputs");
        rawVerifier = _rawVerifier;
        numPublicInputs = _numPublicInputs;
        rawSelector = bytes4(
            keccak256(
                abi.encodePacked(
                    "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[",
                    _toString(_numPublicInputs),
                    "])"
                )
            )
        );
    }

    /// @inheritdoc IVerifier
    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs)
        external
        view
        returns (bool)
    {
        if (publicInputs.length != numPublicInputs) {
            revert WrongInputLength(publicInputs.length, numPublicInputs);
        }
        if (proof.length != 256) revert BadProofEncoding();

        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));

        // Fixed-arity calldata: selector ++ a ++ b ++ c ++ input[0..N-1] (all inline).
        bytes memory cd = abi.encodePacked(
            rawSelector, a[0], a[1], b[0][0], b[0][1], b[1][0], b[1][1], c[0], c[1]
        );
        for (uint256 i = 0; i < publicInputs.length; i++) {
            cd = abi.encodePacked(cd, publicInputs[i]);
        }

        (bool ok, bytes memory ret) = rawVerifier.staticcall(cd);
        if (!ok) revert RawVerifierCallFailed();
        return abi.decode(ret, (bool));
    }

    function _toString(uint256 value) private pure returns (bytes memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return buffer;
    }
}
