// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IVerifier } from "../interfaces/IVerifier.sol";

/// @title MockVerifier
/// @notice Test double for S1's real Groth16 verifiers. Returns a configurable result and
///         records the last public inputs it was called with, so tests can assert the pool
///         assembled the public-input vector in the LOCKED order (SPEC §8).
/// @dev    NEVER deploy to production — the real immutable {Groth16Verifier} from S1
///         (wrapped by {Groth16VerifierAdapter}) replaces this at integration.
contract MockVerifier is IVerifier {
    bool public result = true;

    uint256 public expectedInputLength; // 0 = don't enforce
    uint256[] public lastPublicInputs;
    bytes public lastProof;
    uint256 public callCount;

    constructor(uint256 _expectedInputLength) {
        expectedInputLength = _expectedInputLength;
    }

    function setResult(bool _result) external {
        result = _result;
    }

    function setExpectedInputLength(uint256 n) external {
        expectedInputLength = n;
    }

    /// @inheritdoc IVerifier
    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs)
        external
        returns (bool)
    {
        if (expectedInputLength != 0) {
            require(publicInputs.length == expectedInputLength, "MockVerifier: bad input length");
        }
        lastProof = proof;
        lastPublicInputs = publicInputs;
        callCount += 1;
        return result;
    }

    function lastPublicInput(uint256 i) external view returns (uint256) {
        return lastPublicInputs[i];
    }

    function lastInputsLength() external view returns (uint256) {
        return lastPublicInputs.length;
    }
}
