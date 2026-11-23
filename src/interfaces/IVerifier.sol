// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IVerifier
/// @notice The verification seam between S2 (ShieldedPool) and S1 (Groth16 circuits).
///         ShieldedPool is coded ONLY against this interface, so S1's real verifier
///         contracts drop in at integration without changing the pool.
///
/// @dev    Public-input ordering is the shared contract with S1 and is LOCKED in
///         docs/SPEC.md §8. The pool assembles `publicInputs` in exactly that order and
///         passes it here; the implementation must interpret the array in the same order.
///
///         snarkjs generates verifiers with a fixed-arity ABI
///         `verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[N] input)`.
///         Those are adapted to this uniform ABI by {Groth16VerifierAdapter}, which
///         decodes `proof` into (a,b,c) and splices in the fixed-size input array. S1 may
///         instead implement this interface directly on a thin generated wrapper.
///
///         `proof` encoding (LOCKED): `abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c)`
///         — the Groth16 proof points, exactly 256 bytes. See {Groth16VerifierAdapter}.
interface IVerifier {
    /// @dev Declared non-view (nonpayable) so a recording test double can implement it;
    ///      real implementations are `view`/`pure` (a view function validly overrides a
    ///      nonpayable interface signature), and {Groth16VerifierAdapter} staticcalls the
    ///      underlying verifier for safety.
    /// @param proof        Groth16 proof, `abi.encode(a, b, c)` (256 bytes).
    /// @param publicInputs Public signals in the LOCKED order for this circuit (SPEC §8).
    /// @return ok          True iff the proof verifies for these public inputs.
    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs)
        external
        returns (bool ok);
}
