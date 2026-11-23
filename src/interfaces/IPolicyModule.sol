// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IPolicyModule
/// @notice The per-Custom-Ring policy seam (SPEC §8.4, §9, §10). A Ring points at a
///         PolicyModule in the {RingRegistry}; the {ShieldedPool} calls {enforcePolicy}
///         for a `transactInRing` in that Ring BEFORE it verifies the privacy (transact)
///         proof — Helius's two-proof ordering. A module is pluggable: any contract that
///         implements this interface can supply arbitrary predicates (association set,
///         limits, allowlists, well-formed auditor ciphertext), so Rings can evolve policy
///         without touching the pool. The reference {PolicyModule} verifies the `policy`
///         Groth16 circuit (SPEC §8.4).
///
/// @dev    A module MUST assemble the policy public-input vector from its OWN trusted state
///         (its stored `associationRoot` and `ringId`) rather than from caller-supplied
///         values, so a caller cannot substitute an association set it controls. The only
///         caller-supplied, tx-specific inputs are `auditorCiphertextHash` and
///         `txBindingHash` (the latter equals the transact `extDataHash`, linking the two
///         proofs). A module has NO power over user balances, nullifiers, the tree, or the
///         verifiers — it can only *gate* a Custom-Ring transact; the Default Ring (id 0)
///         and the direct `transact` path never consult a module, so users can always exit.
interface IPolicyModule {
    /// @notice The Ring id this module serves. The pool checks it matches the tx's ringId.
    function ringId() external view returns (uint256);

    /// @notice The current association-set root this module verifies membership against.
    function associationRoot() external view returns (uint256);

    /// @notice Enforce the Ring policy for one transaction.
    /// @param ringId_               the tx's Ring id (must equal {ringId}).
    /// @param policyProof           Groth16 policy proof (`abi.encode(a,b,c)`, 256 bytes).
    /// @param auditorCiphertextHash commitment to the auditor-visible record (SPEC §8.4 idx 2).
    /// @param txBindingHash         the transact `extDataHash` (SPEC §8.4 idx 3), linking proofs.
    /// @return ok                   true iff the policy proof satisfies this Ring's policy.
    function enforcePolicy(
        uint256 ringId_,
        bytes calldata policyProof,
        uint256 auditorCiphertextHash,
        uint256 txBindingHash
    ) external returns (bool ok);
}
