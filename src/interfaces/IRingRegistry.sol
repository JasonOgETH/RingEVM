// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice On-chain configuration of one Ring (SPEC §10). A Custom Ring is created by
///         governance (directly or via {RingFactory}); the Default Ring (id 0) is implicit,
///         permissionless, and NEVER stored here — it has no auditor and no policy.
/// @dev    No field of a RingConfig gives anyone power over user balances. The pool consults
///         a Ring only to *gate* a `transactInRing`; a note is a commitment in the single
///         global tree and is not bound to any Ring, so funds can always exit via the
///         Default Ring regardless of Ring state (the compliance guarantee is opt-in, as in
///         Privacy Pools — a compliant venue chooses to accept only association-set funds).
struct RingConfig {
    bool exists; // true once created (distinguishes id→config misses)
    address authority; // per-Ring admin: can rotate the association root (timelockable). No balance power.
    address policyModule; // IPolicyModule verifying this Ring's policy proof (0 ⇒ no policy)
    uint256 auditorPubKeyX; // Ring auditor public key (Baby Jubjub), for auditor visibility (SPEC §9)
    uint256 auditorPubKeyY;
    uint8 privacyLevel; // informational: 0 = default-like, higher = stricter (policy still governs)
}

/// @title IRingRegistry
/// @notice The Ring directory (SPEC §9/§10). Maps a `ringId` to its {RingConfig} and the
///         set of assets allowed in it. Governed and timelockable; it holds NO custody and
///         has NO admin power over balances, nullifiers, the tree, or the verifiers.
interface IRingRegistry {
    event RingCreated(uint256 indexed ringId, address indexed authority, address policyModule);
    event RingAssetAllowed(uint256 indexed ringId, uint256 indexed assetId, bool allowed);
    event RingAuthorityTransferred(
        uint256 indexed ringId, address indexed from, address indexed to
    );
    event GovernorTransferred(address indexed from, address indexed to);

    /// @notice Full config for a Ring. `exists == false` for an unknown (or the Default) Ring.
    function ringConfig(uint256 ringId) external view returns (RingConfig memory);

    /// @notice Convenience: the policy module for a Ring (address(0) if none / unknown).
    function policyModuleOf(uint256 ringId) external view returns (address);

    /// @notice Whether `assetId` may be transacted in `ringId`. An empty allowlist means
    ///         "all assets allowed" (a Ring opts into restriction by allowing ≥ 1 asset).
    function isAssetAllowed(uint256 ringId, uint256 assetId) external view returns (bool);

    /// @notice True iff a (non-default) Ring exists for `ringId`.
    function ringExists(uint256 ringId) external view returns (bool);
}
