// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IPolicyModule } from "../interfaces/IPolicyModule.sol";
import { IVerifier } from "../interfaces/IVerifier.sol";
import { Field } from "../libraries/Field.sol";

/// @title PolicyModule
/// @notice Reference per-Custom-Ring policy module (SPEC §8.4, §9, §10). Verifies the Ring's
///         `policy` Groth16 proof against the LOCKED public-input vector
///         `[associationRoot, ringId, auditorCiphertextHash, txBindingHash]` (SPEC §8.4).
///         The {ShieldedPool} calls {enforcePolicy} BEFORE it verifies the privacy proof, so
///         a transfer that fails Ring policy is rejected on-chain before value moves.
///
///         Predicates proven by the `policy` circuit and gated here:
///           • association-set membership (Privacy-Pools style) against {associationRoot};
///           • a per-member transfer limit (the cap is bound inside the association leaf);
///           • a well-formed auditor-ciphertext commitment (so compliance can't be faked).
///         Additional non-ZK predicates (asset allowlists) are enforced by the pool/registry.
///
/// @dev    TRUSTED ASSOCIATION ROOT. {enforcePolicy} assembles the public-input vector from
///         this module's OWN `ringId` (immutable) and `associationRoot` (storage) — never
///         from caller input — so a caller cannot verify membership against a set it
///         controls. The only caller-supplied values are the tx-specific
///         `auditorCiphertextHash` and `txBindingHash` (= the transact `extDataHash`).
///
///         TIMELOCKED ROOT ROTATION. Compliance sets grow over time; the Ring `authority`
///         rotates the root behind an on-chain timelock (`rootUpdateDelay`). With a non-zero
///         delay the authority must {queueAssociationRoot} then {commitAssociationRoot} after
///         the ETA — observers get warning of set changes. This is the concrete
///         "timelockable" surface; it has NO power over pool balances or exits.
///
///         PLUGGABLE. A Ring may instead point at any contract implementing {IPolicyModule}
///         with arbitrary predicates — this is the reference implementation.
contract PolicyModule is IPolicyModule {
    /// @notice Immutable Groth16 verifier for the `policy` circuit (4 public inputs).
    IVerifier public immutable verifierPolicy;
    /// @notice The Ring this module serves (immutable).
    uint256 public immutable override ringId;
    /// @notice Timelock delay (seconds) for association-root rotation. 0 = immediate.
    uint256 public immutable rootUpdateDelay;

    /// @notice Per-Ring admin that rotates the association root. No power over balances.
    address public authority;
    /// @notice Current association-set root the policy proof is checked against.
    uint256 public override associationRoot;

    /// @notice Queued root rotation (timelock), and the earliest timestamp it may commit.
    uint256 public pendingRoot;
    uint256 public pendingRootEta;
    bool public hasPendingRoot;

    event AssociationRootUpdated(uint256 indexed oldRoot, uint256 indexed newRoot);
    event AssociationRootQueued(uint256 indexed newRoot, uint256 eta);
    event AuthorityTransferred(address indexed from, address indexed to);

    error NotAuthority();
    error ZeroAddress();
    error NotFieldElement();
    error RingMismatch(uint256 got, uint256 expected);
    error UseTimelock();
    error NoPendingRoot();
    error TimelockNotElapsed(uint256 eta);

    constructor(
        IVerifier _verifierPolicy,
        uint256 _ringId,
        address _authority,
        uint256 _associationRoot,
        uint256 _rootUpdateDelay
    ) {
        if (address(_verifierPolicy) == address(0) || _authority == address(0)) {
            revert ZeroAddress();
        }
        if (!Field.isValid(_associationRoot)) revert NotFieldElement();
        verifierPolicy = _verifierPolicy;
        ringId = _ringId;
        authority = _authority;
        associationRoot = _associationRoot;
        rootUpdateDelay = _rootUpdateDelay;
        emit AssociationRootUpdated(0, _associationRoot);
    }

    modifier onlyAuthority() {
        if (msg.sender != authority) revert NotAuthority();
        _;
    }

    // ---------------------------------------------------------------------
    // policy enforcement (called by the pool BEFORE the privacy proof)
    // ---------------------------------------------------------------------

    /// @inheritdoc IPolicyModule
    function enforcePolicy(
        uint256 ringId_,
        bytes calldata policyProof,
        uint256 auditorCiphertextHash,
        uint256 txBindingHash
    ) external override returns (bool) {
        if (ringId_ != ringId) revert RingMismatch(ringId_, ringId);
        if (!Field.isValid(auditorCiphertextHash) || !Field.isValid(txBindingHash)) {
            revert NotFieldElement();
        }

        // Assemble the LOCKED policy public-input vector (SPEC §8.4), using THIS module's
        // trusted associationRoot and ringId — not caller-supplied values.
        uint256[] memory publicInputs = new uint256[](4);
        publicInputs[0] = associationRoot; // 0
        publicInputs[1] = ringId; // 1
        publicInputs[2] = auditorCiphertextHash; // 2
        publicInputs[3] = txBindingHash; // 3

        return verifierPolicy.verifyProof(policyProof, publicInputs);
    }

    // ---------------------------------------------------------------------
    // timelocked association-root rotation (authority-only)
    // ---------------------------------------------------------------------

    /// @notice Rotate the root immediately. Only valid when `rootUpdateDelay == 0`.
    function setAssociationRoot(uint256 newRoot) external onlyAuthority {
        if (rootUpdateDelay != 0) revert UseTimelock();
        if (!Field.isValid(newRoot)) revert NotFieldElement();
        emit AssociationRootUpdated(associationRoot, newRoot);
        associationRoot = newRoot;
    }

    /// @notice Queue a root rotation; commit after `rootUpdateDelay` via {commitAssociationRoot}.
    function queueAssociationRoot(uint256 newRoot) external onlyAuthority {
        if (!Field.isValid(newRoot)) revert NotFieldElement();
        pendingRoot = newRoot;
        pendingRootEta = block.timestamp + rootUpdateDelay;
        hasPendingRoot = true;
        emit AssociationRootQueued(newRoot, pendingRootEta);
    }

    /// @notice Apply a queued root once its timelock has elapsed. Authority-only.
    function commitAssociationRoot() external onlyAuthority {
        if (!hasPendingRoot) revert NoPendingRoot();
        if (block.timestamp < pendingRootEta) revert TimelockNotElapsed(pendingRootEta);
        emit AssociationRootUpdated(associationRoot, pendingRoot);
        associationRoot = pendingRoot;
        hasPendingRoot = false;
        pendingRoot = 0;
        pendingRootEta = 0;
    }

    function transferAuthority(address to) external onlyAuthority {
        if (to == address(0)) revert ZeroAddress();
        emit AuthorityTransferred(authority, to);
        authority = to;
    }
}
