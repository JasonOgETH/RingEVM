// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ShieldedPool } from "../ShieldedPool.sol";
import { IRingRegistry } from "../interfaces/IRingRegistry.sol";
import { TransactPublic, ExtData } from "../interfaces/IShieldedPool.sol";

/// @title CrossRingRouter
/// @notice Routes a transfer between two Custom Rings (SPEC §10 cross-ring rule). Transfers
///         between Custom Rings route through the Default Ring, and **the source Ring's
///         policy governs** — the router verifies the source Ring's policy proof (via the
///         pool's {ShieldedPool.transactInRing}) and records the destination Ring for the
///         indexer/auditor.
///
/// @dev    WHY "THROUGH THE DEFAULT RING": a note is a Poseidon commitment in the pool's
///         single global tree and is not bound to any Ring (the Default Ring is simply that
///         global, policy-free set). A cross-Ring transfer is therefore one ordinary
///         join-split in the global tree, gated by the SOURCE Ring's policy; the output note
///         is additionally made visible to the DESTINATION Ring's auditor off-chain. The
///         router does not custody funds and has no privileged power — it is a thin,
///         policy-preserving front door that forwards to the pool and emits a cross-ring
///         event. `ext.ringId` MUST equal `sourceRingId` so the pool enforces the source
///         Ring's policy module.
contract CrossRingRouter {
    ShieldedPool public immutable pool;
    IRingRegistry public immutable registry;

    event CrossRingTransfer(
        uint256 indexed sourceRingId, uint256 indexed destRingId, address indexed submitter
    );

    error SourceRingMismatch(uint256 extRingId, uint256 sourceRingId);
    error UnknownRing(uint256 ringId);
    error SameRing();

    constructor(ShieldedPool _pool, IRingRegistry _registry) {
        pool = _pool;
        registry = _registry;
    }

    /// @notice Perform a cross-Ring transfer governed by the source Ring's policy.
    /// @param sourceRingId          the Ring whose policy governs (must equal `ext.ringId`).
    /// @param destRingId            the destination Ring (must exist; informational/auditor routing).
    /// @param policyProof           the SOURCE Ring's `policy` proof.
    /// @param auditorCiphertextHash commitment to the auditor-visible record.
    /// @param proof                 the join-split (transact) proof.
    /// @param pub                   the transact public values.
    /// @param ext                   external data; `ext.ringId` MUST equal `sourceRingId`.
    function transactCrossRing(
        uint256 sourceRingId,
        uint256 destRingId,
        bytes calldata policyProof,
        uint256 auditorCiphertextHash,
        bytes calldata proof,
        TransactPublic calldata pub,
        ExtData calldata ext
    ) external {
        if (ext.ringId != sourceRingId) revert SourceRingMismatch(ext.ringId, sourceRingId);
        if (sourceRingId == destRingId) revert SameRing();
        if (!registry.ringExists(sourceRingId)) revert UnknownRing(sourceRingId);
        if (!registry.ringExists(destRingId)) revert UnknownRing(destRingId);

        // Source Ring's policy governs: the pool verifies the source Ring's policy proof
        // BEFORE the privacy proof (two-proof ordering), exactly as a direct transactInRing.
        pool.transactInRing(policyProof, auditorCiphertextHash, proof, pub, ext);

        emit CrossRingTransfer(sourceRingId, destRingId, msg.sender);
    }
}
