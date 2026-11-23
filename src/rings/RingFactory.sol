// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { RingRegistry } from "./RingRegistry.sol";
import { PolicyModule } from "./PolicyModule.sol";
import { IVerifier } from "../interfaces/IVerifier.sol";

/// @notice Parameters for creating a Custom Ring (grouped to keep the factory under the
///         Solidity stack limit and to make call sites self-documenting).
struct CreateRingParams {
    address authority; // per-Ring admin (rotates the association root). Non-zero.
    uint256 auditorPubKeyX; // Ring auditor public key X (Baby Jubjub); 0 for auditor-less.
    uint256 auditorPubKeyY; // Ring auditor public key Y.
    uint256 associationRoot; // initial association-set root.
    uint256 rootUpdateDelay; // timelock (seconds) for future root rotations (0 = immediate).
    uint8 privacyLevel; // informational privacy tier.
    IVerifier policyVerifier; // per-Ring `policy` verifier, or address(0) for the default.
}

/// @title RingFactory
/// @notice One-call creation of a Custom Ring (SPEC §9/§10): deploys a {PolicyModule} for the
///         Ring and registers its {RingConfig} in the {RingRegistry}. The factory must be
///         appointed via `RingRegistry.setFactory(factory)` by governance; `createCustomRing`
///         is then gated by the registry's `onlyGovernorOrFactory`.
///
/// @dev    The factory predicts the Ring's id from `registry.nextRingId()` so it can deploy
///         the {PolicyModule} (which binds `ringId` immutably) before the registry assigns
///         the id — the two happen atomically in this call, and the result is asserted equal.
///         The factory holds no funds and has no power over balances; it is pure wiring.
contract RingFactory {
    RingRegistry public immutable registry;
    /// @notice Default `policy` verifier used when a Ring does not supply its own.
    IVerifier public immutable defaultPolicyVerifier;

    event CustomRingCreated(
        uint256 indexed ringId, address indexed authority, address policyModule
    );

    error RingIdRace(uint256 predicted, uint256 actual);
    error NoVerifier();

    constructor(RingRegistry _registry, IVerifier _defaultPolicyVerifier) {
        registry = _registry;
        defaultPolicyVerifier = _defaultPolicyVerifier;
    }

    /// @notice Create a Custom Ring with a fresh {PolicyModule} and register it.
    /// @param p             grouped Ring parameters (see {CreateRingParams}).
    /// @param allowedAssets initial asset allowlist (empty ⇒ all assets allowed).
    /// @return ringId       the new Ring id.
    /// @return policyModule the deployed {PolicyModule} address.
    function createCustomRing(CreateRingParams calldata p, uint256[] calldata allowedAssets)
        external
        returns (uint256 ringId, address policyModule)
    {
        IVerifier verifier =
            address(p.policyVerifier) == address(0) ? defaultPolicyVerifier : p.policyVerifier;
        if (address(verifier) == address(0)) revert NoVerifier();

        uint256 predicted = registry.nextRingId();
        policyModule = address(
            new PolicyModule(verifier, predicted, p.authority, p.associationRoot, p.rootUpdateDelay)
        );

        ringId = registry.createRing(
            p.authority, policyModule, p.auditorPubKeyX, p.auditorPubKeyY, p.privacyLevel, allowedAssets
        );
        if (ringId != predicted) revert RingIdRace(predicted, ringId);
        emit CustomRingCreated(ringId, p.authority, policyModule);
    }
}
