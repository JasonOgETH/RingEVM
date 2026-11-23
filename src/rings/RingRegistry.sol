// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IRingRegistry, RingConfig } from "../interfaces/IRingRegistry.sol";

/// @title RingRegistry
/// @notice The Ring directory for EVM Privacy Rings (SPEC §9/§10). Governance creates and
///         configures Custom Rings; the {ShieldedPool} reads a Ring's config to gate a
///         `transactInRing`. The Default Ring (`ringId = 0`) is implicit and permissionless
///         — it is never stored here, has no auditor and no policy (Helius parity).
///
/// @dev    GOVERNANCE SURFACE. A single `governor` creates Rings and appoints the
///         {RingFactory}. The governor is intended to be a timelock / multisig (e.g. an
///         OpenZeppelin `TimelockController`): all privileged entry points take a single
///         `governor` address, so pointing it at a timelock makes every registry change
///         timelocked with no code change here ("governed, timelockable"). Per-Ring mutable
///         policy (the association-set root) is rotated by the Ring's own `authority` behind
///         the {PolicyModule}'s explicit on-chain timelock, not here.
///
///         NO POWER OVER BALANCES. Nothing in this contract can move, freeze, or mint user
///         funds, spend a nullifier, touch the Merkle tree, or swap a verifier. Notes live
///         in the pool's single global tree and are not bound to any Ring, so a Ring can
///         only *gate* the compliant `transactInRing` path — users can always exit through
///         the Default Ring. Creating or misconfiguring a Ring cannot trap or seize funds.
contract RingRegistry is IRingRegistry {
    // ---- governance ----
    address public governor;
    /// @notice Optional factory permitted to create Rings on governance's behalf.
    address public factory;

    // ---- ring state ----
    /// @dev Next Ring id to assign. Starts at 1; id 0 is the reserved Default Ring.
    uint256 public nextRingId = 1;
    mapping(uint256 => RingConfig) private _rings;
    /// @dev ringId → assetId → allowed. An empty allowlist (count 0) means "all allowed".
    mapping(uint256 => mapping(uint256 => bool)) private _assetAllowed;
    mapping(uint256 => uint256) private _allowCount;

    error NotGovernor();
    error NotRingAuthority(uint256 ringId);
    error NotGovernorOrFactory();
    error RingUnknown(uint256 ringId);
    error ZeroAuthority();
    error DefaultRingReserved();
    error ZeroAddress();

    constructor(address _governor) {
        if (_governor == address(0)) revert ZeroAddress();
        governor = _governor;
        emit GovernorTransferred(address(0), _governor);
    }

    modifier onlyGovernor() {
        if (msg.sender != governor) revert NotGovernor();
        _;
    }

    modifier onlyGovernorOrFactory() {
        if (msg.sender != governor && msg.sender != factory) revert NotGovernorOrFactory();
        _;
    }

    modifier onlyRingAuthority(uint256 ringId) {
        if (!_rings[ringId].exists) revert RingUnknown(ringId);
        if (msg.sender != _rings[ringId].authority) revert NotRingAuthority(ringId);
        _;
    }

    // ---------------------------------------------------------------------
    // governance
    // ---------------------------------------------------------------------

    function transferGovernor(address to) external onlyGovernor {
        if (to == address(0)) revert ZeroAddress();
        emit GovernorTransferred(governor, to);
        governor = to;
    }

    /// @notice Appoint (or clear) the factory permitted to create Rings. Governance-only.
    function setFactory(address _factory) external onlyGovernor {
        factory = _factory;
    }

    // ---------------------------------------------------------------------
    // ring creation & configuration
    // ---------------------------------------------------------------------

    /// @notice Create a Custom Ring. Callable by the governor or the appointed factory.
    /// @param authority      per-Ring admin (rotates the association root via the module). Non-zero.
    /// @param policyModule   IPolicyModule verifying this Ring's policy proof (0 ⇒ no policy gate).
    /// @param auditorPubKeyX Ring auditor public key X (Baby Jubjub); 0 for an auditor-less Ring.
    /// @param auditorPubKeyY Ring auditor public key Y.
    /// @param privacyLevel   informational privacy tier (policy still governs enforcement).
    /// @param allowedAssets  initial asset allowlist (empty ⇒ all assets allowed).
    /// @return ringId        the new Ring id (>= 1).
    function createRing(
        address authority,
        address policyModule,
        uint256 auditorPubKeyX,
        uint256 auditorPubKeyY,
        uint8 privacyLevel,
        uint256[] calldata allowedAssets
    ) external onlyGovernorOrFactory returns (uint256 ringId) {
        if (authority == address(0)) revert ZeroAuthority();
        ringId = nextRingId++;
        _rings[ringId] = RingConfig({
            exists: true,
            authority: authority,
            policyModule: policyModule,
            auditorPubKeyX: auditorPubKeyX,
            auditorPubKeyY: auditorPubKeyY,
            privacyLevel: privacyLevel
        });
        for (uint256 i = 0; i < allowedAssets.length; i++) {
            if (!_assetAllowed[ringId][allowedAssets[i]]) {
                _assetAllowed[ringId][allowedAssets[i]] = true;
                _allowCount[ringId] += 1;
                emit RingAssetAllowed(ringId, allowedAssets[i], true);
            }
        }
        emit RingCreated(ringId, authority, policyModule);
    }

    /// @notice Add/remove an asset from a Ring's allowlist. Ring-authority-only.
    function setAssetAllowed(uint256 ringId, uint256 assetId, bool allowed)
        external
        onlyRingAuthority(ringId)
    {
        bool cur = _assetAllowed[ringId][assetId];
        if (cur == allowed) return;
        _assetAllowed[ringId][assetId] = allowed;
        if (allowed) _allowCount[ringId] += 1;
        else _allowCount[ringId] -= 1;
        emit RingAssetAllowed(ringId, assetId, allowed);
    }

    /// @notice Hand a Ring's authority to a new admin. Current-authority-only.
    function transferRingAuthority(uint256 ringId, address to)
        external
        onlyRingAuthority(ringId)
    {
        if (to == address(0)) revert ZeroAuthority();
        emit RingAuthorityTransferred(ringId, _rings[ringId].authority, to);
        _rings[ringId].authority = to;
    }

    // ---------------------------------------------------------------------
    // views (IRingRegistry)
    // ---------------------------------------------------------------------

    function ringConfig(uint256 ringId) external view returns (RingConfig memory) {
        return _rings[ringId];
    }

    function policyModuleOf(uint256 ringId) external view returns (address) {
        return _rings[ringId].policyModule;
    }

    function ringExists(uint256 ringId) external view returns (bool) {
        return _rings[ringId].exists;
    }

    function isAssetAllowed(uint256 ringId, uint256 assetId) external view returns (bool) {
        if (!_rings[ringId].exists) return false;
        // Empty allowlist ⇒ the Ring restricts no assets.
        if (_allowCount[ringId] == 0) return true;
        return _assetAllowed[ringId][assetId];
    }

    /// @notice Number of explicitly-allowed assets for a Ring (0 ⇒ all allowed).
    function allowedAssetCount(uint256 ringId) external view returns (uint256) {
        return _allowCount[ringId];
    }
}
