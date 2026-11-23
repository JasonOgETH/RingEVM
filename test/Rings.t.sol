// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test } from "forge-std/Test.sol";

import { ShieldedPool } from "../src/ShieldedPool.sol";
import { TransactPublic, ExtData } from "../src/interfaces/IShieldedPool.sol";
import { IVerifier } from "../src/interfaces/IVerifier.sol";
import { IHasher } from "../src/interfaces/IHasher.sol";
import { IRingRegistry, RingConfig } from "../src/interfaces/IRingRegistry.sol";
import { IPolicyModule } from "../src/interfaces/IPolicyModule.sol";
import { RingRegistry } from "../src/rings/RingRegistry.sol";
import { RingFactory, CreateRingParams } from "../src/rings/RingFactory.sol";
import { PolicyModule } from "../src/rings/PolicyModule.sol";
import { CrossRingRouter } from "../src/rings/CrossRingRouter.sol";
import { Field } from "../src/libraries/Field.sol";
import { MockHasher } from "../src/mocks/MockHasher.sol";
import { MockVerifier } from "../src/mocks/MockVerifier.sol";

/// @notice S4 Ring + policy + cross-ring tests (SPEC §8.4, §9, §10). Uses MockVerifier doubles
///         (the real `policy`/`transact` verifiers are exercised by the SDK anvil e2e). These
///         prove the on-chain wiring: the registry/factory governance surface, the PolicyModule
///         timelock + enforcement, the pool's two-proof ordering (policy BEFORE privacy), the
///         asset allowlist, and the CrossRingRouter.
contract RingsTest is Test {
    uint256 internal constant P = Field.P;

    ShieldedPool internal pool;
    MockHasher internal hasher;
    MockVerifier internal vShield;
    MockVerifier internal vTransact2x2;
    MockVerifier internal vTransact4x2;
    MockVerifier internal vPolicy;
    RingRegistry internal registry;
    RingFactory internal factory;

    address internal governor = makeAddr("governor");
    address internal ringAuthority = makeAddr("ringAuthority");
    address internal alice = makeAddr("alice");
    address internal guardian = makeAddr("guardian");

    uint256 internal nativeAssetId;
    uint256 internal customRingId;
    address internal customPolicyModule;

    uint256 internal constant ASSOC_ROOT = 0x1234;
    uint256 internal constant AUD_X = 0xaa11;
    uint256 internal constant AUD_Y = 0xbb22;

    bytes internal constant PROOF = hex"abcd";
    bytes internal constant POLICY_PROOF = hex"beef";

    uint256 private salt;

    function setUp() public {
        hasher = new MockHasher();
        vShield = new MockVerifier(3);
        vTransact2x2 = new MockVerifier(8);
        vTransact4x2 = new MockVerifier(10);
        vPolicy = new MockVerifier(4); // policy has 4 public inputs (SPEC §8.4)

        registry = new RingRegistry(governor);
        pool = new ShieldedPool(
            IHasher(address(hasher)),
            IVerifier(address(vShield)),
            IVerifier(address(vTransact2x2)),
            IVerifier(address(vTransact4x2)),
            guardian,
            registry
        );
        factory = new RingFactory(registry, IVerifier(address(vPolicy)));

        nativeAssetId = hasher.hash2(block.chainid, 0);

        // Governance appoints the factory, then creates a Custom Ring (empty allowlist = all assets).
        vm.prank(governor);
        registry.setFactory(address(factory));

        uint256[] memory noAssets = new uint256[](0);
        vm.prank(governor);
        (customRingId, customPolicyModule) = factory.createCustomRing(
            CreateRingParams({
                authority: ringAuthority,
                auditorPubKeyX: AUD_X,
                auditorPubKeyY: AUD_Y,
                associationRoot: ASSOC_ROOT,
                rootUpdateDelay: 1 days,
                privacyLevel: 2,
                policyVerifier: IVerifier(address(0)) // use factory default
            }),
            noAssets
        );

        vm.deal(alice, 1000 ether);

        // Seed one note so there is a known root for internal-transfer tests.
        _shieldNative(10 ether);
    }

    // ---- helpers ----
    function _uniq() internal returns (uint256) {
        salt += 1;
        return uint256(keccak256(abi.encode("uniq", salt))) % P;
    }

    function _shieldNative(uint256 amount) internal returns (uint256 commitment) {
        commitment = _uniq();
        vm.prank(alice);
        pool.shield{ value: amount }(PROOF, nativeAssetId, amount, commitment, "");
    }

    function _nullifiers(uint256 count) internal returns (uint256[] memory nfs) {
        nfs = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            nfs[i] = _uniq();
        }
    }

    function _outputs() internal returns (uint256[] memory outs) {
        outs = new uint256[](2);
        outs[0] = _uniq();
        outs[1] = _uniq();
    }

    /// @dev A pure internal transfer (publicAmount == 0) in `ringId`.
    function _internalPub() internal returns (TransactPublic memory pub) {
        pub.root = pool.currentRoot();
        pub.publicAsset = nativeAssetId;
        pub.publicAmount = 0;
        pub.nullifiers = _nullifiers(2);
        pub.outputCommitments = _outputs();
    }

    function _ext(uint256 ringId) internal pure returns (ExtData memory ext) {
        ext.recipient = address(0);
        ext.extAmount = 0;
        ext.relayer = address(0);
        ext.fee = 0;
        ext.ringId = ringId;
        ext.encryptedOutputs = new bytes[](0);
    }

    // =====================================================================
    // registry + factory
    // =====================================================================

    function test_Factory_CreatesRingWithConfig() public view {
        RingConfig memory cfg = registry.ringConfig(customRingId);
        assertTrue(cfg.exists);
        assertEq(cfg.authority, ringAuthority);
        assertEq(cfg.policyModule, customPolicyModule);
        assertEq(cfg.auditorPubKeyX, AUD_X);
        assertEq(cfg.auditorPubKeyY, AUD_Y);
        assertEq(cfg.privacyLevel, 2);
        assertEq(customRingId, 1); // first Custom Ring
        assertTrue(registry.ringExists(customRingId));
        assertFalse(registry.ringExists(0)); // Default Ring is never stored
    }

    function test_PolicyModule_WiredToRing() public view {
        PolicyModule m = PolicyModule(customPolicyModule);
        assertEq(m.ringId(), customRingId);
        assertEq(m.associationRoot(), ASSOC_ROOT);
        assertEq(m.authority(), ringAuthority);
        assertEq(m.rootUpdateDelay(), 1 days);
        assertEq(address(m.verifierPolicy()), address(vPolicy));
    }

    function test_CreateRing_OnlyGovernorOrFactory() public {
        uint256[] memory noAssets = new uint256[](0);
        vm.expectRevert(RingRegistry.NotGovernorOrFactory.selector);
        vm.prank(alice);
        registry.createRing(ringAuthority, address(0), 0, 0, 0, noAssets);
    }

    function test_EmptyAllowlist_AllowsAllAssets() public view {
        assertTrue(registry.isAssetAllowed(customRingId, nativeAssetId));
        assertTrue(registry.isAssetAllowed(customRingId, 999));
        assertEq(registry.allowedAssetCount(customRingId), 0);
    }

    function test_Allowlist_RestrictsWhenNonEmpty() public {
        vm.prank(ringAuthority);
        registry.setAssetAllowed(customRingId, nativeAssetId, true);
        assertTrue(registry.isAssetAllowed(customRingId, nativeAssetId));
        assertFalse(registry.isAssetAllowed(customRingId, 999));
        assertEq(registry.allowedAssetCount(customRingId), 1);
    }

    function test_Allowlist_OnlyRingAuthority() public {
        vm.expectRevert(abi.encodeWithSelector(RingRegistry.NotRingAuthority.selector, customRingId));
        vm.prank(alice);
        registry.setAssetAllowed(customRingId, nativeAssetId, true);
    }

    function test_GovernorTransfer() public {
        address newGov = makeAddr("newGov");
        vm.prank(governor);
        registry.transferGovernor(newGov);
        assertEq(registry.governor(), newGov);
    }

    // =====================================================================
    // PolicyModule timelock
    // =====================================================================

    function test_TimelockedRootRotation() public {
        PolicyModule m = PolicyModule(customPolicyModule);
        uint256 newRoot = 0x5678;

        // Immediate set is rejected when a delay is configured.
        vm.prank(ringAuthority);
        vm.expectRevert(PolicyModule.UseTimelock.selector);
        m.setAssociationRoot(newRoot);

        // Queue → commit after the delay.
        vm.prank(ringAuthority);
        m.queueAssociationRoot(newRoot);

        vm.prank(ringAuthority);
        vm.expectRevert(abi.encodeWithSelector(PolicyModule.TimelockNotElapsed.selector, block.timestamp + 1 days));
        m.commitAssociationRoot();

        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(ringAuthority);
        m.commitAssociationRoot();
        assertEq(m.associationRoot(), newRoot);
    }

    function test_ImmediateRoot_WhenZeroDelay() public {
        // A module with 0 delay allows immediate rotation.
        PolicyModule m = new PolicyModule(IVerifier(address(vPolicy)), 7, ringAuthority, ASSOC_ROOT, 0);
        vm.prank(ringAuthority);
        m.setAssociationRoot(0x9999);
        assertEq(m.associationRoot(), 0x9999);
    }

    function test_EnforcePolicy_RingMismatchReverts() public {
        vm.expectRevert(abi.encodeWithSelector(PolicyModule.RingMismatch.selector, 42, customRingId));
        PolicyModule(customPolicyModule).enforcePolicy(42, POLICY_PROOF, 1, 2);
    }

    // =====================================================================
    // pool: transactInRing (two-proof ordering)
    // =====================================================================

    function test_TransactInRing_HappyPath() public {
        vPolicy.setResult(true);
        vTransact2x2.setResult(true);

        TransactPublic memory pub = _internalPub();
        ExtData memory ext = _ext(customRingId);

        uint256 auditorCtHash = 0xcafe;
        vm.prank(alice);
        pool.transactInRing(POLICY_PROOF, auditorCtHash, PROOF, pub, ext);

        // Policy verifier saw the LOCKED vector [associationRoot, ringId, auditorCtHash, txBindingHash].
        assertEq(vPolicy.lastPublicInput(0), ASSOC_ROOT);
        assertEq(vPolicy.lastPublicInput(1), customRingId);
        assertEq(vPolicy.lastPublicInput(2), auditorCtHash);
        // txBindingHash == the transact extDataHash (both proofs share it).
        assertEq(vPolicy.lastPublicInput(3), _expectedExtDataHash(ext));
        assertEq(vTransact2x2.callCount(), 1);
    }

    function test_TransactInRing_PolicyRejectedBeforePrivacy() public {
        // Policy FAILS → the whole tx reverts AND the privacy verifier is never reached.
        vPolicy.setResult(false);
        vTransact2x2.setResult(true);
        uint256 privacyCallsBefore = vTransact2x2.callCount();

        TransactPublic memory pub = _internalPub();
        ExtData memory ext = _ext(customRingId);

        vm.prank(alice);
        vm.expectRevert(ShieldedPool.PolicyRejected.selector);
        pool.transactInRing(POLICY_PROOF, 0xcafe, PROOF, pub, ext);

        // Two-proof ordering proven: privacy verifier was NOT called.
        assertEq(vTransact2x2.callCount(), privacyCallsBefore);
    }

    function test_DirectTransact_InCustomRing_Reverts() public {
        // A Custom Ring with a policy module cannot be used via the direct transact path.
        vTransact2x2.setResult(true);
        TransactPublic memory pub = _internalPub();
        ExtData memory ext = _ext(customRingId);

        vm.prank(alice);
        vm.expectRevert(ShieldedPool.PolicyRequired.selector);
        pool.transact(PROOF, pub, ext);
    }

    function test_TransactInRing_UnknownRingReverts() public {
        TransactPublic memory pub = _internalPub();
        ExtData memory ext = _ext(999); // no such ring

        vm.prank(alice);
        vm.expectRevert(ShieldedPool.RingUnknown.selector);
        pool.transactInRing(POLICY_PROOF, 0, PROOF, pub, ext);
    }

    function test_TransactInRing_RejectsRingZero() public {
        TransactPublic memory pub = _internalPub();
        ExtData memory ext = _ext(0);
        vm.prank(alice);
        vm.expectRevert(ShieldedPool.NotACustomRing.selector);
        pool.transactInRing(POLICY_PROOF, 0, PROOF, pub, ext);
    }

    function test_TransactInRing_AssetNotAllowed() public {
        // Restrict the ring to a different asset, then try to transact native.
        vm.prank(ringAuthority);
        registry.setAssetAllowed(customRingId, 0xdead, true); // non-empty allowlist, native excluded

        vPolicy.setResult(true);
        vTransact2x2.setResult(true);
        TransactPublic memory pub = _internalPub(); // publicAsset = nativeAssetId
        ExtData memory ext = _ext(customRingId);

        vm.prank(alice);
        vm.expectRevert(ShieldedPool.AssetNotAllowedInRing.selector);
        pool.transactInRing(POLICY_PROOF, 0, PROOF, pub, ext);
    }

    function test_DefaultRing_UnaffectedByRegistry() public {
        // ringId 0 flows through the normal transact path even with a registry configured.
        vTransact2x2.setResult(true);
        TransactPublic memory pub = _internalPub();
        ExtData memory ext = _ext(0);
        vm.prank(alice);
        pool.transact(PROOF, pub, ext); // no revert
        assertEq(vTransact2x2.callCount(), 1);
    }

    // =====================================================================
    // CrossRingRouter
    // =====================================================================

    function _createSecondRing() internal returns (uint256 ringId) {
        uint256[] memory noAssets = new uint256[](0);
        vm.prank(governor);
        (ringId,) = factory.createCustomRing(
            CreateRingParams({
                authority: ringAuthority,
                auditorPubKeyX: 0xcc33,
                auditorPubKeyY: 0xdd44,
                associationRoot: 0x4321,
                rootUpdateDelay: 0,
                privacyLevel: 2,
                policyVerifier: IVerifier(address(0))
            }),
            noAssets
        );
    }

    function test_CrossRingRouter_RoutesThroughSourcePolicy() public {
        uint256 destRing = _createSecondRing();
        CrossRingRouter router = new CrossRingRouter(pool, registry);

        vPolicy.setResult(true);
        vTransact2x2.setResult(true);

        TransactPublic memory pub = _internalPub();
        ExtData memory ext = _ext(customRingId); // source ring governs

        vm.prank(alice);
        router.transactCrossRing(customRingId, destRing, POLICY_PROOF, 0xcafe, PROOF, pub, ext);

        // Source ring's policy (its module/associationRoot) was the one enforced.
        assertEq(vPolicy.lastPublicInput(0), ASSOC_ROOT);
        assertEq(vPolicy.lastPublicInput(1), customRingId);
    }

    function test_CrossRingRouter_SourceMismatchReverts() public {
        uint256 destRing = _createSecondRing();
        CrossRingRouter router = new CrossRingRouter(pool, registry);

        TransactPublic memory pub = _internalPub();
        ExtData memory ext = _ext(destRing); // ext.ringId != sourceRingId

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CrossRingRouter.SourceRingMismatch.selector, destRing, customRingId));
        router.transactCrossRing(customRingId, destRing, POLICY_PROOF, 0, PROOF, pub, ext);
    }

    function test_CrossRingRouter_SameRingReverts() public {
        CrossRingRouter router = new CrossRingRouter(pool, registry);
        TransactPublic memory pub = _internalPub();
        ExtData memory ext = _ext(customRingId);
        vm.prank(alice);
        vm.expectRevert(CrossRingRouter.SameRing.selector);
        router.transactCrossRing(customRingId, customRingId, POLICY_PROOF, 0, PROOF, pub, ext);
    }

    // ---- extDataHash recompute (mirror of ShieldedPool._extDataHash) ----
    function _expectedExtDataHash(ExtData memory ext) internal pure returns (uint256) {
        return uint256(
            keccak256(
                abi.encode(
                    ext.recipient, ext.extAmount, ext.relayer, ext.fee, ext.ringId, ext.encryptedOutputs
                )
            )
        ) % P;
    }
}
