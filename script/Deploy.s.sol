// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script, console2 } from "forge-std/Script.sol";
import { ShieldedPool } from "../src/ShieldedPool.sol";
import { PoseidonT3Hasher } from "../src/hashers/PoseidonT3Hasher.sol";
import { IHasher } from "../src/interfaces/IHasher.sol";
import { IVerifier } from "../src/interfaces/IVerifier.sol";
import { IRingRegistry } from "../src/interfaces/IRingRegistry.sol";
import { RingRegistry } from "../src/rings/RingRegistry.sol";
import { RingFactory } from "../src/rings/RingFactory.sol";

/// @title Deploy
/// @notice Chain-agnostic ShieldedPool deploy. Reads everything from env so the JS deploy
///         wrapper can source it from the chains registry and refuse unconfirmed chains.
///
///         Required env (injected by the registry-aware wrapper):
///           RINGS_DEPLOY_CONFIRMED   = "true" only for a confirmed chain (chainId/RPC set)
///           RINGS_VERIFIER_SHIELD    = address of the shield verifier (S1, via adapter)
///           RINGS_VERIFIER_TRANSACT_2x2 = address of the transact 2x2 verifier
///           RINGS_VERIFIER_TRANSACT_4x2 = address of the transact 4x2 verifier
///           RINGS_GUARDIAN           = deposit-only circuit-breaker authority
///
///         Run: `forge script script/Deploy.s.sol --rpc-url robinhood --broadcast`
///
/// @dev    `assetId` binds `block.chainid`, so the deployment chain must be the confirmed
///         Robinhood Chain (SPEC §3.1, §12) — the wrapper sets RINGS_DEPLOY_CONFIRMED only
///         then. The PoseidonT3 hasher must match S1's circomlib Poseidon.
contract Deploy is Script {
    error ChainNotConfirmed();

    function run() external returns (ShieldedPool pool) {
        if (!vm.envOr("RINGS_DEPLOY_CONFIRMED", false)) revert ChainNotConfirmed();

        address vShield = vm.envAddress("RINGS_VERIFIER_SHIELD");
        address v2x2 = vm.envAddress("RINGS_VERIFIER_TRANSACT_2x2");
        address v4x2 = vm.envAddress("RINGS_VERIFIER_TRANSACT_4x2");
        address guardian = vm.envAddress("RINGS_GUARDIAN");
        // Ring governor (Custom Rings / policy). Intended to be a timelock/multisig; defaults
        // to the guardian if unset. The optional policy verifier wires a default RingFactory.
        address governor = vm.envOr("RINGS_RING_GOVERNOR", guardian);
        address vPolicy = vm.envOr("RINGS_VERIFIER_POLICY", address(0));

        vm.startBroadcast();
        IHasher hasher = new PoseidonT3Hasher();
        RingRegistry registry = new RingRegistry(governor);
        pool = new ShieldedPool(
            hasher, IVerifier(vShield), IVerifier(v2x2), IVerifier(v4x2), guardian, registry
        );
        RingFactory factory = new RingFactory(registry, IVerifier(vPolicy));
        vm.stopBroadcast();

        console2.log("ShieldedPool:", address(pool));
        console2.log("Hasher:", address(hasher));
        console2.log("RingRegistry:", address(registry));
        console2.log("RingFactory:", address(factory));
        console2.log("chainId:", block.chainid);
    }
}
