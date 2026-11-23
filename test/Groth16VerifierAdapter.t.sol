// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test } from "forge-std/Test.sol";
import { Groth16VerifierAdapter } from "../src/Groth16VerifierAdapter.sol";
import { MockRawVerifier3, MockRawVerifier8 } from "./utils/Mocks.sol";

/// @notice Proves the adapter bridges the pool's uniform IVerifier ABI to a snarkjs-shaped
///         raw verifier: it decodes the proof, forwards a/b/c and the public inputs in order,
///         and computes the right (N-dependent) selector.
contract Groth16VerifierAdapterTest is Test {
    function _proof() internal pure returns (bytes memory) {
        uint256[2] memory a = [uint256(1), 2];
        uint256[2][2] memory b = [[uint256(3), 4], [uint256(5), 6]];
        uint256[2] memory c = [uint256(7), 8];
        return abi.encode(a, b, c);
    }

    function test_Adapter_ForwardsAndVerifies_N3() public {
        MockRawVerifier3 raw = new MockRawVerifier3();
        Groth16VerifierAdapter adapter = new Groth16VerifierAdapter(address(raw), 3);

        uint256[] memory pub = new uint256[](3);
        pub[0] = 42;
        pub[1] = 43;
        pub[2] = 44;
        assertTrue(adapter.verifyProof(_proof(), pub));

        // Wrong value anywhere → raw predicate fails → false.
        pub[2] = 999;
        assertFalse(adapter.verifyProof(_proof(), pub));
    }

    function test_Adapter_SelectorVariesWithN() public {
        MockRawVerifier8 raw = new MockRawVerifier8();
        Groth16VerifierAdapter adapter = new Groth16VerifierAdapter(address(raw), 8);

        uint256[] memory pub = new uint256[](8);
        pub[7] = 99;
        assertTrue(adapter.verifyProof(_proof(), pub));

        pub[7] = 1;
        assertFalse(adapter.verifyProof(_proof(), pub));
    }

    function test_Adapter_RevertsWrongInputLength() public {
        MockRawVerifier3 raw = new MockRawVerifier3();
        Groth16VerifierAdapter adapter = new Groth16VerifierAdapter(address(raw), 3);
        uint256[] memory pub = new uint256[](2);
        vm.expectRevert(
            abi.encodeWithSelector(Groth16VerifierAdapter.WrongInputLength.selector, 2, 3)
        );
        adapter.verifyProof(_proof(), pub);
    }

    function test_Adapter_RevertsBadProofLength() public {
        MockRawVerifier3 raw = new MockRawVerifier3();
        Groth16VerifierAdapter adapter = new Groth16VerifierAdapter(address(raw), 3);
        uint256[] memory pub = new uint256[](3);
        vm.expectRevert(Groth16VerifierAdapter.BadProofEncoding.selector);
        adapter.verifyProof(hex"1234", pub);
    }

    function test_Adapter_ComputedSelectorMatchesSolidity() public {
        MockRawVerifier3 raw = new MockRawVerifier3();
        Groth16VerifierAdapter adapter = new Groth16VerifierAdapter(address(raw), 3);
        bytes4 expected =
            bytes4(keccak256("verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])"));
        assertEq(adapter.rawSelector(), expected);
        // Sanity: equals the mock's actual function selector.
        assertEq(expected, MockRawVerifier3.verifyProof.selector);
    }
}
