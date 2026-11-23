// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IShieldedPool, TransactPublic, ExtData } from "../../src/interfaces/IShieldedPool.sol";

/// @notice Plain mintable ERC-20.
contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MOCK") { }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @notice ERC-20 that burns a fixed bps fee on every transfer (fee-on-transfer token).
///         The pool must reject it via the measured-balance policy.
contract FeeOnTransferERC20 is ERC20 {
    uint256 public immutable feeBps;

    constructor(uint256 _feeBps) ERC20("FeeOnTransfer", "FOT") {
        feeBps = _feeBps;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0) && feeBps != 0) {
            uint256 fee = (value * feeBps) / 10_000;
            super._update(from, address(0xdead), fee); // burn the fee to a sink
            super._update(from, to, value - fee);
        } else {
            super._update(from, to, value);
        }
    }
}

/// @notice ERC-20 whose transfer reenters the pool's transact (should be blocked by the guard).
contract ReentrantERC20 is ERC20 {
    IShieldedPool public pool;
    bool public armed;
    bytes internal proof;
    TransactPublic internal pub;
    ExtData internal ext;

    constructor() ERC20("Reentrant", "RE") { }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function arm(
        IShieldedPool _pool,
        bytes calldata _proof,
        TransactPublic calldata _pub,
        ExtData calldata _ext
    ) external {
        pool = _pool;
        proof = _proof;
        pub = _pub;
        ext = _ext;
        armed = true;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (armed && address(pool) != address(0)) {
            armed = false; // one shot
            pool.transact(proof, pub, ext);
        }
        super._update(from, to, value);
    }
}

/// @notice Native-coin recipient that reenters transact on receive (should be blocked).
contract ReentrantRecipient {
    IShieldedPool public pool;
    bytes internal proof;
    TransactPublic internal pub;
    ExtData internal ext;
    bool public armed;
    bool public reentryReverted;

    function arm(
        IShieldedPool _pool,
        bytes calldata _proof,
        TransactPublic calldata _pub,
        ExtData calldata _ext
    ) external {
        pool = _pool;
        proof = _proof;
        pub = _pub;
        ext = _ext;
        armed = true;
    }

    receive() external payable {
        if (armed) {
            armed = false;
            try pool.transact(proof, pub, ext) {
                reentryReverted = false;
            } catch {
                reentryReverted = true;
            }
        }
    }
}

/// @notice snarkjs-shaped Groth16 verifier with 3 public inputs, for adapter tests.
///         Returns true iff the proof points and inputs match a fixed predicate, proving
///         the adapter decoded and forwarded everything in order. View, so it is staticcallable.
contract MockRawVerifier3 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[3] calldata input
    ) external pure returns (bool) {
        return a[0] == 1 && a[1] == 2 && b[0][0] == 3 && b[0][1] == 4 && b[1][0] == 5
            && b[1][1] == 6 && c[0] == 7 && c[1] == 8 && input[0] == 42 && input[1] == 43
            && input[2] == 44;
    }
}

/// @notice snarkjs-shaped Groth16 verifier with 8 public inputs (proves selector varies with N).
contract MockRawVerifier8 {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[8] calldata input
    ) external pure returns (bool) {
        return input[7] == 99;
    }
}
