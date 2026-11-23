// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IShieldedPool, TransactPublic, ExtData } from "../interfaces/IShieldedPool.sol";

/// @title PrivateSwap
/// @notice Example composability contract: an ATOMIC swap of two *shielded* transfers through
///         the {ShieldedPool}. Party A pays asset X to B and party B pays asset Y to A, and the
///         two private legs settle together or not at all — atomicity is the EVM transaction
///         itself (if the second `pool.transact` reverts, the first is rolled back).
///
/// @dev    COMPOSITION MODEL (see {PrivateEscrow} for the full ZK-boundary discussion):
///         each leg is a pre-built join-split that spends a note owned by a swap-controlled key
///         (derived off-chain from `address(this)` + `swapId` + leg index; see the SDK's
///         `swapKeyFor`) and whose output note pays the counterparty. This contract is the
///         authorized submitter that fires both legs in one call behind a hashlock. The pool
///         enforces value integrity and single-spend; the swap enforces all-or-nothing and the
///         condition/timing. Cross-asset is natural: the two legs carry different `publicAsset`.
///
///         This is an EXAMPLE for the demo + docs, not an audited production swap.
contract PrivateSwap {
    /// @notice The shielded pool both legs settle through. Immutable, chain-agnostic.
    IShieldedPool public immutable pool;

    enum Status {
        None,
        Open,
        Executed,
        Cancelled
    }

    struct Swap {
        address partyA; // funds leg A (pays asset X to B)
        address partyB; // funds leg B (pays asset Y to A)
        bytes32 hashlock; // keccak256(preimage) gates execution
        uint64 deadline; // unix seconds; `<=` executable, `>` cancellable
        Status status;
    }

    /// @notice One shielded transfer leg: exactly the arguments of {IShieldedPool.transact}.
    struct Leg {
        bytes proof;
        TransactPublic pub;
        ExtData ext;
    }

    mapping(bytes32 => Swap) public swaps;

    error SwapExists();
    error SwapNotOpen();
    error NotCounterparty();
    error BadPreimage();
    error Expired();
    error NotYetExpired();
    error ZeroAddress();
    error ZeroHashlock();
    error DeadlineInPast();
    error SameParty();

    event SwapOpened(
        bytes32 indexed swapId,
        address indexed partyA,
        address indexed partyB,
        bytes32 hashlock,
        uint64 deadline
    );
    event SwapExecuted(bytes32 indexed swapId, bytes32 preimage);
    event SwapCancelled(bytes32 indexed swapId);

    constructor(IShieldedPool _pool) {
        if (address(_pool) == address(0)) revert ZeroAddress();
        pool = _pool;
    }

    /// @notice Open an atomic swap between two parties. Permissionless; `swapId` unique.
    function open(
        bytes32 swapId,
        address partyA,
        address partyB,
        bytes32 hashlock,
        uint64 deadline
    ) external {
        if (swaps[swapId].status != Status.None) revert SwapExists();
        if (partyA == address(0) || partyB == address(0)) revert ZeroAddress();
        if (partyA == partyB) revert SameParty();
        if (hashlock == bytes32(0)) revert ZeroHashlock();
        if (deadline <= block.timestamp) revert DeadlineInPast();

        swaps[swapId] = Swap({
            partyA: partyA,
            partyB: partyB,
            hashlock: hashlock,
            deadline: deadline,
            status: Status.Open
        });
        emit SwapOpened(swapId, partyA, partyB, hashlock, deadline);
    }

    /// @notice Atomically settle both shielded legs: reveal the hashlock preimage before the
    ///         deadline and the contract forwards leg A then leg B to the pool in one call. If
    ///         EITHER leg reverts (bad proof, spent nullifier, unknown root, unfunded) the whole
    ///         transaction reverts and neither leg settles. Permissionless to call.
    function execute(
        bytes32 swapId,
        bytes32 preimage,
        Leg calldata legA,
        Leg calldata legB
    ) external {
        Swap storage s = swaps[swapId];
        if (s.status != Status.Open) revert SwapNotOpen();
        if (block.timestamp > s.deadline) revert Expired();
        if (keccak256(abi.encodePacked(preimage)) != s.hashlock) revert BadPreimage();

        s.status = Status.Executed;
        emit SwapExecuted(swapId, preimage);

        // Both or neither: a revert in either leg unwinds the entire transaction.
        pool.transact(legA.proof, legA.pub, legA.ext);
        pool.transact(legB.proof, legB.pub, legB.ext);
    }

    /// @notice After the deadline a counterparty can cancel an un-executed swap (nothing has
    ///         settled, so the funded notes remain spendable by their owners elsewhere).
    function cancel(bytes32 swapId) external {
        Swap storage s = swaps[swapId];
        if (s.status != Status.Open) revert SwapNotOpen();
        if (msg.sender != s.partyA && msg.sender != s.partyB) revert NotCounterparty();
        if (block.timestamp <= s.deadline) revert NotYetExpired();

        s.status = Status.Cancelled;
        emit SwapCancelled(swapId);
    }

    /// @notice Read a swap's full record.
    function getSwap(bytes32 swapId) external view returns (Swap memory) {
        return swaps[swapId];
    }
}
