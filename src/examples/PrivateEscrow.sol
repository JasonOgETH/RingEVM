// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IShieldedPool, TransactPublic, ExtData } from "../interfaces/IShieldedPool.sol";

/// @title PrivateEscrow
/// @notice Example composability contract: a conditional, hash-timelocked settlement of a
///         *shielded* payment through the {ShieldedPool}. It proves "private escrow inside a
///         contract" on EVM — the escrow holds the authority to release a private transfer on
///         a public condition, while the amount and the parties' balances stay inside the
///         pool's UTXO layer (the escrow only ever sees commitments and nullifiers).
///
/// @dev    COMPOSITION MODEL (honest about the ZK boundary — read before reuse):
///
///         A contract cannot generate a Groth16 proof on-chain, so the escrow does NOT itself
///         spend notes. Instead the escrowed value lives in a pool note owned by an
///         *escrow-controlled key* (derived off-chain from `address(this)` + `dealId`; see the
///         SDK's `escrowKeyFor`). Two pre-built join-split proofs spend that one note:
///           • the CLAIM leg  → an output note that pays the beneficiary;
///           • the REFUND leg → an output note that pays the depositor back.
///         Both legs spend the SAME input note, so they share nullifiers — the pool guarantees
///         at most one can ever land (double-spend protection is the pool's, not the escrow's).
///         This contract is the *authorized submitter*: it decides WHICH leg reaches the pool
///         and WHEN, enforcing the hashlock (claim) and the timelock (refund). Value integrity
///         and single-spend are the pool's; condition and timing are the escrow's.
///
///         WHAT THIS CONTRACT GUARANTEES
///           - a deal settles at most once (state machine: Open → Funded → Claimed|Refunded);
///           - CLAIM requires the hashlock preimage AND `block.timestamp <= deadline`;
///           - REFUND requires `block.timestamp > deadline` and the original depositor;
///           - the forwarded transfer reaches the real pool (genuine on-chain composition).
///
///         WHAT IT DOES NOT (by construction, documented for an auditor)
///           - it does not verify that the funding note actually exists or pays the escrow key
///             (that is an off-chain SDK/indexer concern — `fund` records a commitment as an
///             audit anchor only); and it does not hide the hashlock/timing, which are public.
///
///         This is an EXAMPLE for the demo + docs, not an audited production escrow.
contract PrivateEscrow {
    /// @notice The shielded pool this escrow settles through. Immutable, chain-agnostic.
    IShieldedPool public immutable pool;

    enum Status {
        None,
        Open,
        Funded,
        Claimed,
        Refunded
    }

    struct Deal {
        address depositor; // opens + funds + can refund after the deadline
        address beneficiary; // informational: the claim leg's output note pays their Rings key
        bytes32 hashlock; // keccak256(preimage) — claim reveals the preimage
        uint64 deadline; // unix seconds; `<=` claimable, `>` refundable
        uint256 fundingCommitment; // pool leaf that funds this deal (audit anchor; see @dev)
        Status status;
    }

    mapping(bytes32 => Deal) public deals;

    error DealExists();
    error DealNotOpen();
    error DealNotFunded();
    error NotDepositor();
    error BadPreimage();
    error Expired();
    error NotYetExpired();
    error ZeroAddress();
    error ZeroHashlock();
    error DeadlineInPast();

    event DealOpened(
        bytes32 indexed dealId,
        address indexed depositor,
        address indexed beneficiary,
        bytes32 hashlock,
        uint64 deadline
    );
    event DealFunded(bytes32 indexed dealId, uint256 fundingCommitment);
    event DealClaimed(bytes32 indexed dealId, bytes32 preimage);
    event DealRefunded(bytes32 indexed dealId);

    constructor(IShieldedPool _pool) {
        if (address(_pool) == address(0)) revert ZeroAddress();
        pool = _pool;
    }

    /// @notice Open a new escrow deal. Permissionless; `dealId` is chosen by the caller and
    ///         must be unique (e.g. a hash of the order terms).
    function open(
        bytes32 dealId,
        address beneficiary,
        bytes32 hashlock,
        uint64 deadline
    ) external {
        if (deals[dealId].status != Status.None) revert DealExists();
        if (beneficiary == address(0)) revert ZeroAddress();
        if (hashlock == bytes32(0)) revert ZeroHashlock();
        if (deadline <= block.timestamp) revert DeadlineInPast();

        deals[dealId] = Deal({
            depositor: msg.sender,
            beneficiary: beneficiary,
            hashlock: hashlock,
            deadline: deadline,
            fundingCommitment: 0,
            status: Status.Open
        });
        emit DealOpened(dealId, msg.sender, beneficiary, hashlock, deadline);
    }

    /// @notice Record that the depositor has shielded the escrow value into the pool note owned
    ///         by this deal's escrow-controlled key. `fundingCommitment` is the pool leaf, kept
    ///         as an on-chain audit anchor. Only the depositor; only once.
    /// @dev    See the @dev note: this does not (and cannot cheaply) verify the note on-chain.
    function fund(bytes32 dealId, uint256 fundingCommitment) external {
        Deal storage deal = deals[dealId];
        if (deal.status != Status.Open) revert DealNotOpen();
        if (msg.sender != deal.depositor) revert NotDepositor();
        deal.fundingCommitment = fundingCommitment;
        deal.status = Status.Funded;
        emit DealFunded(dealId, fundingCommitment);
    }

    /// @notice Release the shielded payment to the beneficiary: reveal the hashlock preimage
    ///         before the deadline, and the escrow forwards the pre-built CLAIM join-split to
    ///         the pool. Permissionless to call (standard HTLC — anyone holding the preimage).
    /// @param preimage the hashlock preimage: `keccak256(preimage) == deal.hashlock`.
    /// @param proof    the CLAIM leg's transact proof (spends the escrow note → beneficiary).
    /// @param pub      the CLAIM leg's public values.
    /// @param ext      the CLAIM leg's external data.
    function claim(
        bytes32 dealId,
        bytes32 preimage,
        bytes calldata proof,
        TransactPublic calldata pub,
        ExtData calldata ext
    ) external {
        Deal storage deal = deals[dealId];
        if (deal.status != Status.Funded) revert DealNotFunded();
        if (block.timestamp > deal.deadline) revert Expired();
        if (keccak256(abi.encodePacked(preimage)) != deal.hashlock) revert BadPreimage();

        // Effects before the external call (the pool is also reentrancy-guarded).
        deal.status = Status.Claimed;
        emit DealClaimed(dealId, preimage);

        // Interaction: settle the private transfer through the real pool.
        pool.transact(proof, pub, ext);
    }

    /// @notice After the deadline, the depositor reclaims the escrowed value by forwarding the
    ///         pre-built REFUND join-split (spends the same escrow note → depositor). Only the
    ///         depositor; only after `deadline`.
    function refund(
        bytes32 dealId,
        bytes calldata proof,
        TransactPublic calldata pub,
        ExtData calldata ext
    ) external {
        Deal storage deal = deals[dealId];
        if (deal.status != Status.Funded) revert DealNotFunded();
        if (msg.sender != deal.depositor) revert NotDepositor();
        if (block.timestamp <= deal.deadline) revert NotYetExpired();

        deal.status = Status.Refunded;
        emit DealRefunded(dealId);

        pool.transact(proof, pub, ext);
    }

    /// @notice Read a deal's full record.
    function getDeal(bytes32 dealId) external view returns (Deal memory) {
        return deals[dealId];
    }
}
