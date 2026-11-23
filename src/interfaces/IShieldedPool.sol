// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Public portion of a join-split, carried in calldata and spliced into the
///         proof's public-input vector by the pool. `extDataHash` is NOT here: the pool
///         recomputes it from {ExtData} and inserts it at the LOCKED index (SPEC §8.2).
/// @dev    `nullifiers.length` selects the circuit variant: 2 → transact 2x2, 4 → 4x2.
///         `outputCommitments.length` is always 2 (M=2, LOCKED v1).
struct TransactPublic {
    uint256 root; // must be in the pool's root history
    uint256 publicAsset; // assetId common to every note in this tx
    uint256 publicAmount; // field-encoded net value; the pool binds it to ExtData (see ShieldedPool)
    uint256[] nullifiers; // one per input note (2 or 4)
    uint256[] outputCommitments; // one per output note (2)
}

/// @notice External (public-side) data for a join-split. Folded into a single
///         `extDataHash` public input (SPEC §8) that the spend signature covers, so a
///         relayer cannot tamper with recipient, fee, or its own address.
/// @dev    `extAmount` is SIGNED (Tornado-Nova convention): negative = value leaves the
///         pool to `recipient` (withdraw/unshield), positive = public value enters via the
///         join-split, 0 = pure internal transfer. See ShieldedPool for the custody math
///         and the publicAmount binding. This resolves the SPEC §8.2/§8.3 sign ambiguity;
///         the convention is documented in packages/contracts/HANDOFF.md for S1.
struct ExtData {
    address recipient; // withdrawal destination (0 for pure internal transfer)
    int256 extAmount; // signed external flow (see note above)
    address relayer; // paid `fee` (0 if self-submitted)
    uint256 fee; // relayer fee, carved from the transacted value
    uint256 ringId; // 0 = Default Ring (S4 uses non-zero)
    bytes[] encryptedOutputs; // one ciphertext per output note (§6), emitted for the indexer
}

/// @title IShieldedPool
/// @notice Core custody + join-split surface. LOCKED in SPEC §9. The SDK (S3) calls this.
interface IShieldedPool {
    // ---- external state-changing ----

    /// @notice Deposit public funds, creating one private note (commitment).
    /// @dev    `msg.value` funds the native coin; otherwise the pool pulls `amount` of the
    ///         ERC-20 registered for `assetId` (see {registerAsset}). Public inputs to the
    ///         shield verifier are `[commitment, assetId, amount]` (SPEC §8.1).
    function shield(
        bytes calldata proof,
        uint256 assetId,
        uint256 amount,
        uint256 commitment,
        bytes calldata encryptedNote
    ) external payable;

    /// @notice Join-split: internal transfer and/or withdraw (unshield).
    /// @dev    Withdraw when `ext.recipient != 0 && ext.extAmount < 0`. The pool recomputes
    ///         `extDataHash` from `ext`, binds `pub.publicAmount` to `ext.extAmount - ext.fee`,
    ///         verifies the proof, spends nullifiers, inserts output commitments (batched),
    ///         pays the relayer, and settles the withdrawal.
    function transact(bytes calldata proof, TransactPublic calldata pub, ExtData calldata ext)
        external;

    /// @notice Permissionlessly bind an ERC-20 (or native, token=0) to its assetId so the
    ///         pool can custody it. `assetId = hash2(chainId, uint160(token))`. No admin.
    function registerAsset(address token) external returns (uint256 assetId);

    // ---- views ----
    function isKnownRoot(uint256 root) external view returns (bool);
    function isSpent(uint256 nullifier) external view returns (bool);
    function currentRoot() external view returns (uint256);
    function nextLeafIndex() external view returns (uint256);
    function tokenForAsset(uint256 assetId) external view returns (address token, bool registered);

    // ---- events ----
    event Commitment(uint256 indexed leafIndex, uint256 commitment, bytes encryptedNote);
    event Nullified(uint256 indexed nullifier);
    event Deposit(uint256 indexed assetId, uint256 amount, uint256 commitment);
    event Withdrawal(uint256 indexed assetId, uint256 amount, address indexed recipient);
    event AssetRegistered(uint256 indexed assetId, address indexed token);
    event NewRoot(uint256 indexed leafIndex, uint256 root);
}
