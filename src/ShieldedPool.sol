// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import { IShieldedPool, TransactPublic, ExtData } from "./interfaces/IShieldedPool.sol";
import { IVerifier } from "./interfaces/IVerifier.sol";
import { IHasher } from "./interfaces/IHasher.sol";
import { IRingRegistry, RingConfig } from "./interfaces/IRingRegistry.sol";
import { IPolicyModule } from "./interfaces/IPolicyModule.sol";
import { IncrementalMerkleTree } from "./IncrementalMerkleTree.sol";
import { Field } from "./libraries/Field.sol";
import { RelayerFeeLib } from "./libraries/RelayerFeeLib.sol";

/// @title ShieldedPool
/// @notice Core custody + join-split for EVM Privacy Rings (SPEC §9). Non-upgradeable, no
///         admin key over user balances. UTXO notes as Poseidon commitments in an
///         incremental Merkle tree; spends publish nullifiers; proofs verify against the
///         matching immutable Groth16 verifier (mock now, S1's real verifier at integration).
///
/// @dev    Chain-agnostic: no chainId/RPC/address is hardcoded. `assetId` binds
///         `block.chainid` (the deployment's real chainId) so notes are non-replayable
///         across chains (SPEC §3.1); the circuit/SDK must use the same chainId.
///
///         GOVERNANCE SURFACE (Threat #9): a `guardian` may pause DEPOSITS and set per-asset
///         deposit caps — deposit-side only. It can NEVER pause or block {transact}
///         (withdrawals/exits are always available) and has NO power over balances,
///         nullifiers, the tree, or the verifiers.
///
///         CUSTODY / publicAmount convention (SPEC §8.2 index 2; see HANDOFF.md):
///         `ext.extAmount` is signed — `< 0` withdraws `|extAmount|` to `recipient`, `0` is a
///         pure internal transfer. Depositing public value flows through {shield}, so
///         {transact} requires `extAmount <= 0`. `publicAmount = Σin − Σout`, a POSITIVE field
///         element equal to `withdrawAmount + fee` when value exits (`0` for a pure internal
///         transfer) — the LOCKED circuit's public signal. Net custody change is
///         `-(withdrawAmount + fee)` on every path, so the pool stays exactly solvent.
///         (Amendment B, 2026-11-22: the old `field(extAmount - fee)` / `Σin + publicAmount ==
///         Σout` negated framing was the S2 sign bug the real-verifier e2e rejected.)
contract ShieldedPool is IShieldedPool, IncrementalMerkleTree, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ---- immutable configuration ----

    /// @notice shield verifier (3 public inputs, SPEC §8.1).
    IVerifier public immutable verifierShield;
    /// @notice transact 2x2 verifier (8 public inputs, SPEC §8.2).
    IVerifier public immutable verifierTransact2x2;
    /// @notice transact 4x2 verifier (10 public inputs, SPEC §8.2).
    IVerifier public immutable verifierTransact4x2;
    /// @notice chainId bound into assetId (SPEC §3.1). The deployment's real chainId.
    uint256 public immutable chainId;
    /// @notice Deposit-only circuit breaker / cap authority. No power over balances.
    address public immutable guardian;
    /// @notice Ring directory for Custom-Ring policy gating (SPEC §9/§10). MAY be address(0):
    ///         a registry-less pool behaves exactly as the Default Ring for every tx (the
    ///         S0–S3 behavior). It can only *gate* the `transactInRing` compliance path; it
    ///         has NO power over balances, nullifiers, the tree, or the verifiers, and the
    ///         direct {transact}/Default-Ring exit never consults it.
    IRingRegistry public immutable ringRegistry;

    /// @notice Number of output commitments per join-split (M, LOCKED v1).
    uint256 public constant OUTPUTS = 2;

    // ---- state ----

    /// @notice Spent nullifier set (Threat #1).
    mapping(uint256 => bool) public nullifierSpent;
    /// @dev assetId → ERC-20 (0 = native). Registered permissionlessly.
    mapping(uint256 => address) private _assetToken;
    mapping(uint256 => bool) private _assetRegistered;
    /// @notice Per-asset custody ledger. Equals the pool's held balance of that asset
    ///         (modulo unsolicited donations). Solvency invariant anchor.
    mapping(uint256 => uint256) public custodyOf;
    /// @notice Optional per-asset deposit cap (0 = uncapped). Deposit-side only.
    mapping(uint256 => uint256) public depositCap;

    /// @notice When true, {shield} is paused. {transact}/withdrawals are NEVER pausable.
    bool public depositsPaused;

    // ---- errors ----
    error DepositsPaused();
    error ZeroAmount();
    error AmountTooLarge();
    error NotFieldElement();
    error AssetNotRegistered();
    error NativeValueMismatch();
    error UnexpectedNativeValue();
    error FeeOnTransferToken();
    error UnknownRoot();
    error NullifierAlreadySpent();
    error InvalidProof();
    error BadNullifierCount();
    error BadOutputCount();
    error DepositsOnlyDirection();
    error RecipientRequired();
    error WithdrawTransferFailed();
    error DepositCapExceeded();
    error NotGuardian();
    error FeeExceedsValue();
    // ---- Ring / policy errors (S4) ----
    error RingsNotEnabled();
    error NotACustomRing();
    error RingUnknown();
    error AssetNotAllowedInRing();
    error PolicyRequired();
    error PolicyRejected();

    event DepositsPausedSet(bool paused);
    event DepositCapSet(uint256 indexed assetId, uint256 cap);

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert NotGuardian();
        _;
    }

    constructor(
        IHasher _hasher,
        IVerifier _verifierShield,
        IVerifier _verifierTransact2x2,
        IVerifier _verifierTransact4x2,
        address _guardian,
        IRingRegistry _ringRegistry
    ) IncrementalMerkleTree(_hasher) {
        verifierShield = _verifierShield;
        verifierTransact2x2 = _verifierTransact2x2;
        verifierTransact4x2 = _verifierTransact4x2;
        guardian = _guardian;
        ringRegistry = _ringRegistry; // may be address(0): Default-Ring-only pool (S0–S3 behavior)
        chainId = block.chainid;

        // Pre-register the native coin (token = address(0)).
        uint256 nativeAssetId = _hasher.hash2(block.chainid, 0);
        _assetToken[nativeAssetId] = address(0);
        _assetRegistered[nativeAssetId] = true;
        emit AssetRegistered(nativeAssetId, address(0));
    }

    // ---------------------------------------------------------------------
    // Asset registration (permissionless)
    // ---------------------------------------------------------------------

    /// @inheritdoc IShieldedPool
    function registerAsset(address token) external returns (uint256 assetId) {
        assetId = hasher.hash2(chainId, uint256(uint160(token)));
        if (!_assetRegistered[assetId]) {
            _assetToken[assetId] = token;
            _assetRegistered[assetId] = true;
            emit AssetRegistered(assetId, token);
        }
    }

    /// @inheritdoc IShieldedPool
    function tokenForAsset(uint256 assetId) external view returns (address token, bool registered) {
        return (_assetToken[assetId], _assetRegistered[assetId]);
    }

    // ---------------------------------------------------------------------
    // shield (deposit)
    // ---------------------------------------------------------------------

    /// @inheritdoc IShieldedPool
    function shield(
        bytes calldata proof,
        uint256 assetId,
        uint256 amount,
        uint256 commitment,
        bytes calldata encryptedNote
    ) external payable nonReentrant {
        if (depositsPaused) revert DepositsPaused();
        if (amount == 0) revert ZeroAmount();
        if (amount >= Field.AMOUNT_MAX) revert AmountTooLarge();
        if (!Field.isValid(commitment) || !Field.isValid(assetId)) revert NotFieldElement();
        if (!_assetRegistered[assetId]) revert AssetNotRegistered();

        // Deposit cap (deposit-only blast-radius bound, Threat #2).
        uint256 cap = depositCap[assetId];
        if (cap != 0 && custodyOf[assetId] + amount > cap) revert DepositCapExceeded();

        // Verify the shield proof: public inputs [commitment, assetId, amount] (SPEC §8.1).
        uint256[] memory publicInputs = new uint256[](3);
        publicInputs[0] = commitment;
        publicInputs[1] = assetId;
        publicInputs[2] = amount;
        if (!verifierShield.verifyProof(proof, publicInputs)) revert InvalidProof();

        // Effects: insert the commitment (batch of one), update custody.
        (uint256 leafIndex, uint256 newRoot) = _insert(commitment);
        custodyOf[assetId] += amount;

        // Interactions: take custody of exactly `amount`.
        address token = _assetToken[assetId];
        if (token == address(0)) {
            if (msg.value != amount) revert NativeValueMismatch();
        } else {
            if (msg.value != 0) revert UnexpectedNativeValue();
            _pullExact(token, msg.sender, amount);
        }

        emit Commitment(leafIndex, commitment, encryptedNote);
        emit NewRoot(leafIndex, newRoot);
        emit Deposit(assetId, amount, commitment);
    }

    // ---------------------------------------------------------------------
    // transact (internal transfer and/or withdraw)
    // ---------------------------------------------------------------------

    /// @inheritdoc IShieldedPool
    /// @dev Default-Ring / registry-less path. If a `ringRegistry` is configured and this tx
    ///      targets a Custom Ring (`ext.ringId != 0`) that has a policy module, the caller
    ///      MUST use {transactInRing} so the Ring policy is verified first — this direct path
    ///      then reverts `PolicyRequired`. A Custom Ring with no policy module, or ringId 0,
    ///      flows through unchanged. A registry-less pool (ringRegistry == 0) treats `ringId`
    ///      as a free tag exactly as in S0–S3.
    function transact(bytes calldata proof, TransactPublic calldata pub, ExtData calldata ext)
        external
        nonReentrant
    {
        if (address(ringRegistry) != address(0) && ext.ringId != 0) {
            if (ringRegistry.policyModuleOf(ext.ringId) != address(0)) revert PolicyRequired();
        }
        _transactCore(proof, pub, ext);
    }

    /// @notice Join-split in a Custom Ring: verify the Ring's policy proof FIRST, then the
    ///         privacy proof (SPEC §8.4 two-proof ordering). Identical custody/tree/nullifier
    ///         semantics to {transact}; it only adds the policy gate in front.
    /// @param policyProof           the Ring's `policy` Groth16 proof (`abi.encode(a,b,c)`).
    /// @param auditorCiphertextHash commitment to the auditor-visible record (policy pubinput 2).
    /// @param proof                 the join-split (transact) proof.
    /// @param pub                   the transact public values.
    /// @param ext                   external data; `ext.ringId` selects the Custom Ring.
    function transactInRing(
        bytes calldata policyProof,
        uint256 auditorCiphertextHash,
        bytes calldata proof,
        TransactPublic calldata pub,
        ExtData calldata ext
    ) external nonReentrant {
        if (address(ringRegistry) == address(0)) revert RingsNotEnabled();
        if (ext.ringId == 0) revert NotACustomRing();

        RingConfig memory ring = ringRegistry.ringConfig(ext.ringId);
        if (!ring.exists) revert RingUnknown();

        // Asset allowlist predicate (non-ZK) — an empty allowlist means "all assets".
        if (!ringRegistry.isAssetAllowed(ext.ringId, pub.publicAsset)) {
            revert AssetNotAllowedInRing();
        }

        // ---- TWO-PROOF ORDERING (SPEC §8.4): policy proof BEFORE the privacy proof. ----
        // The policy proof's txBindingHash equals this tx's extDataHash, cryptographically
        // linking the two proofs; the module checks membership against its own trusted
        // association root, the per-member limit, and auditor-ciphertext well-formedness.
        if (ring.policyModule != address(0)) {
            uint256 txBindingHash = _extDataHash(ext);
            bool policyOk = IPolicyModule(ring.policyModule).enforcePolicy(
                ext.ringId, policyProof, auditorCiphertextHash, txBindingHash
            );
            if (!policyOk) revert PolicyRejected();
        }

        _transactCore(proof, pub, ext);
    }

    /// @dev The shared join-split engine behind {transact} and {transactInRing}. Reentrancy
    ///      is guarded by the external entry points (both `nonReentrant`).
    function _transactCore(bytes calldata proof, TransactPublic calldata pub, ExtData calldata ext)
        internal
    {
        uint256 n = pub.nullifiers.length;
        if (n != 2 && n != 4) revert BadNullifierCount();
        if (pub.outputCommitments.length != OUTPUTS) revert BadOutputCount();

        // Deposits go through shield; transact only keeps value internal or withdraws it.
        if (ext.extAmount > 0) revert DepositsOnlyDirection();

        // Field validity of every public value handed to the verifier.
        if (
            !Field.isValid(pub.root) || !Field.isValid(pub.publicAsset)
                || !Field.isValid(pub.publicAmount)
        ) {
            revert NotFieldElement();
        }
        if (!_assetRegistered[pub.publicAsset]) revert AssetNotRegistered();

        // Root must be in recent history (SPEC §5).
        if (!isKnownRoot(pub.root)) revert UnknownRoot();

        // Bind publicAmount to the external flow: publicAmount == field(extAmount - fee).
        uint256 withdrawAmount =
            _requireAndBindPublicAmount(pub.publicAmount, ext.extAmount, ext.fee);

        // extDataHash binds recipient/fee/relayer/ringId/encOutputs into the proof (SPEC §8).
        uint256 extDataHash = _extDataHash(ext);

        // Assemble public inputs in the LOCKED order (SPEC §8.2):
        // [root, publicAsset, publicAmount, extDataHash, nullifiers.., outputCommitments..].
        uint256[] memory publicInputs = new uint256[](4 + n + OUTPUTS);
        publicInputs[0] = pub.root;
        publicInputs[1] = pub.publicAsset;
        publicInputs[2] = pub.publicAmount;
        publicInputs[3] = extDataHash;
        for (uint256 i = 0; i < n; i++) {
            uint256 nf = pub.nullifiers[i];
            if (!Field.isValid(nf)) revert NotFieldElement();
            publicInputs[4 + i] = nf;
        }
        for (uint256 j = 0; j < OUTPUTS; j++) {
            uint256 c = pub.outputCommitments[j];
            if (!Field.isValid(c)) revert NotFieldElement();
            publicInputs[4 + n + j] = c;
        }

        // Nullifier checks before any effects (Threat #1); intra-tx duplicates revert here.
        for (uint256 i = 0; i < n; i++) {
            uint256 nf = pub.nullifiers[i];
            if (nullifierSpent[nf]) revert NullifierAlreadySpent();
            nullifierSpent[nf] = true;
            emit Nullified(nf);
        }

        // Verify the join-split proof against the variant's immutable verifier.
        IVerifier verifier = n == 2 ? verifierTransact2x2 : verifierTransact4x2;
        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        // Effects: insert both output commitments as ONE batch (one new root).
        (uint256 firstLeaf, uint256 newRoot) = _insertMany(_toMemory(pub.outputCommitments));

        // Custody accounting. Net change = extAmount - fee = -(withdrawAmount + fee) <= 0.
        address token = _assetToken[pub.publicAsset];
        if (withdrawAmount + ext.fee > 0) {
            custodyOf[pub.publicAsset] -= (withdrawAmount + ext.fee); // reverts on insolvency
        }

        // Interactions: pay relayer, then settle withdrawal.
        RelayerFeeLib.payFee(token, ext.relayer, ext.fee);

        if (withdrawAmount > 0) {
            if (ext.recipient == address(0)) revert RecipientRequired();
            _payout(token, ext.recipient, withdrawAmount);
            emit Withdrawal(pub.publicAsset, withdrawAmount, ext.recipient);
        }

        // Emit commitment/root events for the indexer.
        for (uint256 j = 0; j < OUTPUTS; j++) {
            bytes memory enc;
            if (j < ext.encryptedOutputs.length) enc = ext.encryptedOutputs[j];
            emit Commitment(firstLeaf + j, pub.outputCommitments[j], enc);
        }
        emit NewRoot(firstLeaf, newRoot);
    }

    // ---------------------------------------------------------------------
    // views
    // ---------------------------------------------------------------------

    /// @inheritdoc IShieldedPool
    function isSpent(uint256 nullifier) external view returns (bool) {
        return nullifierSpent[nullifier];
    }

    /// @inheritdoc IShieldedPool
    function nextLeafIndex() external view returns (uint256) {
        return nextIndex;
    }

    /// @inheritdoc IShieldedPool
    function currentRoot()
        public
        view
        override(IShieldedPool, IncrementalMerkleTree)
        returns (uint256)
    {
        return IncrementalMerkleTree.currentRoot();
    }

    /// @inheritdoc IShieldedPool
    function isKnownRoot(uint256 root)
        public
        view
        override(IShieldedPool, IncrementalMerkleTree)
        returns (bool)
    {
        return IncrementalMerkleTree.isKnownRoot(root);
    }

    // ---------------------------------------------------------------------
    // guardian: deposit-only circuit breaker + caps (never touches withdrawals)
    // ---------------------------------------------------------------------

    function pauseDeposits() external onlyGuardian {
        depositsPaused = true;
        emit DepositsPausedSet(true);
    }

    function unpauseDeposits() external onlyGuardian {
        depositsPaused = false;
        emit DepositsPausedSet(false);
    }

    function setDepositCap(uint256 assetId, uint256 cap) external onlyGuardian {
        depositCap[assetId] = cap;
        emit DepositCapSet(assetId, cap);
    }

    // ---------------------------------------------------------------------
    // internal helpers
    // ---------------------------------------------------------------------

    /// @dev Recompute extDataHash from calldata (SPEC §8). Must match the circuit's encoding.
    function _extDataHash(ExtData calldata ext) internal pure returns (uint256) {
        return uint256(
            keccak256(
            abi.encode(
            ext.recipient, ext.extAmount, ext.relayer, ext.fee, ext.ringId, ext.encryptedOutputs
        )
        )
        ) % Field.P;
    }

    /// @dev Enforce range + field encoding of publicAmount and return the withdraw amount.
    ///      publicAmount == withdrawAmount + fee == Σin − Σout (positive); extAmount <= 0 here.
    function _requireAndBindPublicAmount(uint256 publicAmount, int256 extAmount, uint256 fee)
        internal
        pure
        returns (uint256 withdrawAmount)
    {
        if (fee >= Field.AMOUNT_MAX) revert AmountTooLarge();
        // extAmount in (-2^128, 0].
        if (extAmount <= -int256(Field.AMOUNT_MAX)) revert AmountTooLarge();
        withdrawAmount = uint256(-extAmount); // >= 0

        // A fee with no value to draw it from would make the user's notes under-fund it;
        // the circuit's conservation also forbids it, but reject early for clarity.
        //
        // publicAmount convention — S3 INTEGRATION FIX (pending orchestrator ratification):
        // the LOCKED circuit (circuits/templates/joinsplit.circom) and SPEC §8.2 index 2
        // define `publicAmount = Σin − Σout`, which is POSITIVE (= withdrawAmount + fee)
        // when value leaves the pool. S2 originally bound `publicAmount == field(extAmount −
        // fee) == P − (withdrawAmount + fee)` (the opposite, Tornado-Nova sign), which the
        // real Groth16 verifier rejects — the circuit's public signal is the positive value,
        // so the proof never matches that negated bind. The real-verifier e2e (S3 Milestone 1)
        // surfaced this. Aligning the pool to the circuit (the cryptographic ground truth
        // baked into the verifier) is a one-line, ABI-preserving change; custody math is
        // unchanged (net custody delta is still -(withdrawAmount + fee)). Flagged to the
        // orchestrator; see packages/sdk/src/extdata.ts and HANDOFF.md.
        uint256 magnitude = withdrawAmount + fee;
        uint256 expected = magnitude; // = Σin − Σout (positive when value exits)
        if (publicAmount != expected) revert InvalidProof();
    }

    /// @dev Pull exactly `amount` of an ERC-20, measuring the received balance so
    ///      fee-on-transfer / rebasing tokens are rejected (SPEC §9 fee-on-transfer policy).
    function _pullExact(address token, address from, uint256 amount) internal {
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(from, address(this), amount);
        uint256 received = IERC20(token).balanceOf(address(this)) - balanceBefore;
        if (received != amount) revert FeeOnTransferToken();
    }

    /// @dev Send `amount` of `token` (native when 0) to `to`.
    function _payout(address token, address to, uint256 amount) internal {
        if (token == address(0)) {
            (bool ok,) = payable(to).call{ value: amount }("");
            if (!ok) revert WithdrawTransferFailed();
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }

    function _toMemory(uint256[] calldata arr) internal pure returns (uint256[] memory out) {
        out = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            out[i] = arr[i];
        }
    }
}
