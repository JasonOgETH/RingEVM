// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title RelayerFeeLib
/// @notice Pays a relayer its fee as part of settling a join-split.
///
/// @dev    Fee-theft / griefing resistance lives in the PROOF, not here: `relayer` and
///         `fee` are folded into `extDataHash` (SPEC §8, a LOCKED public input) and covered
///         by the EdDSA spend signature (SPEC §7). A relayer that edits its address or the
///         fee invalidates the proof. The fee is carved from the user's transacted value
///         via the `publicAmount = extAmount - fee` accounting (SPEC §8.2) — i.e. paid out
///         of a shielded output the proof commits to — so a relayer can neither inflate nor
///         steal it. This library only performs the transfer, safely.
library RelayerFeeLib {
    using SafeERC20 for IERC20;

    error RelayerRequired();
    error FeeTransferFailed();

    /// @notice Pay `fee` of `token` (native when `token == 0`) to `relayer`. No-op if fee 0.
    /// @dev    Caller (the pool) has already debited its custody ledger for `fee` and holds
    ///         reentrancy protection; this is the interaction step.
    function payFee(address token, address relayer, uint256 fee) internal {
        if (fee == 0) return;
        if (relayer == address(0)) revert RelayerRequired();
        if (token == address(0)) {
            (bool ok,) = payable(relayer).call{ value: fee }("");
            if (!ok) revert FeeTransferFailed();
        } else {
            IERC20(token).safeTransfer(relayer, fee);
        }
    }
}
