// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../SecureVault.sol";

/**
 * @title MaliciousReentrantRecipient
 * @notice Helper contract designed to attempt a reentrant call into `withdraw` during ETH transfer.
 */
contract MaliciousReentrantRecipient {
    SecureVault public vault;
    bytes public replaySignature;
    uint256 public replayAmount;
    uint256 public replayNonce;
    bool public attacked;

    constructor(address payable _vault) {
        vault = SecureVault(_vault);
    }

    function setAttackParams(uint256 _amount, uint256 _nonce, bytes calldata _sig) external {
        replayAmount = _amount;
        replayNonce = _nonce;
        replaySignature = _sig;
        attacked = false;
    }

    receive() external payable {
        if (!attacked) {
            attacked = true;
            // Attempt reentrancy back into vault.withdraw
            vault.withdraw(payable(address(this)), replayAmount, replayNonce, replaySignature);
        }
    }
}

/**
 * @title RejectingRecipient
 * @notice Helper contract that rejects all incoming ETH transfers.
 */
contract RejectingRecipient {
    receive() external payable {
        revert("RejectingRecipient: Refusing ETH transfer");
    }
}
