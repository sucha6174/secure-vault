// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./interfaces/IAuthorizationManager.sol";

/**
 * @title SecureVault
 * @author sucha6174
 * @notice Pooled custody vault holding native ETH, delegating withdrawal authorization to an external AuthorizationManager.
 *
 * ARCHITECTURAL DESIGN & RESPONSIBILITIES:
 * - Operates as a pooled asset custody vault: deposits from any address are pooled into native ETH balance.
 * - Fund movement is strictly authorization-governed: native ETH transfers can ONLY be initiated after an explicit,
 *   off-chain authorization is confirmed and consumed by the external AuthorizationManager contract.
 * - Separation of Concerns: The vault performs NO cryptographic signature verification itself. It relies exclusively
 *   on the AuthorizationManager to validate and consume permissions.
 *
 * @custom:invariant INV-VAULT-1: Vault ETH balance can never become negative (enforced by EVM balance semantics and pre-transfer balance check).
 * @custom:invariant INV-VAULT-2: Withdrawals succeed only after authorization manager confirms and consumes authorization.
 * @custom:invariant INV-VAULT-3: Internal accounting (totalWithdrawn) increments exactly once per successful withdrawal.
 * @custom:invariant INV-VAULT-4: Checks-Effects-Interactions pattern: internal accounting is updated BEFORE external ETH transfer.
 * @custom:invariant INV-VAULT-5: Reentrancy protection via ReentrancyGuard and single-use authorization consumption.
 * @custom:invariant INV-VAULT-6: Initialization can only be executed once, exclusively by the contract owner.
 * @custom:invariant INV-VAULT-7: Failed external value transfers revert atomically, leaving internal accounting intact.
 */
contract SecureVault is Ownable, ReentrancyGuard {
    /// @notice Address of the AuthorizationManager contract governing withdrawal permissions.
    IAuthorizationManager public authManager;

    /// @notice Tracks whether the contract initialization has been completed.
    bool public initialized;

    /// @notice Cumulative total of all ETH successfully withdrawn from this vault.
    uint256 public totalWithdrawn;

    /// @notice Cumulative total of all ETH deposited into this vault.
    uint256 public totalDeposited;

    /**
     * @notice Emitted when native currency (ETH) is deposited into the vault.
     * @param sender The address depositing ETH.
     * @param amount The deposited ETH amount in wei.
     */
    event Deposit(address indexed sender, uint256 amount);

    /**
     * @notice Emitted when an authorized withdrawal is successfully executed.
     * @param recipient The recipient address receiving the withdrawn ETH.
     * @param amount The amount of ETH transferred in wei.
     */
    event Withdrawal(address indexed recipient, uint256 amount);

    /**
     * @notice Sets deployer as the initial owner.
     * @dev Explicit access control ensures only deployer can perform initialization.
     */
    constructor() Ownable(msg.sender) {}

    /**
     * @notice Initializes the vault with the AuthorizationManager contract address.
     * @dev Protected by `onlyOwner` to prevent malicious front-running during deployment.
     * @param _authManager The address of the deployed AuthorizationManager contract.
     */
    function initialize(address _authManager) external onlyOwner {
        require(!initialized, "Already initialized");
        require(_authManager != address(0), "Invalid auth manager");

        authManager = IAuthorizationManager(_authManager);
        initialized = true;
    }

    /**
     * @notice Accepts native ETH deposits from any sender.
     */
    receive() external payable {
        _handleDeposit();
    }

    /**
     * @notice Explicit deposit function allowing callers to deposit ETH.
     */
    function deposit() external payable {
        _handleDeposit();
    }

    /**
     * @dev Internal helper for deposit accounting and event emission.
     */
    function _handleDeposit() internal {
        require(msg.value > 0, "Deposit must be greater than zero");
        totalDeposited += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Executes an authorized withdrawal of pooled funds to a recipient.
     * @dev Delegates permission validation to AuthorizationManager and follows Checks-Effects-Interactions.
     * @param recipient The destination address receiving the withdrawn ETH.
     * @param amount The amount of ETH to withdraw in wei.
     * @param nonce The unique nonce for the authorization.
     * @param signature The cryptographic signature approving this withdrawal.
     */
    function withdraw(
        address payable recipient,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant {
        require(initialized, "Not initialized");
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");
        require(address(this).balance >= amount, "Insufficient balance");

        // Validate and consume authorization exclusively via the external AuthorizationManager
        bool ok = authManager.verifyAuthorization(
            address(this),
            recipient,
            amount,
            nonce,
            signature
        );
        require(ok, "Authorization failed");

        // Checks-Effects-Interactions: state updated before external transfer
        totalWithdrawn += amount;

        emit Withdrawal(recipient, amount);

        // Value transfer: transfer ETH to recipient
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    /**
     * @notice Returns the current native ETH balance held by the vault.
     * @return Current balance in wei.
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
