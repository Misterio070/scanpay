// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC8183JobEscrow {
    function complete(uint256 jobId, bytes32 attestationReason) external;
    function reject(uint256 jobId, bytes32 attestationReason) external;
}

interface IERC8004ValidationRegistry {
    function recordValidation(
        uint256 providerAgentId,
        bytes32 deliverableHash,
        bytes32 oracleAttestationHash,
        bool passed
    ) external;
}

interface IERC8004ReputationRegistry {
    function postFeedback(
        uint256 agentId,
        uint256 score,
        string calldata tag,
        bytes32 proofOfPaymentTxHash
    ) external;
}

contract ScanPayEvaluatorV2 {
    address public immutable scanPayOracleSigner;
    IERC8004ValidationRegistry public immutable validationRegistry;
    IERC8004ReputationRegistry public immutable reputationRegistry;

    event JobEvaluatedAndBridged(
        uint256 indexed jobId,
        uint256 indexed providerAgentId,
        bytes32 deliverableHash,
        bool passed,
        uint8 riskScore
    );

    error UnauthorizedOracle();
    error InvalidRiskThreshold();

    constructor(
        address _oracleSigner,
        address _validationRegistry,
        address _reputationRegistry
    ) {
        scanPayOracleSigner = _oracleSigner;
        validationRegistry = IERC8004ValidationRegistry(_validationRegistry);
        reputationRegistry = IERC8004ReputationRegistry(_reputationRegistry);
    }

    /**
     * @notice ასრულებს ERC-8183 ესქროუს შეფასებას და ავტომატურად წერს შედეგს ERC-8004 რეესტრებში.
     */
    function evaluateAndSettleJob(
        address escrowContract,
        uint256 jobId,
        uint256 providerAgentId,
        bytes32 deliverableHash,
        bytes32 oracleAttestationHash,
        bytes32 x402PaymentTxHash,
        uint8 riskScore,
        bool allowExecution
    ) external {
        if (msg.sender != scanPayOracleSigner) revert UnauthorizedOracle();

        // 1. ERC-8183 ესქროუს გადაწყვეტა (Complete ან Reject)
        if (allowExecution && riskScore <= 20) {
            IERC8183JobEscrow(escrowContract).complete(jobId, oracleAttestationHash);

            // 2. ERC-8004 Validation & Reputation ჩაწერა
            validationRegistry.recordValidation(
                providerAgentId,
                deliverableHash,
                oracleAttestationHash,
                true
            );
            reputationRegistry.postFeedback(
                providerAgentId,
                uint256(100 - riskScore) * 1e16, // ნორმალიზებული 18-დეციმალიანი ქულა
                "scanpay:ast-security-verified",
                x402PaymentTxHash
            );
        } else {
            IERC8183JobEscrow(escrowContract).reject(jobId, oracleAttestationHash);
            validationRegistry.recordValidation(
                providerAgentId,
                deliverableHash,
                oracleAttestationHash,
                false
            );
        }

        emit JobEvaluatedAndBridged(
            jobId,
            providerAgentId,
            deliverableHash,
            allowExecution && riskScore <= 20,
            riskScore
        );
    }
}