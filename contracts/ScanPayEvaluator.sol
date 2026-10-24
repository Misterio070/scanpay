// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ScanPayEvaluator
 * @notice ERC-8183 Agentic Commerce Protocol Evaluator & ERC-8004 Validation Registry Bridge.
 * @dev Verifies deterministic ScanPay AST security attestations before releasing escrowed funds
 *      for autonomous AI agent code deliverables.
 */
interface IERC8183JobEscrow {
    function completeJob(bytes32 jobId, bytes calldata deliverableData) external;
    function rejectJob(bytes32 jobId, string calldata reason) external;
}

interface IERC8004ValidationRegistry {
    function recordValidation(address agent, bytes32 jobHash, uint8 score, bytes calldata proof) external;
}

contract ScanPayEvaluator {
    address public immutable owner;
    address public oracleSigner;
    address public validationRegistry;

    event DeliverableEvaluated(bytes32 indexed jobId, address indexed provider, bool passed, bytes32 deliverableHash);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);

    error Unauthorized();
    error InvalidOracleSignature();
    error DeliverableSecurityBlocked();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor(address _oracleSigner, address _validationRegistry) {
        owner = msg.sender;
        oracleSigner = _oracleSigner;
        validationRegistry = _validationRegistry;
    }

    function setOracleSigner(address _newOracle) external onlyOwner {
        emit OracleUpdated(oracleSigner, _newOracle);
        oracleSigner = _newOracle;
    }

    /**
     * @notice Evaluates deliverable code attestation issued by ScanPay.
     * @param escrow Address of the ERC-8183 JobEscrow contract.
     * @param jobId Unique identifier of the agentic commerce job.
     * @param provider Address of the agent provider submitting the code.
     * @param deliverableHash SHA256 / keccak hash of the scanned deliverable code.
     * @param verdict Verdict issued by ScanPay ("PASS" required for completion).
     * @param signature Cryptographic oracle signature over (jobId, deliverableHash, verdict).
     */
    function evaluateAndComplete(
        address escrow,
        bytes32 jobId,
        address provider,
        bytes32 deliverableHash,
        string calldata verdict,
        bytes calldata signature
    ) external {
        if (keccak256(bytes(verdict)) != keccak256(bytes("PASS"))) {
            IERC8183JobEscrow(escrow).rejectJob(jobId, "ScanPay: Security audit verdict not PASS");
            emit DeliverableEvaluated(jobId, provider, false, deliverableHash);
            return;
        }

        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(jobId, deliverableHash, verdict)))
        );

        address recovered = recoverSigner(messageHash, signature);
        if (recovered != oracleSigner) {
            revert InvalidOracleSignature();
        }

        // Release escrowed funds on ERC-8183 contract
        IERC8183JobEscrow(escrow).completeJob(jobId, abi.encode(deliverableHash, verdict));

        // Optionally record proof in ERC-8004 Validation Registry
        if (validationRegistry != address(0)) {
            IERC8004ValidationRegistry(validationRegistry).recordValidation(
                provider,
                jobId,
                100,
                signature
            );
        }

        emit DeliverableEvaluated(jobId, provider, true, deliverableHash);
    }

    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) revert InvalidOracleSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        return ecrecover(messageHash, v, r, s);
    }
}
