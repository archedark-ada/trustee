// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MandateRegistry
/// @notice On-chain registry for trusted AP2 mandate issuance and revocation.
contract MandateRegistry {
    error Unauthorized();
    error AgentPaused(address agent);
    error InvalidAgent();
    error InvalidIssuer();
    error InvalidHash();
    error InvalidExpiry();
    error InvalidSize();
    error InvalidCursor();
    error MandateNotFound(bytes32 mandateHash);
    error MandateAlreadyExists(bytes32 mandateHash);
    error MandateAlreadyRevoked(bytes32 mandateHash);

    struct MandateRecord {
        bytes32 mandateHash;
        bytes32 payloadHash;
        address issuer;
        address agent;
        uint64 issuedAt;
        uint64 expiresAt;
        uint64 revokedAt;
        string metadataURI;
    }

    /// @notice Guardian can manage trusted issuers and pause state for any agent.
    address public immutable guardian;

    mapping(bytes32 => MandateRecord) public mandates;
    mapping(address => mapping(address => bool)) public trustedIssuerForAgent;
    mapping(address => bool) public agentPaused;
    mapping(address => bytes32[]) private mandateHashesByAgent;

    event TrustedIssuerUpdated(address indexed agent, address indexed issuer, bool allowed);
    event AgentPauseUpdated(address indexed agent, bool paused, address indexed actor);
    event MandateIssued(
        bytes32 indexed mandateHash,
        bytes32 indexed payloadHash,
        address indexed issuer,
        address agent,
        uint256 expiresAt,
        string metadataURI
    );
    event MandateRevoked(bytes32 indexed mandateHash, address indexed issuer, uint256 revokedAt);

    constructor(address guardian_) {
        guardian = guardian_ == address(0) ? msg.sender : guardian_;
    }

    modifier onlyAgentOrGuardian(address agent) {
        if (msg.sender != agent && msg.sender != guardian) {
            revert Unauthorized();
        }
        _;
    }

    function setTrustedIssuer(address agent, address issuer, bool allowed) external onlyAgentOrGuardian(agent) {
        if (agent == address(0)) {
            revert InvalidAgent();
        }
        if (issuer == address(0)) {
            revert InvalidIssuer();
        }

        trustedIssuerForAgent[agent][issuer] = allowed;
        emit TrustedIssuerUpdated(agent, issuer, allowed);
    }

    function setAgentPaused(address agent, bool paused) external onlyAgentOrGuardian(agent) {
        if (agent == address(0)) {
            revert InvalidAgent();
        }

        agentPaused[agent] = paused;
        emit AgentPauseUpdated(agent, paused, msg.sender);
    }

    function issueMandateOnChain(
        bytes32 mandateHash,
        bytes32 payloadHash,
        address agent,
        uint64 expiresAt,
        string calldata metadataURI
    ) external {
        if (agent == address(0)) {
            revert InvalidAgent();
        }
        if (mandateHash == bytes32(0) || payloadHash == bytes32(0)) {
            revert InvalidHash();
        }
        if (expiresAt != 0 && expiresAt <= block.timestamp) {
            revert InvalidExpiry();
        }
        if (!trustedIssuerForAgent[agent][msg.sender]) {
            revert Unauthorized();
        }
        if (agentPaused[agent]) {
            revert AgentPaused(agent);
        }
        if (mandates[mandateHash].issuedAt != 0) {
            revert MandateAlreadyExists(mandateHash);
        }

        mandates[mandateHash] = MandateRecord({
            mandateHash: mandateHash,
            payloadHash: payloadHash,
            issuer: msg.sender,
            agent: agent,
            issuedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            revokedAt: 0,
            metadataURI: metadataURI
        });

        mandateHashesByAgent[agent].push(mandateHash);

        emit MandateIssued(mandateHash, payloadHash, msg.sender, agent, expiresAt, metadataURI);
    }

    function revokeMandate(bytes32 mandateHash) external {
        MandateRecord storage record = mandates[mandateHash];
        if (record.issuedAt == 0) {
            revert MandateNotFound(mandateHash);
        }
        if (record.issuer != msg.sender) {
            revert Unauthorized();
        }
        if (record.revokedAt != 0) {
            revert MandateAlreadyRevoked(mandateHash);
        }

        record.revokedAt = uint64(block.timestamp);
        emit MandateRevoked(mandateHash, msg.sender, block.timestamp);
    }

    function getMandateStatus(bytes32 mandateHash)
        external
        view
        returns (
            bool exists,
            bool active,
            bool revoked,
            uint64 expiresAt,
            address issuer,
            address agent,
            bytes32 payloadHash,
            string memory metadataURI
        )
    {
        MandateRecord storage record = mandates[mandateHash];
        exists = record.issuedAt != 0;
        revoked = exists && record.revokedAt != 0;
        bool expired = exists && record.expiresAt != 0 && record.expiresAt <= block.timestamp;
        active = exists && !revoked && !expired;
        expiresAt = record.expiresAt;
        issuer = record.issuer;
        agent = record.agent;
        payloadHash = record.payloadHash;
        metadataURI = record.metadataURI;
    }

    function getMandatesByAgentPaged(address agent, uint256 cursor, uint256 size)
        external
        view
        returns (bytes32[] memory hashes, uint256 nextCursor)
    {
        if (size == 0) {
            revert InvalidSize();
        }

        uint256 total = mandateHashesByAgent[agent].length;
        if (cursor > total) {
            revert InvalidCursor();
        }

        uint256 end = cursor + size;
        if (end > total) {
            end = total;
        }

        uint256 count = end - cursor;
        hashes = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            hashes[i] = mandateHashesByAgent[agent][cursor + i];
        }

        nextCursor = end;
    }
}
