// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MandateRegistry} from "src/MandateRegistry.sol";

contract MandateRegistryTest is Test {
    MandateRegistry internal registry;

    address internal guardian = address(0xA11CE);
    address internal agent = address(0xBEEF);
    address internal issuer = address(0xC0FFEE);
    address internal stranger = address(0xD00D);

    function setUp() public {
        registry = new MandateRegistry(guardian);
    }

    function testGuardianCanSetTrustedIssuer() public {
        vm.prank(guardian);
        registry.setTrustedIssuer(agent, issuer, true);

        assertTrue(registry.trustedIssuerForAgent(agent, issuer));
    }

    function testAgentCanSetTrustedIssuer() public {
        vm.prank(agent);
        registry.setTrustedIssuer(agent, issuer, true);

        assertTrue(registry.trustedIssuerForAgent(agent, issuer));
    }

    function testNonOwnerCannotSetTrustedIssuer() public {
        vm.prank(stranger);
        vm.expectRevert(MandateRegistry.Unauthorized.selector);
        registry.setTrustedIssuer(agent, issuer, true);
    }

    function testSetTrustedIssuerRejectsZeroAgent() public {
        vm.prank(guardian);
        vm.expectRevert(MandateRegistry.InvalidAgent.selector);
        registry.setTrustedIssuer(address(0), issuer, true);
    }

    function testSetTrustedIssuerRejectsZeroIssuer() public {
        vm.prank(guardian);
        vm.expectRevert(MandateRegistry.InvalidIssuer.selector);
        registry.setTrustedIssuer(agent, address(0), true);
    }

    function testGuardianCanPauseAgent() public {
        vm.prank(guardian);
        registry.setAgentPaused(agent, true);

        assertTrue(registry.agentPaused(agent));
    }

    function testAgentCanPauseSelf() public {
        vm.prank(agent);
        registry.setAgentPaused(agent, true);

        assertTrue(registry.agentPaused(agent));
    }

    function testNonOwnerCannotPauseAgent() public {
        vm.prank(stranger);
        vm.expectRevert(MandateRegistry.Unauthorized.selector);
        registry.setAgentPaused(agent, true);
    }

    function testIssueMandateRejectsUntrustedIssuer() public {
        vm.prank(issuer);
        vm.expectRevert(MandateRegistry.Unauthorized.selector);
        registry.issueMandateOnChain(_hash("m1"), _hash("p1"), agent, _futureExpiry(1 days), "ipfs://m1");
    }

    function testIssueMandateRejectsPausedAgent() public {
        _trustIssuer();

        vm.prank(guardian);
        registry.setAgentPaused(agent, true);

        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(MandateRegistry.AgentPaused.selector, agent));
        registry.issueMandateOnChain(_hash("m1"), _hash("p1"), agent, _futureExpiry(1 days), "ipfs://m1");
    }

    function testIssueMandateRejectsDuplicateHash() public {
        _trustIssuer();

        bytes32 mandateHash = _hash("m1");
        bytes32 payloadHash = _hash("p1");

        vm.prank(issuer);
        registry.issueMandateOnChain(mandateHash, payloadHash, agent, _futureExpiry(1 days), "ipfs://m1");

        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(MandateRegistry.MandateAlreadyExists.selector, mandateHash));
        registry.issueMandateOnChain(mandateHash, payloadHash, agent, _futureExpiry(2 days), "ipfs://m1b");
    }

    function testIssueMandateStoresAndReturnsStatus() public {
        _trustIssuer();

        bytes32 mandateHash = _hash("m1");
        bytes32 payloadHash = _hash("p1");
        uint64 expiresAt = _futureExpiry(1 days);

        vm.prank(issuer);
        registry.issueMandateOnChain(mandateHash, payloadHash, agent, expiresAt, "ipfs://m1");

        (
            bool exists,
            bool active,
            bool revoked,
            uint64 returnedExpiresAt,
            address returnedIssuer,
            address returnedAgent,
            bytes32 returnedPayloadHash,
            string memory metadataURI
        ) = registry.getMandateStatus(mandateHash);

        assertTrue(exists);
        assertTrue(active);
        assertFalse(revoked);
        assertEq(returnedExpiresAt, expiresAt);
        assertEq(returnedIssuer, issuer);
        assertEq(returnedAgent, agent);
        assertEq(returnedPayloadHash, payloadHash);
        assertEq(metadataURI, "ipfs://m1");
    }

    function testGetMandateStatusExpired() public {
        _trustIssuer();

        bytes32 mandateHash = _hash("m1");

        vm.prank(issuer);
        registry.issueMandateOnChain(mandateHash, _hash("p1"), agent, _futureExpiry(100), "ipfs://m1");

        vm.warp(block.timestamp + 101);

        (, bool active,, uint64 expiresAt,,,,) = registry.getMandateStatus(mandateHash);
        assertFalse(active);
        assertEq(expiresAt, uint64(block.timestamp - 1));
    }

    function testRevokeMandateIssuerOnly() public {
        _trustIssuer();
        bytes32 mandateHash = _hash("m1");

        vm.prank(issuer);
        registry.issueMandateOnChain(mandateHash, _hash("p1"), agent, _futureExpiry(1 days), "ipfs://m1");

        vm.prank(stranger);
        vm.expectRevert(MandateRegistry.Unauthorized.selector);
        registry.revokeMandate(mandateHash);

        vm.prank(issuer);
        registry.revokeMandate(mandateHash);

        (, bool active, bool revoked,,,,,) = registry.getMandateStatus(mandateHash);
        assertFalse(active);
        assertTrue(revoked);
    }

    function testRevokeMandateRejectsUnknownHash() public {
        vm.prank(issuer);
        bytes32 missingHash = _hash("missing");
        vm.expectRevert(abi.encodeWithSelector(MandateRegistry.MandateNotFound.selector, missingHash));
        registry.revokeMandate(missingHash);
    }

    function testRevokeMandateRejectsAlreadyRevoked() public {
        _trustIssuer();
        bytes32 mandateHash = _hash("m1");

        vm.prank(issuer);
        registry.issueMandateOnChain(mandateHash, _hash("p1"), agent, _futureExpiry(1 days), "ipfs://m1");

        vm.prank(issuer);
        registry.revokeMandate(mandateHash);

        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(MandateRegistry.MandateAlreadyRevoked.selector, mandateHash));
        registry.revokeMandate(mandateHash);
    }

    function testIssueRejectsPastExpiry() public {
        _trustIssuer();

        vm.prank(issuer);
        vm.expectRevert(MandateRegistry.InvalidExpiry.selector);
        registry.issueMandateOnChain(_hash("m1"), _hash("p1"), agent, uint64(block.timestamp), "ipfs://m1");
    }

    function testPaginationReturnsHashesAcrossPagesIncludingRevoked() public {
        _trustIssuer();

        bytes32 h1 = _hash("m1");
        bytes32 h2 = _hash("m2");
        bytes32 h3 = _hash("m3");

        vm.startPrank(issuer);
        registry.issueMandateOnChain(h1, _hash("p1"), agent, _futureExpiry(1 days), "ipfs://m1");
        registry.issueMandateOnChain(h2, _hash("p2"), agent, _futureExpiry(1 days), "ipfs://m2");
        registry.issueMandateOnChain(h3, _hash("p3"), agent, _futureExpiry(1 days), "ipfs://m3");
        registry.revokeMandate(h2);
        vm.stopPrank();

        (bytes32[] memory page1, uint256 next1) = registry.getMandatesByAgentPaged(agent, 0, 2);
        assertEq(page1.length, 2);
        assertEq(page1[0], h1);
        assertEq(page1[1], h2);
        assertEq(next1, 2);

        (bytes32[] memory page2, uint256 next2) = registry.getMandatesByAgentPaged(agent, next1, 2);
        assertEq(page2.length, 1);
        assertEq(page2[0], h3);
        assertEq(next2, 3);
    }

    function testPaginationRejectsZeroSize() public {
        vm.expectRevert(MandateRegistry.InvalidSize.selector);
        registry.getMandatesByAgentPaged(agent, 0, 0);
    }

    function testPaginationRejectsInvalidCursor() public {
        vm.expectRevert(MandateRegistry.InvalidCursor.selector);
        registry.getMandatesByAgentPaged(agent, 1, 1);
    }

    function _trustIssuer() internal {
        vm.prank(guardian);
        registry.setTrustedIssuer(agent, issuer, true);
    }

    function _hash(string memory seed) internal pure returns (bytes32) {
        return keccak256(bytes(seed));
    }

    function _futureExpiry(uint256 delta) internal view returns (uint64) {
        return uint64(block.timestamp + delta);
    }
}
