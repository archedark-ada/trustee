// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {MandateRegistry} from "src/MandateRegistry.sol";

contract DeployMandateRegistry is Script {
    function run() external returns (MandateRegistry registry) {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address guardian = vm.envOr("MANDATE_GUARDIAN", deployer);

        vm.startBroadcast(deployerPrivateKey);
        registry = new MandateRegistry(guardian);
        vm.stopBroadcast();

        console2.log("MandateRegistry deployed at", address(registry));
        console2.log("Guardian", guardian);
    }
}
