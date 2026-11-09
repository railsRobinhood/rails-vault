// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {RailsVault} from "../src/RailsVault.sol";

/// @notice Deploys one RailsVault with a parameterized owner / agent / loop delay.
///
/// Configuration (env vars, all optional):
///   RAILS_OWNER      — initial owner; defaults to the broadcaster (the keystore wallet).
///   RAILS_AGENT      — initial agent; defaults to the owner.
///   RAILS_LOOP_DELAY — seconds a held call waits in the loop line; defaults to
///                      21600 (6 hours).
///
/// The new policy vault starts undrawn: no routes, no caps, holding disabled.
/// The owner draws the four signals (setRoute / setLimits / setLoopConfig) before
/// funding it — see docs/contract-deploy-manual.md.
contract Deploy is Script {
    /// @notice Env-driven entry point: forge script script/Deploy.s.sol:Deploy --broadcast ...
    function run() external returns (RailsVault vault) {
        address ownerAddr = vm.envOr("RAILS_OWNER", address(0));
        address agentAddr = vm.envOr("RAILS_AGENT", address(0));
        uint256 delay = vm.envOr("RAILS_LOOP_DELAY", uint256(21600));
        if (ownerAddr == address(0)) ownerAddr = msg.sender;
        if (agentAddr == address(0)) agentAddr = ownerAddr;
        vault = _deploy(ownerAddr, agentAddr, delay);
    }

    /// @notice Explicit-args entry point:
    ///         forge script script/Deploy.s.sol:Deploy \
    ///           --sig "runWith(address,address,uint256)" <owner> <agent> <delaySeconds> \
    ///           --broadcast ...
    function runWith(address ownerAddr, address agentAddr, uint256 delay)
        external
        returns (RailsVault vault)
    {
        vault = _deploy(ownerAddr, agentAddr, delay);
    }

    function _deploy(address ownerAddr, address agentAddr, uint256 delay)
        internal
        returns (RailsVault vault)
    {
        vm.startBroadcast();
        vault = new RailsVault(ownerAddr, agentAddr, delay);
        vm.stopBroadcast();

        console2.log("---------------------------------------------------------");
        console2.log("RAILS_VAULT_ADDRESS   =", address(vault));
        console2.log("owner                 =", ownerAddr);
        console2.log("agent                 =", agentAddr);
        console2.log("loopDelay (seconds)   =", delay);
        console2.log("Policy state          = undrawn (no routes, no caps)");
        console2.log("Next: draw routes + limits with the owner wallet, then fund.");
        console2.log("---------------------------------------------------------");
    }
}
