// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {RailsVault} from "../src/RailsVault.sol";

/// @notice Draws the demo policy on an already-deployed RailsVault (owner must be the broadcaster).
///
/// Configuration (env):
///   RAILS_VAULT — deployed vault address (required)
///   RAILS_OWNER — route target for the plain-transfer demo route (required)
///
/// Three transactions, all owner-only:
///   02 interlocking — allow plain ETH transfers to the owner (selector 0x00000000)
///   03 axle limit   — 0.4 / 1.0 / 2.0 ETH per tx / hour / day
///   04 loop line    — hold anything above 0.25 ETH for the constructor's delay (21600s)
///
/// The vault holds no funds; this only writes policy so the table has real state to read.
contract Draw is Script {
    function run() external {
        address vaultAddr = vm.envAddress("RAILS_VAULT");
        address ownerAddr = vm.envAddress("RAILS_OWNER");
        RailsVault vault = RailsVault(payable(vaultAddr));

        console2.log("vault before: revision =", vault.revision(), "routes =", vault.routesCount());

        vm.startBroadcast();
        vault.setRoute(ownerAddr, bytes4(0), "ETH transfer");
        vault.setLimits(0.4 ether, 1 ether, 2 ether);
        vault.setLoopConfig(0.25 ether, 21600);
        vm.stopBroadcast();

        console2.log("vault after : revision =", vault.revision(), "routes =", vault.routesCount());
        console2.log("limits      : 0.4 / 1.0 / 2.0 ETH (tx/hour/day)");
        console2.log("loop line   : hold above 0.25 ETH for 21600s");
    }
}
