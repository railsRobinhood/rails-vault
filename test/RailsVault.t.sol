// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {RailsVault} from "../src/RailsVault.sol";

/// ------------------------------------------------------------------ mocks

/// @dev Stand-in for a routed destination: records incoming native value, can
///      fail on demand, can attempt reentry into the vault, can refund a share.
contract TargetMock {
    address public immutable vault;
    uint256 public timesCalled;
    bool public failNext;
    bool public reenterNext;
    bytes public lastReentryRevert; // raw revert data of the last reentry attempt
    uint256 public refundBps; // share (0..10000) of incoming value sent back

    constructor(address vault_) {
        vault = vault_;
    }

    function setFailNext(bool f) external {
        failNext = f;
    }

    function setReenterNext(bool f) external {
        reenterNext = f;
    }

    function setRefundBps(uint256 b) external {
        refundBps = b;
    }

    receive() external payable {
        timesCalled++;
        if (reenterNext) {
            reenterNext = false;
            (bool ok, bytes memory ret) =
                vault.call(abi.encodeCall(RailsVault.execute, (address(this), 0, "")));
            if (!ok) {
                lastReentryRevert = ret; // swallowed: the outer call must not break
            }
        }
        if (failNext) {
            failNext = false;
            revert("target refused this call");
        }
        if (refundBps > 0 && msg.value > 0) {
            uint256 back = (msg.value * refundBps) / 10000;
            if (back > 0) {
                (bool ok, ) = payable(vault).call{value: back}("");
                require(ok, "refund failed");
            }
        }
    }
}

/// @dev Stand-in for an ERC-20 surface used to probe unlimited-approval refusals.
contract TokenMock {
    uint256 public lastApproved;
    address public lastSpender;
    bool public lastApprovedForAll;

    function approve(address spender, uint256 amount) external returns (bool) {
        lastApproved = amount;
        lastSpender = spender;
        return true;
    }

    function increaseAllowance(address spender, uint256 added) external returns (bool) {
        lastApproved = added;
        lastSpender = spender;
        return true;
    }

    function setApprovalForAll(address operator, bool approved) external {
        lastSpender = operator;
        lastApprovedForAll = approved;
    }
}

/// ------------------------------------------------------------------ tests

contract RailsVaultTest is Test {
    RailsVault internal vault;
    TargetMock internal target;
    TokenMock internal token;

    address internal ownerAddr;
    address internal agentAddr;
    address internal stranger;

    uint256 internal constant MAX_PER_TX = 3 ether;
    uint256 internal constant MAX_PER_HOUR = 5 ether;
    uint256 internal constant MAX_PER_DAY = 8 ether;
    uint256 internal constant HOLD_ABOVE = 2 ether;
    uint256 internal constant LOOP_DELAY = 100; // seconds
    uint256 internal constant FUND = 100 ether;

    bytes4 internal constant SEL_PLAIN = 0x00000000;
    bytes4 internal constant SEL_ROGUE = 0xffffffff;
    bytes4 internal constant SEL_APPROVE = 0x095ea7b3;
    bytes4 internal constant SEL_INCREASE_ALLOWANCE = 0x39509351;
    bytes4 internal constant SEL_SET_APPROVAL_FOR_ALL = 0xa22cb465;

    function setUp() public {
        ownerAddr = makeAddr("owner");
        agentAddr = makeAddr("agent");
        stranger = makeAddr("stranger");
        vault = new RailsVault(ownerAddr, agentAddr, LOOP_DELAY);
        vm.deal(address(vault), FUND);
        target = new TargetMock(address(vault));
        token = new TokenMock();
    }

    // ------------------------------------------------------------ helpers

    function _routePlain() internal {
        _routePlain(address(target));
    }

    function _routePlain(address t) internal {
        vm.prank(ownerAddr);
        vault.setRoute(t, SEL_PLAIN, "ETH transfer");
    }

    function _route(address t, bytes4 sel) internal {
        vm.prank(ownerAddr);
        vault.setRoute(t, sel, "drawn route");
    }

    function _policy() internal {
        vm.startPrank(ownerAddr);
        vault.setLimits(MAX_PER_TX, MAX_PER_HOUR, MAX_PER_DAY);
        vault.setLoopConfig(HOLD_ABOVE, LOOP_DELAY);
        vm.stopPrank();
    }

    /// @dev Signal-03 isolation: same caps, loop line disabled so every
    ///      within-cap value lands instead of queueing.
    function _policyNoHold() internal {
        _routePlain();
        vm.startPrank(ownerAddr);
        vault.setLimits(MAX_PER_TX, MAX_PER_HOUR, MAX_PER_DAY);
        vault.setLoopConfig(0, LOOP_DELAY);
        vm.stopPrank();
    }

    function _fullSetup() internal {
        _routePlain();
        _policy();
    }

    function _land(uint256 value) internal {
        vm.prank(agentAddr);
        vault.execute(address(target), value, "");
    }

    function _queue(uint256 value) internal returns (uint256 index) {
        index = vault.loopEntriesTotal();
        vm.prank(agentAddr);
        vault.execute(address(target), value, "");
    }

    /// @dev `sealed()` exists only through the fallback (reserved keyword) — read it low-level.
    function _readSealed() internal view returns (bool) {
        (bool ok, bytes memory ret) =
            address(vault).staticcall(abi.encodeWithSignature("sealed()"));
        assertTrue(ok, "sealed() read must succeed");
        return abi.decode(ret, (bool));
    }

    // ============================================================== signal 01

    function test_Signal01_SealUnsealRoundTripAndEvents() public {
        vm.expectEmit(true, true, false, true);
        emit RailsVault.SealedStateChanged(true);
        vm.prank(ownerAddr);
        vault.seal();
        assertTrue(_readSealed(), "vault must be sealed");

        vm.expectEmit(true, true, false, true);
        emit RailsVault.SealedStateChanged(false);
        vm.prank(ownerAddr);
        vault.unseal();
        assertFalse(_readSealed(), "vault must be unsealed");
        // operational action: no revision bump
        assertEq(vault.revision(), 0, "seal/unseal must not bump revision");
    }

    function test_Signal01_SealBlocksExecute() public {
        _fullSetup();
        vm.prank(ownerAddr);
        vault.seal();
        vm.prank(agentAddr);
        vm.expectRevert(RailsVault.Signal01Sealed.selector);
        vault.execute(address(target), 1 ether, "");
    }

    function test_Signal01_SealBlocksRelease() public {
        _fullSetup();
        uint256 idx = _queue(2.5 ether);
        vm.prank(ownerAddr);
        vault.seal();
        vm.warp(block.timestamp + LOOP_DELAY);
        vm.prank(agentAddr);
        vm.expectRevert(RailsVault.Signal01Sealed.selector);
        vault.release(idx);
        assertTrue(_readSealed() && vault.loopQueueLength() == 1, "entry must survive seal");
        vm.prank(ownerAddr);
        vault.unseal();
        vm.prank(agentAddr);
        vault.release(idx); // now lands
        assertEq(address(target).balance, 2.5 ether, "released after unseal");
    }

    function test_Signal01_StateUnchangedReverts() public {
        vm.prank(ownerAddr);
        vm.expectRevert(RailsVault.Signal01AlreadyClear.selector);
        vault.unseal();
        vm.prank(ownerAddr);
        vault.seal();
        vm.prank(ownerAddr);
        vm.expectRevert(RailsVault.Signal01AlreadySet.selector);
        vault.seal();
    }

    function test_Signal01_OnlyOwnerCanSealOrUnseal() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vault.seal();
        vm.prank(agentAddr);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, agentAddr));
        vault.unseal();
    }

    function test_Signal01_OwnerExecuteRescuesWhileSealed() public {
        _fullSetup();
        vm.prank(ownerAddr);
        vault.seal();
        vm.expectEmit(true, false, false, true);
        emit RailsVault.OwnerExecuted(address(target), 4 ether, "");
        vm.prank(ownerAddr);
        vault.ownerExecute(address(target), 4 ether, "");
        assertEq(address(target).balance, 4 ether, "rescue landed");
        assertEq(address(vault).balance, FUND - 4 ether, "vault debited");
        vm.prank(agentAddr);
        vm.expectRevert(RailsVault.Signal01Sealed.selector);
        vault.execute(address(target), 1 ether, ""); // agent still frozen
    }

    function test_Signal01_CancelWorksWhileSealed() public {
        _fullSetup();
        uint256 idx = _queue(2.5 ether);
        vm.prank(ownerAddr);
        vault.seal();
        vm.expectEmit(true, true, false, true);
        emit RailsVault.CallCancelled(idx, address(target), 2.5 ether);
        vm.prank(ownerAddr);
        vault.cancelQueued(idx);
        assertEq(vault.loopQueueLength(), 0, "cancelled leaves the open queue");
    }

    // ============================================================== signal 02

    function test_Signal02_SetRouteEnumerates() public {
        address other = makeAddr("other");
        vm.expectEmit(true, true, false, true);
        emit RailsVault.RouteChanged(address(target), SEL_PLAIN, true, "ETH transfer");
        vm.prank(ownerAddr);
        vault.setRoute(address(target), SEL_PLAIN, "ETH transfer");
        vm.expectEmit(true, true, false, true);
        emit RailsVault.RouteChanged(other, SEL_PLAIN, true, "second board point");
        vm.prank(ownerAddr);
        vault.setRoute(other, SEL_PLAIN, "second board point");

        assertEq(vault.routesCount(), 2, "two drawn routes");
        (address t0, string memory l0) = vault.route(0);
        (address t1, string memory l1) = vault.route(1);
        assertEq(t0, address(target));
        assertEq(t1, other);
        assertEq(l0, "ETH transfer");
        assertEq(l1, "second board point");
        assertEq(vault.revision(), 2, "each route draw revises policy");
    }

    function test_Signal02_ClearRouteRemovesAndDenseSwaps() public {
        address a = makeAddr("a");
        address b = makeAddr("b");
        vm.startPrank(ownerAddr);
        vault.setRoute(a, SEL_PLAIN, "A");
        vault.setRoute(b, SEL_PLAIN, "B");
        vault.clearRoute(a, SEL_PLAIN);
        vm.stopPrank();
        assertEq(vault.routesCount(), 1, "one route left");
        (address t0, string memory l0) = vault.route(0);
        assertEq(t0, b, "last key moved into the cleared slot");
        assertEq(l0, "B");
        vm.expectRevert(abi.encodeWithSelector(RailsVault.RouteIndexOutOfBounds.selector, 1));
        vault.route(1);
    }

    function test_Signal02_ExecuteUnroutedRefused() public {
        _policy();
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal02Unrouted.selector, address(target), SEL_PLAIN)
        );
        vault.execute(address(target), 1 ether, "");
    }

    function test_Signal02_SelectorMismatchRefused() public {
        _routePlain();
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                RailsVault.Signal02Unrouted.selector, address(target), bytes4(0x12345678)
            )
        );
        vault.execute(address(target), 0, hex"12345678");
    }

    function test_Signal02_ClearRouteThenExecuteRefused() public {
        _fullSetup();
        vm.prank(ownerAddr);
        vault.clearRoute(address(target), SEL_PLAIN);
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal02Unrouted.selector, address(target), SEL_PLAIN)
        );
        vault.execute(address(target), 1 ether, "");
    }

    function test_Signal02_RouteControlsAreOwnerOnly() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vault.setRoute(address(target), SEL_PLAIN, "x");
        vm.prank(agentAddr);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, agentAddr));
        vault.clearRoute(address(target), SEL_PLAIN);
    }

    function test_Signal02_SelfRouteForbidden() public {
        vm.prank(ownerAddr);
        vm.expectRevert(RailsVault.Signal02SelfRoute.selector);
        vault.setRoute(address(vault), SEL_PLAIN, "self");
        // even without any route, calling the vault itself is refused first
        vm.prank(agentAddr);
        vm.expectRevert(RailsVault.Signal02SelfRoute.selector);
        vault.execute(address(vault), 1 ether, "");
    }

    function test_Signal02_RogueSelectorForbidden() public {
        vm.prank(ownerAddr);
        vm.expectRevert(RailsVault.Signal02RogueSelector.selector);
        vault.setRoute(address(target), SEL_ROGUE, "rogue");
    }

    function test_Signal02_PartialAndZeroPrefixedCalldataNeverRoute() public {
        _routePlain();
        // 2-byte calldata can never ride a drawn route
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal02Unrouted.selector, address(target), SEL_ROGUE)
        );
        vault.execute(address(target), 0, hex"0102");
        // zero-prefixed calldata must not ride the plain-send route
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal02Unrouted.selector, address(target), SEL_ROGUE)
        );
        vault.execute(address(target), 0, hex"00000000");
    }

    function test_Signal02_UnlimitedApproveRefused() public {
        _route(address(token), SEL_APPROVE);
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                RailsVault.Signal02UnlimitedApproval.selector, address(token), SEL_APPROVE
            )
        );
        vault.execute(address(token), 0, abi.encodeCall(TokenMock.approve, (stranger, type(uint256).max)));
        // a bounded allowance is fine and lands
        vm.prank(agentAddr);
        vault.execute(address(token), 0, abi.encodeCall(TokenMock.approve, (stranger, 1 ether)));
        assertEq(token.lastApproved(), 1 ether);
        assertEq(token.lastSpender(), stranger);
    }

    function test_Signal02_UnlimitedIncreaseAllowanceAndApproveForAllRefused() public {
        _route(address(token), SEL_INCREASE_ALLOWANCE);
        _route(address(token), SEL_SET_APPROVAL_FOR_ALL);
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                RailsVault.Signal02UnlimitedApproval.selector,
                address(token),
                SEL_INCREASE_ALLOWANCE
            )
        );
        vault.execute(
            address(token), 0, abi.encodeCall(TokenMock.increaseAllowance, (stranger, type(uint256).max))
        );
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                RailsVault.Signal02UnlimitedApproval.selector,
                address(token),
                SEL_SET_APPROVAL_FOR_ALL
            )
        );
        vault.execute(address(token), 0, abi.encodeCall(TokenMock.setApprovalForAll, (stranger, true)));
        // revoking approval-for-all is not a grant and lands
        vm.prank(agentAddr);
        vault.execute(address(token), 0, abi.encodeCall(TokenMock.setApprovalForAll, (stranger, false)));
        assertFalse(token.lastApprovedForAll());
    }

    function test_Signal02_RouteIndexOutOfBounds() public {
        vm.expectRevert(abi.encodeWithSelector(RailsVault.RouteIndexOutOfBounds.selector, 0));
        vault.route(0);
    }

    // ============================================================== signal 03

    function test_Signal03_OverPerTxRefused() public {
        _fullSetup();
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal03OverPerTx.selector, 3.5 ether, MAX_PER_TX)
        );
        vault.execute(address(target), 3.5 ether, "");
        assertEq(address(vault).balance, FUND, "refused: funds untouched");
    }

    function test_Signal03_HourBoundaryExactPassThenRefuse() public {
        _policyNoHold();
        _land(3 ether); // hour spent 3
        _land(2 ether); // 3 + 2 == 5 == cap: exact boundary passes
        assertEq(vault.axleSpentThisHour(), 5 ether);
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal03OverPerHour.selector, 1 ether, 5 ether, 5 ether)
        );
        vault.execute(address(target), 1 ether, "");
    }

    function test_Signal03_DayCapRefusedAcrossHourResets() public {
        _policyNoHold();
        vm.warp(10 days + 3 hours); // pin inside a known hour/day
        _land(3 ether); // day 3
        vm.warp(block.timestamp + 1 hours); // hour resets, day keeps 3
        _land(3 ether); // day 6
        vm.warp(block.timestamp + 1 hours);
        _land(2 ether); // day 8 == cap: passes
        assertEq(vault.axleSpentToday(), 8 ether);
        vm.warp(block.timestamp + 1 hours);
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal03OverPerDay.selector, 1 ether, 8 ether, 8 ether)
        );
        vault.execute(address(target), 1 ether, ""); // day 9 > 8
    }

    function test_Signal03_BucketRolloverResetsCounters() public {
        _policyNoHold();
        vm.warp(10 days + 3 hours);
        _land(3 ether);
        assertEq(vault.axleSpentToday(), 3 ether);
        assertEq(vault.axleSpentThisHour(), 3 ether);
        vm.warp(block.timestamp + 1 hours); // cross hour boundary
        assertEq(vault.axleSpentThisHour(), 0, "hour window reset");
        assertEq(vault.axleSpentToday(), 3 ether, "day window still running");
        _land(3 ether); // hour 3 <= 5 ok, day 6 <= 8 ok
        vm.warp(block.timestamp + 1 days); // cross day boundary
        assertEq(vault.axleSpentToday(), 0, "day window reset");
        _land(3 ether); // fresh day: passes again
        assertEq(vault.axleSpentToday(), 3 ether);
    }

    function test_Signal03_ZeroValueNeverConsumesAllowance() public {
        _policyNoHold();
        vm.warp(10 days + 3 hours); // pin inside a known hour/day
        _land(3 ether);
        vm.warp(block.timestamp + 1 hours);
        _land(3 ether);
        vm.warp(block.timestamp + 1 hours);
        _land(2 ether); // day fully consumed: 3 + 3 + 2 == 8
        assertEq(vault.axleSpentToday(), MAX_PER_DAY);
        uint256 before = address(target).balance;
        vm.prank(agentAddr);
        vault.execute(address(target), 0, ""); // zero value: not refused, not charged
        assertEq(vault.axleSpentToday(), MAX_PER_DAY, "zero value consumed nothing");
        assertEq(address(target).balance, before, "zero value moved nothing");
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal03OverPerDay.selector, 1 wei, MAX_PER_DAY, MAX_PER_DAY)
        );
        vault.execute(address(target), 1 wei, ""); // any positive value now refused
    }

    function test_Signal03_ZeroCapIsZeroTolerance() public {
        _fullSetup();
        vm.prank(ownerAddr);
        vault.setLimits(0, 0, 0);
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal03OverPerTx.selector, 1 wei, 0)
        );
        vault.execute(address(target), 1 wei, "");
        vm.prank(agentAddr);
        vault.execute(address(target), 0, ""); // zero value still passes
    }

    function test_Signal03_SetLimitsEventAndRevision() public {
        vm.expectEmit(false, false, false, true);
        emit RailsVault.LimitsChanged(1 ether, 2 ether, 3 ether);
        vm.prank(ownerAddr);
        vault.setLimits(1 ether, 2 ether, 3 ether);
        assertEq(vault.revision(), 1, "limits redraw revises policy");
        assertEq(vault.maxPerTx(), 1 ether);
        assertEq(vault.axleDailyCap(), 3 ether);
    }

    // ============================================================== signal 04

    function test_Signal04_LargeCallQueuesWithExactFields() public {
        _fullSetup();
        uint256 before = block.timestamp;
        vm.expectEmit(true, true, false, true);
        emit RailsVault.CallHeldInLoop(0, address(target), 2.5 ether, "", before + LOOP_DELAY);
        vm.prank(agentAddr);
        vault.execute(address(target), 2.5 ether, "");

        assertEq(vault.loopQueueLength(), 1, "one call waiting");
        assertEq(vault.loopEntriesTotal(), 1, "one ledger row");
        assertEq(address(vault).balance, FUND, "queued funds stay in the vault");
        assertEq(address(target).balance, 0, "nothing landed");
        assertEq(vault.axleSpentToday(), 0, "queuing consumes no allowance");

        (address t, uint256 v, bytes memory data, uint256 readyAt, bool open) = vault.queueEntry(0);
        assertEq(t, address(target));
        assertEq(v, 2.5 ether);
        assertEq(data, "");
        assertEq(readyAt, before + LOOP_DELAY);
        assertTrue(open);
    }

    function test_Signal04_ReleaseBeforeReadyReverts() public {
        _fullSetup();
        uint256 idx = _queue(2.5 ether);
        vm.warp(block.timestamp + LOOP_DELAY - 1); // one second short
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                RailsVault.Signal04NotReady.selector, idx, block.timestamp + 1
            )
        );
        vault.release(idx);
        assertEq(vault.loopQueueLength(), 1, "still queued");
    }

    function test_Signal04_ReleaseLandsAfterExactDelay() public {
        _fullSetup();
        uint256 readyAt = block.timestamp + LOOP_DELAY;
        uint256 idx = _queue(2.5 ether);
        vm.warp(readyAt); // boundary: timestamp == readyAt is releasable
        vm.expectEmit(true, true, false, true);
        emit RailsVault.CallReleased(idx, address(target), 2.5 ether);
        vm.expectEmit(true, true, false, true);
        emit RailsVault.CallLanded(address(target), SEL_PLAIN, 2.5 ether);
        vm.prank(agentAddr);
        vault.release(idx);

        assertEq(address(target).balance, 2.5 ether);
        assertEq(address(vault).balance, FUND - 2.5 ether);
        assertEq(vault.loopQueueLength(), 0, "left the open queue");
        assertEq(vault.loopEntriesTotal(), 1, "history kept");
        (, , , , bool open) = vault.queueEntry(idx);
        assertFalse(open, "row closed");
        assertEq(vault.axleSpentToday(), 2.5 ether, "allowance charged at release");
    }

    function test_Signal04_ReleaseByOwnerOkStrangerRefused() public {
        _fullSetup();
        uint256 idx = _queue(2.5 ether);
        vm.warp(block.timestamp + LOOP_DELAY);
        vm.prank(stranger);
        vm.expectRevert(RailsVault.AgentOnly.selector);
        vault.release(idx);
        vm.prank(ownerAddr);
        vault.release(idx); // owner may release
        assertEq(address(target).balance, 2.5 ether);
    }

    function test_Signal04_ReleaseRechecksHourLimitAndStaysQueued() public {
        _fullSetup();
        vm.warp(10 days + 3 hours); // pin inside a known hour/day
        uint256 idx = _queue(2.5 ether); // queued, consumes nothing
        _land(2 ether); // hour 2 (lands: 2 <= holdAbove)
        _land(2 ether); // hour 4
        _land(1 ether); // hour 5 == cap
        vm.warp(block.timestamp + LOOP_DELAY);
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal03OverPerHour.selector, 2.5 ether, 5 ether, 5 ether)
        );
        vault.release(idx); // hour window full: stays queued, named refusal
        assertEq(vault.loopQueueLength(), 1, "entry must stay open");
        vm.warp(block.timestamp + 1 hours); // hour resets
        vm.prank(agentAddr);
        vault.release(idx); // now within limits
        assertEq(address(target).balance, 5 ether + 2.5 ether, "three lands + the released call");
        assertEq(vault.axleSpentToday(), 5 ether + 2.5 ether, "day accumulated 5 + 2.5");
    }

    function test_Signal04_ReleaseRechecksPerTxLimit() public {
        _fullSetup();
        uint256 idx = _queue(3 ether); // == maxPerTx at queue time
        vm.warp(block.timestamp + LOOP_DELAY);
        vm.prank(ownerAddr);
        vault.setLimits(2 ether, MAX_PER_HOUR, MAX_PER_DAY); // owner tightens per-tx
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal03OverPerTx.selector, 3 ether, 2 ether)
        );
        vault.release(idx); // tightened cap: stays queued
        assertEq(vault.loopQueueLength(), 1);
    }

    function test_Signal04_FailedLandingKeepsEntryOpen() public {
        _fullSetup();
        uint256 idx = _queue(2.5 ether);
        vm.warp(block.timestamp + LOOP_DELAY);
        target.setFailNext(true);
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                RailsVault.CallFailed.selector,
                abi.encodeWithSignature("Error(string)", "target refused this call")
            )
        );
        vault.release(idx);
        (, , , , bool open) = vault.queueEntry(idx);
        assertTrue(open, "failed landing must keep the call queued");
        assertEq(vault.axleSpentToday(), 0, "charge rolled back with the failed release");
        target.setFailNext(false);
        vm.prank(agentAddr);
        vault.release(idx); // retry works
        assertEq(address(target).balance, 2.5 ether);
    }

    function test_Signal04_CancelQueuedOwnerOnly() public {
        _fullSetup();
        uint256 idx = _queue(2.5 ether);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vault.cancelQueued(idx);
        vm.prank(ownerAddr);
        vault.cancelQueued(idx);
        assertEq(vault.loopQueueLength(), 0);
        vm.warp(block.timestamp + LOOP_DELAY);
        vm.prank(agentAddr);
        vm.expectRevert(abi.encodeWithSelector(RailsVault.Signal04NotOpen.selector, idx));
        vault.release(idx); // cancelled row can never release
        vm.prank(ownerAddr);
        vm.expectRevert(abi.encodeWithSelector(RailsVault.Signal04NotOpen.selector, idx));
        vault.cancelQueued(idx); // double cancel refused
    }

    function test_Signal04_QueuedCallsNeverExpire() public {
        _fullSetup();
        uint256 idx = _queue(2.5 ether);
        vm.warp(block.timestamp + 30 days); // far future: no expiry
        vm.prank(agentAddr);
        vault.release(idx);
        assertEq(address(target).balance, 2.5 ether, "queued call survives arbitrarily long");
    }

    function test_Signal04_IndexesStayStable() public {
        _fullSetup();
        uint256 i0 = _queue(2.5 ether);
        uint256 i1 = _queue(2.2 ether);
        uint256 i2 = _queue(2.1 ether);
        assertEq(i0, 0);
        assertEq(i1, 1);
        assertEq(i2, 2);
        vm.prank(ownerAddr);
        vault.cancelQueued(i1);
        assertEq(vault.loopQueueLength(), 2, "two open rows");
        assertEq(vault.loopEntriesTotal(), 3, "ledger keeps all rows");
        vm.warp(block.timestamp + LOOP_DELAY);
        vm.prank(agentAddr);
        vault.release(i0);
        vm.prank(agentAddr);
        vault.release(i2);
        assertEq(address(target).balance, 2.5 ether + 2.1 ether);
        assertEq(vault.loopQueueLength(), 0);
        (, , , , bool open1) = vault.queueEntry(i1);
        assertFalse(open1, "cancelled row remains as history");
    }

    function test_Signal04_QueueIndexOutOfBounds() public {
        _fullSetup();
        vm.prank(agentAddr);
        vm.expectRevert(abi.encodeWithSelector(RailsVault.QueueIndexOutOfBounds.selector, 0));
        vault.release(0);
        vm.prank(ownerAddr);
        vm.expectRevert(abi.encodeWithSelector(RailsVault.QueueIndexOutOfBounds.selector, 0));
        vault.cancelQueued(0);
        vm.expectRevert(abi.encodeWithSelector(RailsVault.QueueIndexOutOfBounds.selector, 0));
        vault.queueEntry(0);
    }

    function test_Signal04_ZeroValueNeverQueues() public {
        _fullSetup();
        vm.prank(agentAddr);
        vault.execute(address(target), 0, ""); // 0 > holdAbove is never true
        assertEq(vault.loopQueueLength(), 0);
        assertEq(vault.loopEntriesTotal(), 0);
    }

    function test_Signal04_SetLoopConfigDisablesHolding() public {
        _fullSetup();
        vm.expectEmit(false, false, false, true);
        emit RailsVault.LoopConfigChanged(0, 60);
        vm.prank(ownerAddr);
        vault.setLoopConfig(0, 60); // holdAbove == 0 disables the loop line
        assertEq(vault.revision(), 4, "route(1) + limits(2) + loop(3) + this loop redraw(4)");
        vm.prank(agentAddr);
        vault.execute(address(target), 3 ether, ""); // would have queued before
        assertEq(address(target).balance, 3 ether, "landed directly with holding disabled");
        assertEq(vault.loopEntriesTotal(), 0);
    }

    // ================================================================== rule

    function test_Rule_TriStateVerdicts() public {
        _fullSetup();
        (uint8 vPass, uint256 raPass) = vault.rule(address(target), 1 ether, "");
        assertEq(vPass, vault.VERDICT_PASS());
        assertEq(raPass, 0);

        (uint8 vHold, uint256 raHold) = vault.rule(address(target), 2.5 ether, "");
        assertEq(vHold, vault.VERDICT_HOLD());
        assertEq(raHold, block.timestamp + LOOP_DELAY);

        (uint8 vRefused, uint256 raRefused) = vault.rule(address(target), 3.5 ether, "");
        assertEq(vRefused, vault.VERDICT_REFUSED());
        assertEq(raRefused, 0);
    }

    function test_Rule_SealedAlwaysRefusedFirst() public {
        _fullSetup();
        vm.prank(ownerAddr);
        vault.seal();
        (uint8 v, uint256 ra) = vault.rule(address(target), 1 ether, "");
        assertEq(v, vault.VERDICT_REFUSED());
        assertEq(ra, 0);
        // sealed verdict wins even over unrouted/over-cap combinations
        (v, ra) = vault.rule(address(stranger), type(uint256).max, hex"deadbeef");
        assertEq(v, vault.VERDICT_REFUSED());
    }

    function test_Rule_RefusalOrderMatchesExecute() public {
        _fullSetup();
        // sealed + over-limit: execute names 01
        vm.prank(ownerAddr);
        vault.seal();
        vm.prank(agentAddr);
        vm.expectRevert(RailsVault.Signal01Sealed.selector);
        vault.execute(address(target), 5 ether, "");
        vm.prank(ownerAddr);
        vault.unseal();

        // unrouted + over-limit: execute names 02 (the stranger target has no route)
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal02Unrouted.selector, address(stranger), SEL_PLAIN)
        );
        vault.execute(address(stranger), 5 ether, "");

        // unlimited approval + over-limit: execute names 02 unlimited
        _route(address(token), SEL_APPROVE);
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                RailsVault.Signal02UnlimitedApproval.selector, address(token), SEL_APPROVE
            )
        );
        vault.execute(
            address(token), type(uint256).max, abi.encodeCall(TokenMock.approve, (stranger, type(uint256).max))
        );

        // over-per-tx + over-per-day at once: per-tx axis is named first
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(RailsVault.Signal03OverPerTx.selector, type(uint256).max, MAX_PER_TX)
        );
        vault.execute(address(target), type(uint256).max, "");
    }

    function test_Rule_HoldReadyAtMatchesQueuedEntry() public {
        _fullSetup();
        (, uint256 ra) = vault.rule(address(target), 2.5 ether, "");
        vm.prank(agentAddr);
        vault.execute(address(target), 2.5 ether, "");
        (, , , uint256 actualReadyAt, ) = vault.queueEntry(0);
        assertEq(actualReadyAt, ra, "simulator and queue agree on readyAt");
    }

    function test_Rule_NeverRevertsOnArbitraryInput() public {
        _fullSetup();
        bytes memory weird = new bytes(1000);
        (uint8 v, ) = vault.rule(address(stranger), type(uint256).max, weird);
        assertEq(v, vault.VERDICT_REFUSED(), "unrouted is refused, not reverted");
        (v, ) = vault.rule(address(target), type(uint256).max, weird);
        assertEq(v, vault.VERDICT_REFUSED(), "over-limit is refused, not reverted");
        (v, ) = vault.rule(address(vault), 0, "");
        assertEq(v, vault.VERDICT_REFUSED(), "self-target is refused, not reverted");
        // rule() is caller-independent (pure policy)
        vm.prank(stranger);
        (v, ) = vault.rule(address(target), 1 ether, "");
        assertEq(v, vault.VERDICT_PASS());
    }

    // ================================================================ execute

    function test_Execute_OnlyDesignatedAgent() public {
        _fullSetup();
        vm.prank(stranger);
        vm.expectRevert(RailsVault.AgentOnly.selector);
        vault.execute(address(target), 1 ether, "");
        vm.prank(ownerAddr); // owner is NOT the agent by default
        vm.expectRevert(RailsVault.AgentOnly.selector);
        vault.execute(address(target), 1 ether, "");
    }

    function test_Execute_RejectsAttachedEth() public {
        _fullSetup();
        vm.deal(address(this), 1 ether); // the caller can afford to attach
        vm.prank(agentAddr);
        (bool ok, bytes memory ret) = address(vault).call{value: 1 ether}(
            abi.encodeCall(RailsVault.execute, (address(target), 1 ether, ""))
        );
        assertFalse(ok, "non-payable execute must refuse attached ETH");
        assertEq(ret.length, 0, "plain empty revert");
        assertEq(address(vault).balance, FUND, "vault untouched");
    }

    function test_Execute_FailedTargetLeavesEverythingUntouched() public {
        _fullSetup();
        target.setFailNext(true);
        vm.prank(agentAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                RailsVault.CallFailed.selector,
                abi.encodeWithSignature("Error(string)", "target refused this call")
            )
        );
        vault.execute(address(target), 1 ether, "");
        assertEq(address(vault).balance, FUND, "vault untouched");
        assertEq(address(target).balance, 0);
        assertEq(vault.axleSpentToday(), 0, "charge rolled back");
    }

    function test_Execute_ReentrancyIsGuarded() public {
        _fullSetup();
        target.setReenterNext(true);
        vm.prank(agentAddr);
        vault.execute(address(target), 1 ether, ""); // lands; the reentry is swallowed
        bytes memory guardRevert =
            abi.encodeWithSelector(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        assertEq(target.lastReentryRevert(), guardRevert, "reentry must be refused by the guard");
        assertEq(address(target).balance, 1 ether, "outer call landed exactly once");
        assertEq(vault.axleSpentToday(), 1 ether);
    }

    function test_Execute_LandsChargesAndEmits() public {
        _fullSetup();
        vm.expectEmit(true, true, false, true);
        emit RailsVault.CallLanded(address(target), SEL_PLAIN, 1 ether);
        vm.prank(agentAddr);
        vault.execute(address(target), 1 ether, "");
        assertEq(address(target).balance, 1 ether);
        assertEq(address(vault).balance, FUND - 1 ether);
        assertEq(vault.axleSpentToday(), 1 ether);
        assertEq(vault.axleSpentThisHour(), 1 ether);
    }

    // ============================================================== owner path

    function test_OwnerExecute_BypassesEverySignal() public {
        _fullSetup();
        vm.prank(ownerAddr);
        vault.seal(); // sealed
        vm.prank(ownerAddr);
        vault.setLimits(0, 0, 0); // zero caps
        // unrouted, over every cap, sealed: the rescue channel still lands
        vm.prank(ownerAddr);
        vault.ownerExecute(address(stranger), 7 ether, "");
        assertEq(address(stranger).balance, 7 ether);
        assertEq(address(vault).balance, FUND - 7 ether);
        assertEq(vault.axleSpentToday(), 0, "rescue path never consumes allowance");
    }

    function test_OwnerExecute_FailureReverts() public {
        _fullSetup();
        target.setFailNext(true);
        vm.prank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                RailsVault.CallFailed.selector,
                abi.encodeWithSignature("Error(string)", "target refused this call")
            )
        );
        vault.ownerExecute(address(target), 1 ether, "");
        assertEq(address(vault).balance, FUND);
    }

    function test_OwnerExecute_OwnerOnly() public {
        vm.prank(agentAddr);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, agentAddr));
        vault.ownerExecute(address(target), 1 ether, "");
    }

    // ================================================================== agent

    function test_Agent_SetAgentRekeysTheVault() public {
        address newAgent = makeAddr("newAgent");
        vm.expectEmit(true, false, false, true);
        emit RailsVault.AgentChanged(newAgent);
        vm.prank(ownerAddr);
        vault.setAgent(newAgent);
        assertEq(vault.revision(), 1, "re-key revises policy");
        vm.prank(agentAddr);
        vm.expectRevert(RailsVault.AgentOnly.selector);
        vault.execute(address(target), 0, ""); // old agent out
        _routePlain();
        vm.prank(newAgent);
        vault.execute(address(target), 0, ""); // new agent in
    }

    function test_Agent_ZeroAddressForbidden() public {
        vm.prank(ownerAddr);
        vm.expectRevert(RailsVault.ZeroAddress.selector);
        vault.setAgent(address(0));
    }

    function test_Agent_ConstructorRoles() public {
        assertEq(vault.owner(), ownerAddr);
        assertEq(vault.agent(), agentAddr);
        assertEq(vault.loopDelay(), LOOP_DELAY);
    }

    // ======================================================== ownership 2-step

    function test_Ownership_TwoStepTransferFlow() public {
        address newOwner = makeAddr("newOwner");
        vm.expectEmit(true, true, false, true);
        emit Ownable2Step.OwnershipTransferStarted(ownerAddr, newOwner);
        vm.prank(ownerAddr);
        vault.transferOwnership(newOwner);
        assertEq(vault.pendingOwner(), newOwner);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vault.acceptOwnership(); // only the pending owner may accept

        vm.expectEmit(true, true, false, true);
        emit Ownable.OwnershipTransferred(ownerAddr, newOwner);
        vm.prank(newOwner);
        vault.acceptOwnership();
        assertEq(vault.owner(), newOwner);
        assertEq(vault.pendingOwner(), address(0));

        vm.prank(ownerAddr); // previous owner loses all rights
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ownerAddr));
        vault.seal();
        vm.prank(newOwner);
        vault.seal(); // new owner has them
        assertTrue(_readSealed());
    }

    function test_Ownership_TransferProposalOwnerOnly() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vault.transferOwnership(stranger);
    }

    function test_Ownership_ConstructorRejectsZeroOwner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new RailsVault(address(0), agentAddr, LOOP_DELAY);
    }

    function test_Ownership_ConstructorRejectsZeroAgent() public {
        vm.expectRevert(RailsVault.ZeroAddress.selector);
        new RailsVault(ownerAddr, address(0), LOOP_DELAY);
    }

    // ================================================================ receive

    function test_Receive_AnyoneMayFundTheVault() public {
        vm.deal(stranger, 1 ether);
        vm.prank(stranger);
        (bool ok, ) = payable(address(vault)).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(vault).balance, FUND + 1 ether);
    }

    function test_Receive_UnguardedForMidFlightRefunds() public {
        _fullSetup();
        target.setRefundBps(5000); // target sends half back immediately
        vm.prank(agentAddr);
        vault.execute(address(target), 1 ether, "");
        assertEq(address(target).balance, 0.5 ether, "kept half");
        assertEq(address(vault).balance, FUND - 0.5 ether, "refund accepted mid-flight");
        assertEq(vault.axleSpentToday(), 1 ether, "outgoing value is what counts");
    }

    // ================================================================== fuzz

    /// @dev Signal 03 invariant: whatever lands, the spend book never exceeds the caps.
    function fuzz_AxleLimitUnbreakable(uint128 seed0, uint128 seed1, uint128 seed2, uint128 seed3)
        public
    {
        vm.prank(ownerAddr);
        vault.setLimits(1 ether, 2.5 ether, 4 ether);
        _routePlain();
        uint128[4] memory seeds = [seed0, seed1, seed2, seed3];
        uint256 landedOut = 0;
        for (uint256 i; i < seeds.length; ++i) {
            uint256 value = bound(seeds[i], 0, 2 ether); // some above the 1e per-tx cap
            vm.prank(agentAddr);
            try vault.execute(address(target), value, "") {
                landedOut += value;
                assertLe(vault.axleSpentToday(), 4 ether, "daily cap broken");
                assertLe(vault.axleSpentThisHour(), 2.5 ether, "hourly cap broken");
            } catch {
                // refused by 03 (or nothing at all) — vault funds must be intact
                assertEq(address(vault).balance, FUND - landedOut, "refused call must not move funds");
            }
        }
        assertEq(address(target).balance, landedOut, "target holds exactly what landed");
    }

    /// @dev rule() and execute() must never disagree on the same state.
    function fuzz_RuleExecuteConsistency(uint256 s0, uint256 s1, uint256 s2) public {
        _fullSetup();
        vm.warp(10 days + 3 hours);
        uint256[3] memory seeds = [s0, s1, s2];
        uint256 rowsBefore = vault.loopEntriesTotal();
        for (uint256 i; i < seeds.length; ++i) {
            uint256 value = bound(seeds[i], 0, 2 * MAX_PER_TX);
            (uint8 verdict, ) = vault.rule(address(target), value, "");
            vm.prank(agentAddr);
            try vault.execute(address(target), value, "") {
                if (verdict == vault.VERDICT_PASS()) {
                    assertEq(
                        vault.loopEntriesTotal(), rowsBefore, "PASS must land, not queue"
                    );
                } else if (verdict == vault.VERDICT_HOLD()) {
                    assertEq(vault.loopEntriesTotal(), rowsBefore + 1, "HOLD must queue");
                    (, , , uint256 readyAt, bool open) = vault.queueEntry(rowsBefore);
                    assertTrue(open);
                    assertGt(readyAt, block.timestamp - 1);
                } else {
                    assertTrue(false, "rule REFUSED but execute landed");
                }
                rowsBefore = vault.loopEntriesTotal();
            } catch {
                assertEq(verdict, vault.VERDICT_REFUSED(), "execute reverted but rule allowed");
            }
        }
    }

    /// @dev Fixed buckets keep the spend book bounded across arbitrary clock jumps.
    function fuzz_BucketResetAcrossTime(uint256 s0, uint256 s1, uint256 s2) public {
        vm.prank(ownerAddr);
        vault.setLimits(1 ether, 2.5 ether, 4 ether);
        _routePlain();
        uint256[3] memory seeds = [s0, s1, s2];
        for (uint256 i; i < seeds.length; ++i) {
            uint256 value = bound(seeds[i], 1, 2 ether);
            vm.warp(block.timestamp + bound(seeds[i], 0, 50 hours));
            (uint8 verdict, ) = vault.rule(address(target), value, "");
            vm.prank(agentAddr);
            try vault.execute(address(target), value, "") {
                assertEq(verdict, vault.VERDICT_PASS());
                assertLe(vault.axleSpentToday(), 4 ether);
                assertLe(vault.axleSpentThisHour(), 2.5 ether);
            } catch {
                assertEq(verdict, vault.VERDICT_REFUSED());
            }
        }
    }

    /// @dev Unlimited approvals are refused regardless of route drawing.
    function fuzz_UnlimitedApprovalAlwaysRefused(uint256 amount) public {
        _route(address(token), SEL_APPROVE);
        amount = bound(amount, 0, type(uint256).max);
        bool unlimited = amount > type(uint256).max / 2;
        if (unlimited) amount = type(uint256).max;
        vm.prank(agentAddr);
        try vault.execute(address(token), 0, abi.encodeCall(TokenMock.approve, (stranger, amount))) {
            assertFalse(unlimited, "unlimited approval must not land");
            assertEq(token.lastApproved(), amount);
        } catch {
            assertTrue(unlimited, "bounded approval must land");
        }
    }
}
