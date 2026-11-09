// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title RailsVault — a policy vault for one autonomous agent on Robinhood Chain.
/// @notice The owner draws four signals; every agent call must clear them in order:
///           01 buffer stop   — the whole vault can be sealed; nothing moves while sealed;
///           02 interlocking  — only drawn (target, selector) pairs may be called;
///           03 axle limit    — native-value caps per tx / per hour / per day (fixed buckets);
///           04 loop line     — calls above a threshold queue up and release after a delay.
///         A call either lands, waits in the loop queue, or reverts naming the signal
///         that stopped it. Queued calls never expire on their own.
/// @dev    Funds live in this contract; the agent never holds them. External calls are
///         always the last step of a state transition (checks-effects-interactions) and
///         every entry point that reaches outward is additionally reentrancy-guarded.
///         The owner keeps a signal-free rescue channel (`ownerExecute`) and two-step
///         ownership transfer (OpenZeppelin `Ownable2Step`).
contract RailsVault is Ownable2Step, ReentrancyGuard {
    // ---------------------------------------------------------------- constants

    /// @dev Verdict codes returned by `rule` (the read-only simulator).
    uint8 public constant VERDICT_PASS = 0;
    uint8 public constant VERDICT_HOLD = 1;
    uint8 public constant VERDICT_REFUSED = 2;

    /// @dev Empty calldata is the only way to express a plain native transfer.
    bytes4 private constant SELECTOR_PLAIN = 0x00000000;
    /// @dev Calldata shorter than 4 bytes (or zero-prefixed calldata) can never
    ///      match a drawn route — it would smuggle a fallback call onto a route.
    bytes4 private constant SELECTOR_ROGUE = 0xffffffff;

    bytes4 private constant SELECTOR_APPROVE = 0x095ea7b3; // approve(address,uint256)
    bytes4 private constant SELECTOR_INCREASE_ALLOWANCE = 0x39509351; // increaseAllowance(address,uint256)
    bytes4 private constant SELECTOR_SET_APPROVAL_FOR_ALL = 0xa22cb465; // setApprovalForAll(address,bool)

    uint256 private constant HOUR_SECONDS = 1 hours;
    uint256 private constant DAY_SECONDS = 1 days;

    // -------------------------------------------------------------------- types

    /// @dev A drawn route: one (target, selector) pair with a display label.
    struct Route {
        address target;
        bytes4 selector;
        string label;
    }

    /// @dev Native-value spend counters. Buckets are fixed clock windows
    ///      (`block.timestamp / 1 hours` and `/ 1 days`); a new window starts at zero.
    struct SpendBook {
        uint64 hourEpoch;
        uint64 dayEpoch;
        uint256 hourSpent;
        uint256 daySpent;
    }

    /// @dev A call parked in the loop line. Entries are append-only: the index an
    ///      agent learns from `CallHeldInLoop` stays valid forever; released and
    ///      cancelled entries keep their row with `open == false` as history.
    struct QueuedCall {
        address target;
        uint256 value;
        bytes data;
        uint256 readyAt;
        bool open;
    }

    // ------------------------------------------------------------------- state

    /// @notice The only address allowed to call `execute` and `release`.
    address public agent;

    /// @notice Signal 01. Sealed = agent entry frozen (owner rescue still works).
    /// @dev `sealed` is a reserved Solidity keyword, so the storage flag stays private
    ///      under `_sealed` and the public `sealed()` read is surfaced by the fallback.
    bool private _sealed;

    /// @dev Selector of `sealed()` — the one read the fallback answers.
    // forge-lint: disable-next-line(unsafe-typecast) bytes32 -> bytes4 keeps the leftmost bytes by design
    bytes4 private constant _SEL_SEALED = bytes4(keccak256("sealed()"));

    /// @notice Bumped on every policy change (routes, limits, loop, agent); operational
    ///         actions like seal/unseal do not count.
    uint256 public revision;

    /// @notice Signal 03 — native-value caps. Zero = zero tolerance on that axis
    ///         (nothing above zero may pass), which is a deliberate owner tool.
    uint256 public maxPerTx;
    uint256 public maxPerHour;
    uint256 public maxPerDay;

    /// @notice Signal 04 — calls with value strictly above `holdAbove` (when nonzero)
    ///         queue up instead of landing immediately.
    uint256 public holdAbove;

    /// @notice Signal 04 — seconds a queued call waits before it may release.
    uint256 public loopDelay;

    /// @dev Drawn routes keyed by (target, selector); `_routeKeys` enumerates them.
    mapping(bytes32 routeKey => Route) private _routes;
    bytes32[] private _routeKeys;

    /// @dev Loop line ledger. Append-only; `_openCalls` counts rows with `open == true`.
    QueuedCall[] private _loop;
    uint256 private _openCalls;

    /// @dev Signal 03 counters.
    SpendBook private _spend;

    // ------------------------------------------------------------------ events

    event SealedStateChanged(bool sealedState);
    event RouteChanged(address indexed target, bytes4 indexed selector, bool listed, string label);
    event LimitsChanged(uint256 maxPerTxValue, uint256 maxPerHourValue, uint256 maxPerDayValue);
    event LoopConfigChanged(uint256 holdAboveValue, uint256 loopDelayValue);
    event AgentChanged(address indexed newAgent);
    event PolicyRevised(uint256 indexed newRevision);

    event CallHeldInLoop(
        uint256 indexed index, address indexed target, uint256 value, bytes data, uint256 readyAt
    );
    event CallReleased(uint256 indexed index, address indexed target, uint256 value);
    event CallCancelled(uint256 indexed index, address indexed target, uint256 value);
    event CallLanded(address indexed target, bytes4 indexed selector, uint256 value);
    event OwnerExecuted(address indexed target, uint256 value, bytes data);

    // ------------------------------------------------------------------ errors

    /// @dev Signal 01 — the vault is sealed; agent entry is frozen.
    error Signal01Sealed();
    error Signal01AlreadySet();
    error Signal01AlreadyClear();

    /// @dev Signal 02 — interlocking refusals.
    error Signal02Unrouted(address target, bytes4 selector);
    error Signal02UnlimitedApproval(address target, bytes4 selector);
    error Signal02SelfRoute();
    error Signal02RogueSelector();
    error Signal02NotRouted(address target, bytes4 selector);

    /// @dev Signal 03 — axle limit refusals. Arguments avoid computing sums, so the
    ///      error itself can never overflow.
    error Signal03OverPerTx(uint256 value, uint256 cap);
    error Signal03OverPerHour(uint256 value, uint256 spentInWindow, uint256 cap);
    error Signal03OverPerDay(uint256 value, uint256 spentInWindow, uint256 cap);

    /// @dev Signal 04 — loop line refusals.
    error Signal04NotReady(uint256 index, uint256 readyAt);
    error Signal04NotOpen(uint256 index);

    error AgentOnly();
    error ZeroAddress();
    error CallFailed(bytes returnData);
    error RouteIndexOutOfBounds(uint256 index);
    error QueueIndexOutOfBounds(uint256 index);
    error UnknownSelector(bytes4 selector);

    // --------------------------------------------------------------- modifiers

    modifier onlyAgent() {
        if (msg.sender != agent) revert AgentOnly();
        _;
    }

    modifier onlyAgentOrOwner() {
        if (msg.sender != agent && msg.sender != owner()) revert AgentOnly();
        _;
    }

    // -------------------------------------------------------------- constructor

    /// @param initialOwner Draws and revises the policy; two-step transferable.
    /// @param initialAgent The only executor of `execute` / `release`.
    /// @param loopDelay_ Seconds a held call waits in the loop line.
    /// @dev Caps and routes start undrawn: with no route and no cap nothing can move.
    ///      That is the intended fail-safe default — draw the policy before funding.
    constructor(address initialOwner, address initialAgent, uint256 loopDelay_)
        Ownable(initialOwner)
    {
        if (initialAgent == address(0)) revert ZeroAddress();
        agent = initialAgent;
        loopDelay = loopDelay_;
        emit AgentChanged(initialAgent);
    }

    /// @notice Owner funding and return flows from called contracts land here.
    /// @dev Deliberately open to anyone: called protocols may refund ETH mid-flight.
    receive() external payable {}

    /// @notice Public read for signal 01: selector `sealed()` returns `bool`.
    /// @dev Exists only here because `sealed` cannot name a Solidity function.
    ///      The body is read-only, so `eth_call` / `staticcall` work as expected.
    ///      Any other unknown selector is refused explicitly.
    fallback(bytes calldata) external returns (bytes memory) {
        if (msg.sig == _SEL_SEALED) {
            return abi.encode(_sealed);
        }
        revert UnknownSelector(msg.sig);
    }

    // =========================================================== agent entry

    /// @notice The agent asks to move native value. Lands immediately, waits in the
    ///         loop line, or reverts naming the signal that stopped it.
    /// @dev Paid from this vault's own balance — attached ETH is not accepted
    ///      (the function is not payable). The target call is the last action.
    function execute(address target, uint256 value, bytes calldata data)
        external
        nonReentrant
        onlyAgent
    {
        // 01 buffer stop
        if (_sealed) revert Signal01Sealed();

        // 02 interlocking
        bytes4 selector = _selectorOf(data);
        if (target == address(this)) revert Signal02SelfRoute();
        if (!_isRouted(target, selector)) revert Signal02Unrouted(target, selector);
        if (_grantsUnlimitedApproval(selector, data)) {
            revert Signal02UnlimitedApproval(target, selector);
        }

        // 03 axle limit (fully checked before 04 — a call over both the cap and the
        // threshold is refused by 03, never parked in the queue)
        _checkAxle(value);

        // 04 loop line
        if (holdAbove != 0 && value > holdAbove) {
            uint256 readyAt = block.timestamp + loopDelay;
            _loop.push(
                QueuedCall({
                    target: target,
                    value: value,
                    data: data,
                    readyAt: readyAt,
                    open: true
                })
            );
            uint256 index = _loop.length - 1;
            unchecked {
                ++_openCalls;
            }
            // forge-lint: disable-next-line(reentrancy-events) no external call precedes this emit on the queue path
            emit CallHeldInLoop(index, target, value, data, readyAt);
            return;
        }

        // land: effects first, interaction last
        _chargeAxle(value);
        _land(target, value, data, selector);
    }

    /// @notice Release a queued call once its delay has passed. Agent or owner.
    /// @dev Re-verifies signal 01 (sealed freezes releases) and re-verifies signal 03
    ///      against the *current* windows — an over-limit call stays queued and reverts
    ///      naming signal 03. Routes are NOT re-checked here: to stop a queued call
    ///      outright the owner cancels it by index (`cancelQueued`).
    function release(uint256 index) external nonReentrant onlyAgentOrOwner {
        if (index >= _loop.length) revert QueueIndexOutOfBounds(index);
        QueuedCall storage entry = _loop[index];
        if (!entry.open) revert Signal04NotOpen(index);
        if (_sealed) revert Signal01Sealed(); // 01 buffer stop
        if (block.timestamp < entry.readyAt) revert Signal04NotReady(index, entry.readyAt); // 04
        _checkAxle(entry.value); // 03 re-verified now; refusal keeps the call queued

        entry.open = false;
        unchecked {
            --_openCalls;
        }
        _chargeAxle(entry.value);
        bytes4 selector = _selectorOf(entry.data);
        // forge-lint: disable-next-line(reentrancy-events) emitted only after the delay + limit checks pass; the call lands right after
        emit CallReleased(index, entry.target, entry.value);
        _land(entry.target, entry.value, entry.data, selector);
    }

    // ========================================================== owner controls

    /// @notice Signal 01 — freeze all agent entry (execute and release).
    function seal() external onlyOwner {
        if (_sealed) revert Signal01AlreadySet();
        _sealed = true;
        emit SealedStateChanged(true);
    }

    /// @notice Signal 01 — lift the freeze.
    function unseal() external onlyOwner {
        if (!_sealed) revert Signal01AlreadyClear();
        _sealed = false;
        emit SealedStateChanged(false);
    }

    /// @notice Signal 02 — draw a route. Plain native transfers use
    ///         `selector == 0x00000000` with empty calldata only.
    function setRoute(address target, bytes4 selector, string calldata label) external onlyOwner {
        if (target == address(0)) revert ZeroAddress();
        if (target == address(this)) revert Signal02SelfRoute();
        if (selector == SELECTOR_ROGUE) revert Signal02RogueSelector();

        bytes32 key = _routeKey(target, selector);
        if (_routes[key].target == address(0)) {
            _routeKeys.push(key);
        }
        _routes[key] = Route({target: target, selector: selector, label: label});
        emit RouteChanged(target, selector, true, label);
        _revise();
    }

    /// @notice Signal 02 — erase a drawn route. Enumeration order may shift for the
    ///         last entry (dense board: swap-and-pop).
    function clearRoute(address target, bytes4 selector) external onlyOwner {
        bytes32 key = _routeKey(target, selector);
        if (_routes[key].target == address(0)) revert Signal02NotRouted(target, selector);
        delete _routes[key];

        uint256 last = _routeKeys.length - 1;
        for (uint256 i; i <= last; ++i) {
            if (_routeKeys[i] == key) {
                _routeKeys[i] = _routeKeys[last];
                _routeKeys.pop();
                break;
            }
        }
        emit RouteChanged(target, selector, false, "");
        _revise();
    }

    /// @notice Signal 03 — redraw the native-value caps.
    function setLimits(uint256 maxPerTx_, uint256 maxPerHour_, uint256 maxPerDay_)
        external
        onlyOwner
    {
        maxPerTx = maxPerTx_;
        maxPerHour = maxPerHour_;
        maxPerDay = maxPerDay_;
        emit LimitsChanged(maxPerTx_, maxPerHour_, maxPerDay_);
        _revise();
    }

    /// @notice Signal 04 — redraw the loop line. `holdAbove_ == 0` disables holding.
    function setLoopConfig(uint256 holdAbove_, uint256 loopDelay_) external onlyOwner {
        holdAbove = holdAbove_;
        loopDelay = loopDelay_;
        emit LoopConfigChanged(holdAbove_, loopDelay_);
        _revise();
    }

    /// @notice Re-key the vault: only `newAgent` may execute afterwards.
    function setAgent(address newAgent) external onlyOwner {
        if (newAgent == address(0)) revert ZeroAddress();
        agent = newAgent;
        emit AgentChanged(newAgent);
        _revise();
    }

    /// @notice Owner drops a queued call. Works while sealed; history is kept.
    function cancelQueued(uint256 index) external onlyOwner {
        if (index >= _loop.length) revert QueueIndexOutOfBounds(index);
        QueuedCall storage entry = _loop[index];
        if (!entry.open) revert Signal04NotOpen(index);
        entry.open = false;
        unchecked {
            --_openCalls;
        }
        emit CallCancelled(index, entry.target, entry.value);
    }

    /// @notice Owner moves funds directly, bypassing every signal — the rescue
    ///         channel. Works while sealed. The external call stays last.
    /// @dev `target` may be any address by design: rescue means sending anywhere
    ///      (exchanges, fresh wallets, bridges) without pre-registration.
    // forge-lint: disable-next-line(missing-zero-check) owner-only rescue channel must reach arbitrary destinations
    function ownerExecute(address target, uint256 value, bytes calldata data)
        external
        nonReentrant
        onlyOwner
        returns (bytes memory ret)
    {
        bool ok;
        // forge-lint: disable-next-line(arbitrary-send-eth) owner-only rescue channel must reach arbitrary destinations
        (ok, ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
        // forge-lint: disable-next-line(reentrancy-events) emitted only after a successful call, by design
        emit OwnerExecuted(target, value, data);
    }

    // =================================================================== views

    /// @notice Native value spent in the current day window (0 once the window rolls).
    function axleSpentToday() external view returns (uint256) {
        return _spend.dayEpoch == block.timestamp / DAY_SECONDS ? _spend.daySpent : 0;
    }

    /// @notice Native value spent in the current hour window (0 once the window rolls).
    function axleSpentThisHour() external view returns (uint256) {
        return _spend.hourEpoch == block.timestamp / HOUR_SECONDS ? _spend.hourSpent : 0;
    }

    /// @notice Signal 03 day cap (read-only twin of `maxPerDay`).
    function axleDailyCap() external view returns (uint256) {
        return maxPerDay;
    }

    /// @notice Calls currently waiting in the loop line (released/cancelled rows
    ///         remain in the ledger but have left the queue).
    function loopQueueLength() external view returns (uint256) {
        return _openCalls;
    }

    /// @notice Total rows ever parked in the loop line (the ledger never shrinks).
    function loopEntriesTotal() external view returns (uint256) {
        return _loop.length;
    }

    /// @notice One loop-line row by stable index (the index from `CallHeldInLoop`).
    function queueEntry(uint256 index)
        external
        view
        returns (address target, uint256 value, bytes memory data, uint256 readyAt, bool open)
    {
        if (index >= _loop.length) revert QueueIndexOutOfBounds(index);
        QueuedCall storage entry = _loop[index];
        return (entry.target, entry.value, entry.data, entry.readyAt, entry.open);
    }

    /// @notice Number of drawn routes.
    function routesCount() external view returns (uint256) {
        return _routeKeys.length;
    }

    /// @notice One drawn route by index — the display face of signal 02.
    function route(uint256 index) external view returns (address target, string memory label) {
        if (index >= _routeKeys.length) revert RouteIndexOutOfBounds(index);
        Route storage r = _routes[_routeKeys[index]];
        return (r.target, r.label);
    }

    /// @notice Read-only simulator — never reverts, never moves anything.
    /// @return verdict 0 = PASS, 1 = HOLD (`readyAt` set), 2 = REFUSED.
    ///         Refusal order mirrors the agent path: 01 sealed -> 02 unrouted /
    ///         unlimited approval -> 03 per-tx -> per-hour -> per-day -> 04 hold.
    function rule(address target, uint256 value, bytes calldata data)
        external
        view
        returns (uint8 verdict, uint256 readyAt)
    {
        if (_sealed) return (VERDICT_REFUSED, 0); // 01
        bytes4 selector = _selectorOf(data);
        if (target == address(this)) return (VERDICT_REFUSED, 0); // 02
        if (!_isRouted(target, selector)) return (VERDICT_REFUSED, 0); // 02
        if (_grantsUnlimitedApproval(selector, data)) return (VERDICT_REFUSED, 0); // 02

        if (value > maxPerTx) return (VERDICT_REFUSED, 0); // 03 per-tx
        uint256 hourSpentNow =
            _spend.hourEpoch == block.timestamp / HOUR_SECONDS ? _spend.hourSpent : 0;
        if (hourSpentNow > maxPerHour || value > maxPerHour - hourSpentNow) {
            return (VERDICT_REFUSED, 0); // 03 per-hour
        }
        uint256 daySpentNow = _spend.dayEpoch == block.timestamp / DAY_SECONDS ? _spend.daySpent : 0;
        if (daySpentNow > maxPerDay || value > maxPerDay - daySpentNow) {
            return (VERDICT_REFUSED, 0); // 03 per-day
        }

        if (holdAbove != 0 && value > holdAbove) {
            return (VERDICT_HOLD, block.timestamp + loopDelay); // 04
        }
        return (VERDICT_PASS, 0);
    }

    // --------------------------------------------------------------- internals

    function _land(address target, uint256 value, bytes memory data, bytes4 selector) private {
        // forge-lint: disable-next-line(arbitrary-send-eth, missing-zero-check) target is gated by a drawn route (02) and can never be zero or this vault
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
        // forge-lint: disable-next-line(reentrancy-events) emitted only after a successful call, by design
        emit CallLanded(target, selector, value);
    }

    /// @dev Reverts naming the first axle axis the call would break.
    function _checkAxle(uint256 value) private view {
        if (value > maxPerTx) revert Signal03OverPerTx(value, maxPerTx);
        uint256 hourSpentNow =
            _spend.hourEpoch == block.timestamp / HOUR_SECONDS ? _spend.hourSpent : 0;
        if (hourSpentNow > maxPerHour || value > maxPerHour - hourSpentNow) {
            revert Signal03OverPerHour(value, hourSpentNow, maxPerHour);
        }
        uint256 daySpentNow = _spend.dayEpoch == block.timestamp / DAY_SECONDS ? _spend.daySpent : 0;
        if (daySpentNow > maxPerDay || value > maxPerDay - daySpentNow) {
            revert Signal03OverPerDay(value, daySpentNow, maxPerDay);
        }
    }

    /// @dev Adds `value` to the current fixed windows. Zero-value calls never consume
    ///      allowance. Only ever called after `_checkAxle` passed, so no overflow.
    function _chargeAxle(uint256 value) private {
        if (value == 0) return;
        uint256 hourEpochNow = block.timestamp / HOUR_SECONDS;
        uint256 dayEpochNow = block.timestamp / DAY_SECONDS;
        uint256 hourSpentNow = _spend.hourEpoch == hourEpochNow ? _spend.hourSpent : 0;
        uint256 daySpentNow = _spend.dayEpoch == dayEpochNow ? _spend.daySpent : 0;
        // forge-lint: disable-next-line(unsafe-typecast) timestamp/1h fits uint64 until ~5.8e12 years
        _spend.hourEpoch = uint64(hourEpochNow);
        // forge-lint: disable-next-line(unsafe-typecast) timestamp/1d fits uint64 until ~5.8e11 years
        _spend.dayEpoch = uint64(dayEpochNow);
        _spend.hourSpent = hourSpentNow + value;
        _spend.daySpent = daySpentNow + value;
    }

    function _isRouted(address target, bytes4 selector) private view returns (bool) {
        return _routes[_routeKey(target, selector)].target != address(0);
    }

    function _routeKey(address target, bytes4 selector) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(target, selector));
    }

    /// @dev The selector a call rides on. Empty calldata = plain send; partial or
    ///      zero-prefixed calldata can never ride a drawn route.
    function _selectorOf(bytes memory data) private pure returns (bytes4 selector) {
        if (data.length == 0) return SELECTOR_PLAIN;
        if (data.length < 4) return SELECTOR_ROGUE;
        selector = bytes4(bytes32(_word(data, 0))); // first four bytes, big-endian
        if (selector == SELECTOR_PLAIN) return SELECTOR_ROGUE;
    }

    /// @dev Reads the 32-byte big-endian word at byte offset `start` of `data`.
    ///      Callers must guarantee data.length >= start + 32 (memory reads beyond
    ///      an array's contents would otherwise touch unrelated memory).
    function _word(bytes memory data, uint256 start) private pure returns (uint256 word) {
        assembly {
            word := mload(add(add(data, 0x20), start))
        }
    }

    /// @dev True when the calldata grants an unlimited authorization — approve to the
    ///      maximum, increaseAllowance to the maximum, or setApprovalForAll(true).
    ///      Refused even when the route itself is drawn.
    function _grantsUnlimitedApproval(bytes4 selector, bytes memory data)
        private
        pure
        returns (bool)
    {
        if (data.length < 68) return false;
        if (selector == SELECTOR_APPROVE || selector == SELECTOR_INCREASE_ALLOWANCE) {
            return _word(data, 36) == type(uint256).max;
        }
        if (selector == SELECTOR_SET_APPROVAL_FOR_ALL) {
            return _word(data, 36) != 0;
        }
        return false;
    }

    function _revise() private {
        ++revision;
        emit PolicyRevised(revision);
    }
}
