# RailsVault

A policy vault for one autonomous agent on **Robinhood Chain** (chainId 4663).

The owner draws four signals once; every call the agent signs is tested against them at
execution — not by asking a human. Anyone can read every vault's rules and state straight
from the chain.

```
01 buffer stop   the whole vault can be sealed; nothing moves while sealed
02 interlocking  only drawn (target, selector) pairs may be called; infinite approvals never pass
03 axle limit    native-value caps per tx / per hour / per day (fixed clock buckets)
04 loop line     calls above a threshold queue up and release after the delay
```

A call either lands, waits in the loop queue, or reverts naming the signal that stopped it.

## Deployment

| | |
|---|---|
| Chain | Robinhood Chain (4663) |
| Address | [`0xDeE46274604EC5CEBa52c784DBd7350f066Cd8B6`](https://robinhoodchain.blockscout.com/address/0xDeE46274604EC5CEBa52c784DBd7350f066Cd8B6) |
| Deploy tx | `0x9bd52b78c5bdf2049c5d56beed6bf76d74bd3257b7fb7f3e5b299cc46eb183ea` (block 109812815) |
| owner / agent | set at construction (see `script/Deploy.s.sol`) |
| loopDelay | 21600s |
| Compiler | solc 0.8.28 · optimizer on · runs 400 · evmVersion prague |
| Site | [raelis.top](https://raelis.top) — the owner's table reads any vault live |

The reference deployment is an **empty demo vault**: no funds, policy drawn for display.
It exists so the site's table has real on-chain state to read.

## Read a vault

Any address can be read without a wallet:

```bash
cast call <vault> "owner()(address)"       --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call <vault> "agent()(address)"       --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call <vault> "sealed()(bool)"         --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call <vault> "axleSpentToday()(uint256)" --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call <vault> "axleDailyCap()(uint256)"   --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call <vault> "loopQueueLength()(uint256)" --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call <vault> "routesCount()(uint256)"     --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call <vault> "route(uint256)(address,string)" 0 --rpc-url https://rpc.mainnet.chain.robinhood.com
```

`rule(target, value, data)` is the read-only simulator — it never reverts and returns
`(verdict, readyAt)`: `0 = PASS`, `1 = HOLD`, `2 = REFUSED`.

## Build & test

```bash
forge install OpenZeppelin/openzeppelin-contracts forge-std
forge test          # 61 tests incl. fuzzing
```

## Deploy your own

```bash
RAILS_OWNER=<your owner address> \
RAILS_AGENT=<your agent address> \
RAILS_LOOP_DELAY=21600 \
forge script script/Deploy.s.sol:Deploy \
  --rpc-url https://rpc.mainnet.chain.robinhood.com --broadcast --account <your keystore>
```

A fresh vault starts **undrawn**: no routes, no caps — nothing can move until the owner
draws the policy (`Draw.s.sol` shows one example) and funds the vault.

## Security

**Not audited.** Do not route real funds through any vault claiming to be RailsVault before
an audit ships. Known, documented properties:

- Signal 03 counts native value only; token transfers allowed by a route are not capped.
- `release` re-checks signal 03 but not 02 — cancel a queued call by index to stop it.
- Queued calls never expire on their own.
- The owner key is the root of trust: it can redraw the policy, seal the vault, and move
  funds out via `ownerExecute` (the rescue channel).

## License

MIT — see [LICENSE](LICENSE).
