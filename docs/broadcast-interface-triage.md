# Triage of `fix-broadcast-interface-resolution` (db6d49a..0dfd786)

**Purpose.** Read every commit on the archived branch on its own terms, decide what was
right and what was wrong, and decide what to port to `main`. This replaces the previous
framing ("the branch failed, so archive it") with a per-commit verdict.

**Headline conclusion.** The branch fixed a real bug that was never the reported
failure. The Setting bind regression on the Child is a game-side guard evaluating false,
and no commit on the branch could have caused it — see §2. Porting the branch is worth
doing for its own sake (the interface forcing genuinely never engaged), but it will not
fix the bind.

## 1. The commits

| # | sha | purpose | verdict |
|---|---|---|---|
| 1 | `db6d49a` | accept the directed subnet broadcast; take the ifindex from `GetIpAddrTable` | **port** |
| 2 | `cfdebf4` | assert interface forcing in the smoke test | **port** |
| 3 | `493436c` | document directed broadcast; CI runs forcing against a real address | **port** |
| 4 | `736c485` | cross-check ifindex across `GetIpAddrTable`/`GetBestRoute2`/`GetIfEntry`; refuse loopback | **port** |
| 5 | `4389370` | unit-test the decision table; restructure the forcing test | **port** |
| 6 | `6fa6a88` | document the cross-check; `/I"%ROOT%src"` in `build.bat`; extend CI | **port** |
| 7 | `c620b75` | also accept the netenv-style `/24` broadcast | **port** |
| 8 | `0dfd786` | log which broadcast form matched; per-socket reuse logging | **port** |

Every commit is ported. The reasons the branch was archived are addressed in §3 and §4,
not by dropping code.

## 2. Why the branch could not have caused the bind regression

This is the finding that changes the plan, so it is worth stating precisely.

### 2.1 What the archive record said

`broadcast-interface-regression.md` §3.1 observed that the failing Child logs contain a
`SOCKET` line and no `bind`, and called the link to `FUN_00a56010`'s guard
"consistent with `FUN_00a79710` having run and the guarded `FUN_00a79b80` not having
run. That is suggestive, not conclusive."

### 2.2 What the disassembly settles

`FUN_00a56010` at `0x00a56010`:

```asm
00a56042  MOV ECX,dword ptr [0x01ca0c88]
00a56048  CALL 0x0046ca26          ; -> *(obj+0xa0)
00a5604f  CALL 0x0045961a          ; -> *(that+0xc)+0x54   (IP string)
00a5605e  MOVZX EAX,word ptr [0x01c1caa0]   ; 50201
00a56067  CALL dword ptr [0x0221ac28]       ; inet_addr
00a56071  CALL 0x0043d7c1          ; thunk_FUN_00a79710 : broadcast socket, NO bind
00a56076  TEST AL,AL
00a56078  JZ   0x00a560a6         ; bail out
00a5607a  MOV ECX,dword ptr [0x01ca0c88]
00a56080  CALL 0x0040f47a          ; -> *(obj+0xb4)
00a56087  CALL 0x0045b7bc          ; thunk_FUN_007e42a0
00a5608e  TEST ECX,ECX
00a56090  JZ   0x00a560a6         ; <-- the guard
00a56099  MOVZX EAX,word ptr [0x01c1caa0]
00a560a1  CALL 0x00406997          ; thunk_FUN_00a79b80 : creates a socket, then binds
```

Two separate socket objects, created by two separate calls:

- `FUN_00a79710` does `socket(2,2,0)` then `setsockopt(SO_BROADCAST)`. It never binds.
- `FUN_00a79b80` does `socket(2,2,0)` **and then** `bind(s, &addr, 16)`.

So each attempt that passes the guard produces **two** `socket()` calls, one of which is
immediately followed by a `bind`. Each attempt that fails the guard produces **one**.

### 2.3 The logs agree, in both directions

Working Child, `v0.1.0` (`bisect_logs/..._005404_pid21292.log`):

```
+65682.391ms  SOCKET api=socket af=2 type=2 result=5696
+65685.545ms  NET    bind sock=5696 service=SETTING local=192.168.139.17:50201 result=0
+86345.666ms  CLOSE  socket=5696 service=SETTING
+86355.739ms  SOCKET api=socket af=2 type=2 result=5196
+86359.320ms  NET    bind sock=5196 service=SETTING local=192.168.139.17:50201 result=0
```

One socket per retry, then a bind 3 ms later. Repeats on the same ~20.6 s cadence.

Failing Child, branch (`logs_3/B_guest/..._223601_pid8684.log`):

```
+68677.117ms  SOCKET api=socket af=2 type=2 result=5696
+89345.150ms  SOCKET api=socket af=2 type=2 result=5672
```

One socket per retry, and **no second socket and no bind**, on the same ~20.6 s cadence.

The socket handle `5696` appearing in both is only coincidence, but the shape is the
point: the failing log has exactly one `socket()` per attempt where the working log has
`bind` on that same socket. Since `FUN_00a79b80` allocates its own socket before
binding, a passing guard would have added a *second* `socket()` line. It did not.

**Therefore the guard `*( *( *(client+0xb4) + 0xc ) + 0x50 ) == 0` was false.** The game
decided not to bind. The hook is not swallowing anything.

### 2.4 The guard is a configuration field, not a socket

`thunk_FUN_007e42a0` is `*( *(p + 0xc) + 0x50 )`, and its sibling
`thunk_FUN_007e0940` is `*( *(p + 0xc) + 0x54 )`, used as an IPv4 string with the usual
`capacity < 0x10` SSO test at `+0x14`. Two adjacent fields on one shared structure: a
32-bit value at `+0x50` and a `std::string` at `+0x54`.

That structure is the Child's own Setting configuration — the address it is told to bind
and the port/flag beside it. It is populated by the game from its runtime settings
(`FUN_00de4230` / `FUN_00a57f00` configure Setting; `role == 0` selects Parent). The
hook never writes it.

### 2.5 Consequence

The open question is no longer "what did the hook break". It is "why does this machine's
Child have that field zero", which is a configuration or game-state question, and it
was the same on both DLL versions — the three failing runs used the branch, but so did
the two Parent runs that bound fine, and `v0.1.0` Child runs on the same machine did
bind. The DLL version is not the axis; the machine's configuration at the moment of
launch is.

## 3. What was right

- **`db6d49a`'s diagnosis of the forcing bug is correct and independently confirmed.**
  `netenv` reports `IfIndex = 1` and `OnLinkPrefixLength = 24`
  (`references/segatools/common/platform/netenv.c:253,301,306`), and the game sends
  Setting/Party/Advertise to `192.168.139.255`. Matching only `INADDR_BROADCAST`
  therefore could never fire. `force_broadcast` appears 0 times across the `v0.1.0`
  logs and 2-3 times across the branch logs, `matched=directed`. This is the real bug
  the branch found, and it is worth having fixed.
- **Using an API `netenv` does not hook, rather than trying to defeat the hook.** The
  branch does not patch `GetAdaptersAddresses`; it asks a different question of a
  different API. That is the right shape for a hook that coexists with segatools.
- **Cross-checking rather than chaining.** `736c485`'s refusal to fall back to a
  virtualized index when no source answers, and its loopback guard for the case where
  all three APIs are virtualized to the same value, are both real defences rather than
  assumptions.
- **Extracting the decision table into `interface_resolution.h`.** Making the table a
  pure function is what lets it be tested without reproducing segatools' install race in
  a test process. This is what made the branch's logic reviewable at all.
- **`0dfd786`'s distinction between `directed` and `limited`.** Under `netenv`, the hook
  may sit before or after it in the `sendto` chain, so `matched=limited` does not prove
  the hook saw the game's original address. Recording which form matched is what makes a
  captured log interpretable, and it is cheap.

## 4. What was wrong

Not one commit is wrong on its own. The failure was in method:

1. **The branch was treated as the explanation for the bind regression before the
   mechanism was known.** Three Child runs lost the bind, so the branch was presumed
   guilty and the work archived. The mechanism in §2 shows the branch was not in the
   code path at all. The archive record did note the counter-evidence (§3.2) but did not
   resolve it.
2. **No run isolated a variable.** The one experiment that "fixed" it
   (`forceLimitedBroadcast=0`) also changed netenv state, so it proved nothing. With the
   analysis in §2, `forceLimitedBroadcast` could not have been the variable: it gates
   `ensure_broadcast_interface()`, which is only reached from `hook_sendto`/`hook_wsasendto`,
   and the failing logs contain no `sendto` at all before the socket appears.
3. **The blocking question was identified late.** `broadcast-interface-regression.md` §6
   lists "make `hook_bind` log unconditionally" as priority 1, but `log_io` still drops
   any bind whose port is not one of the five known ones — so a bind with an unexpected
   address is invisible. That gap is what made §2.3 above take a night of bisecting
   instead of one line of static analysis.
4. **The netenv install-order race was left open** (§6.2). Every captured run shows
   either all real adapters or only `Fake Ethernet`, never a mix, and it does not track
   the DLL version. Until it is pinned down, any A/B on one machine is not an experiment.
   This is a live risk for the porting work and is called out in `docs/porting-plan.md`.

## 5. What this means for porting

The broadcast and interface-resolution work is ported to `main` because it fixes a real
egress bug, verified separately from the bind issue. It is not expected to fix the bind.

Two things are done differently:

- **Ported in dependency order, one concern per commit**, each building and smoke-tested
  on its own, so a regression can be attributed to a single change.
- **The diagnostic gap is closed first**, before any behaviour changes, so the next
  on-machine run answers the bind question without another bisect. See
  `docs/porting-plan.md` for the per-commit plan and the test procedure.