# Triage of `fix-broadcast-interface-resolution` (db6d49a..0dfd786)

> **Superseded in part.** The conclusion in §2 ("the branch could not have caused the bind
> regression, it is a game-side guard") was reached from log shape alone and is **not
> established**. A controlled A/B on 2026-10-13 later showed the opposite: a locally
> built v0.1.0 and Port 1 differ in behaviour, and the real variable turned out to be the
> **build toolchain**, not the source. See
> [`docs/build-toolchain-divergence.md`](build-toolchain-divergence.md), which supersedes
> the causal claim in §2. §1 (per-commit verdicts), §3 (what was right) and §4.1 (method
> failures) remain valid; §4.2 and §5 are revised.

**Purpose.** Read every commit on the archived branch on its own terms, decide what was
right and what was wrong, and decide what to port to `main`. This replaces the previous
framing ("the branch failed, so archive it") with a per-commit verdict.

**Headline conclusion.** The branch fixed a real bug that was never the reported
failure: interface forcing genuinely never engaged. Porting it is worth doing on its own
merits. Whether it relates to the Setting bind is **still open**, and is now known to be
confounded by a build difference rather than settled by the reasoning below.

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

## 2. The bind: what the disassembly shows, and where this section is wrong

This section originally concluded that the bind failure was a game-side guard evaluating
false and therefore unrelated to the hook. **That conclusion was wrong in its causal
claim.** The disassembly facts below still hold; the inference drawn from them does not.

### 2.1 What the archive record said

`broadcast-interface-regression.md` §3.1 observed that the failing Child logs contain a
`SOCKET` line and no `bind`, and called the link to `FUN_00a56010`'s guard
"consistent with `FUN_00a79710` having run and the guarded `FUN_00a79b80` not having
run. That is suggestive, not conclusive."

### 2.2 What the disassembly shows

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

`FUN_00a57060` constructs `Setting::Host` and `Setting::Client` into the **same
allocation** (`puVar2` is passed to both `FUN_00a7d440` and `FUN_00a80c40`), which is
why reading `client+0xb4` is well defined.

### 2.3 The counting argument was wrong

This section used to claim that the guard could be read off the *number* of `socket()`
calls per attempt. **It cannot.** Measured across all available logs:

| log | role | `socket()` per attempt | `bind` |
|---|---|---|---|
| `logs_3/B_main/..._222903_pid5808` | Parent, bound | 1 | yes |
| `bisect_logs/..._005404_pid21292` | Child, bound | 1 | yes |
| `logs_3/B_guest/..._223601_pid8684` | Child, no bind | 1 | no |

All three are 1:1. `FUN_00a79b80`'s own `socket()` is never visible in any log, so the
count carries no information. The only reliable indicator is whether a `bind` line
appears at all — which is why Port 1 added unconditional bind tracing.

### 2.4 The guard field is not identified

The guarded value is `*( *(*(client+0xb4) + 0xc) + 0x50 )`. Its sibling `+0x54` is an
IPv4 string with the usual SSO capacity field at `+0x14`. A setting dump function
(`FUN_00a576a0`) prints a field labelled `isRetryEnable` through vtable slot `+0x50`,
but that is a **virtual slot on a different object**, not a field at offset `+0x50`, and
conflating the two is a mistake this file previously made. The writer of the guarded
field has not been identified.

### 2.5 Why the causal claim collapsed

The reasoning "same `hook_bind` source, so the hook cannot be responsible" assumed the
two DLLs under comparison were the same build. They were not:

- the "working v0.1.0" was the **GitHub Release binary**, built by CI;
- the "broken Port 1" was built **on this machine**.

Those two binaries differ in CRT library version, size and import set — see
[`docs/build-toolchain-divergence.md`](build-toolchain-divergence.md). A controlled A/B
on 2026-10-13 then showed the locally built v0.1.0 also fails to bind, which removes the
source change as the variable and points at the build. **Source equivalence does not imply
binary equivalence**, and that assumption was the reason this investigation went in
circles.

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
   guilty and the work archived. The archive record did note the counter-evidence
   (§3.2) but did not resolve it. Presuming the newest change is at fault is the default
   trap; the correct move was to reproduce the *old* build locally and A/B it.
2. **No run isolated a variable.** The one experiment that "fixed" it
   (`forceLimitedBroadcast=0`) also changed netenv state, so it proved nothing. With the
   analysis in §2, `forceLimitedBroadcast` could not have been the variable: it gates
   `ensure_broadcast_interface()`, which is only reached from `hook_sendto`/`hook_wsasendto`,
   and the failing logs contain no `sendto` at all before the socket appears.
3. **The blocking question was identified late.** `broadcast-interface-regression.md` §6
   lists "make `hook_bind` log unconditionally" as priority 1, but `log_io` still drops
   any bind whose port is not one of the five known ones — so a bind with an unexpected
   address is invisible. Port 1 closed this gap.
4. **The netenv install-order race was left open** (§6.2). Every captured run shows
   either all real adapters or only `Fake Ethernet`, never a mix, and it does not track
   the DLL version. Until it is pinned down, any A/B on one machine is suspect. This is
   called out in `docs/porting-plan.md`.
5. **Source equivalence was treated as binary equivalence — the costliest mistake.**
   Because `git diff v0.1.0 main -- src/` is empty, the two DLLs were assumed to be the
   same program. They are not: the release binary was built by CI, the comparison binary
   on this machine, and they differ in CRT library version. Every A/B drawn between them
   was therefore measuring two variables at once. This is now the primary finding; see
   [`docs/build-toolchain-divergence.md`](build-toolchain-divergence.md).

## 5. What this means for porting

The broadcast and interface-resolution work is ported because it fixes a real egress bug,
verified separately from the bind issue. Whether it also affects the bind is **unknown**:
that question is now blocked on reproducing the CI build locally, not on more log reading.

Three things are done differently:

- **Ported in dependency order, one concern per commit**, each building and smoke-tested
  on its own, so a regression can be attributed to a single change.
- **The diagnostic gap is closed first**, before any behaviour changes, so the next
  on-machine run answers the bind question without another bisect.
- **Every A/B must hold the build constant.** Compare only binaries built by the same
  toolchain, and record which one was used. See `docs/porting-plan.md`.