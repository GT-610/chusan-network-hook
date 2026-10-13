# Build toolchain divergence: the v0.1.0 release binary is not a local build

**Status: superseded in part. See §0. The toolchain divergence is real, but it is NOT
the cause of the bind difference and it is NOT a CI-vs-local-only effect.**

## 0. Correction (2026-10-13, after CI-built Port 1 and CI-built main became available)

Two CI artifacts were built from the same runner image, which removes the confound:

- `references/issues/v0.1.0_release` — the GitHub Release artifact for `v0.1.0` (binds)
- `references/issues/main_release` — CI build of `main` @ `01450ac`
- `references/issues/0032f83_release` — CI build of Port 1 @ `0032f83`

### 0.1 CI v0.1.0 and CI main are the same binary

| property | CI v0.1.0 | CI main |
|---|---|---|
| x86 size | 150528 | 150528 |
| identical bytes | — | **150497 / 150528 = 99.98 %** |
| `.rdata` string diff | — | **0 differences** |

All 31 differing bytes are accounted for:

- `0x80`–`0xDF` — the XOR-encoded Rich header, because the XOR key differs
  (`0x89F632A5` → `0x89F632A9`). The only decoded difference is the linker entries
  `0x102`/`0x105`, build `35228` → `35229`.
- `0x100`–`0x102` and `0x2101C`–`0x2101E` — the PE `TimeDateStamp`
  (`0x6AAA5FD5` → `0x6ACDA199`), stored once in the COFF header and once in the
  debug directory.

**So `main` really does rebuild to the same binary as `v0.1.0`.** The user's
expectation here was correct, and the earlier claim that the two were materially
different binaries does not hold between two CI builds.

### 0.2 CI Port 1 vs CI main: 83.6 % of bytes differ, but the code is the same code

| property | CI main | CI Port 1 |
|---|---|---|
| x86 size | 150528 | 150528 |
| byte diff | — | 125891 (83.6 %) |
| `.text` per-section identical | — | **3.2 %** |
| `.text` shared 4-byte words (multiset) | — | **94.9 %** |
| `.rdata` string diff | — | exactly 2: `bind_virtualized`, the new format string |
| `.text` growth | 0x198B0 | 0x19980 (**+0xD0 = 208 bytes**) |
| `.reloc` growth | 0x16A0 | 0x16B8 (**+0x18 = 6 relocation entries**) |

The byte-position comparison is dominated by a **layout shift**: the 208 extra
bytes of `.text` move everything after the insertion point, so a naive
position-wise diff reports ~84 %. Measured as a multiset of 4-byte words
(shift-insensitive), 94.9 % of the code words are shared, and the visible
strings differ by exactly the two Port 1 log strings — nothing else.

A constant-delta model does **not** fit cleanly (best delta `+0xD0` matches
86.2 %, common prefix under that delta is 0 bytes), so the insertion is not one
contiguous block; `log_bind_always` is called from two sites in `hook_bind`,
which would produce exactly this shape.

**Conclusion: Port 1's CI build is a faithful CI build of Port 1.** The 84 % figure
is a measurement artifact, not evidence of a different program.

### 0.3 What this does and does not settle

- It **does** settle the Port 0 prerequisite from the original plan. Reproducing
  CRT 33145 locally, or building both sides on CI, is **no longer needed**: the
  release artifact and Port 1 are already CI-built and mutually comparable.
- It **does** confirm the toolchain divergence is real and CI-wide, but shows it
  is **constant across CI builds** — v0.1.0 and Port 1 both use CRT 33145 and
  linker 35228/35229. The toolchain therefore cannot distinguish "binds" from
  "does not bind" between two CI builds; it only distinguishes CI from this host
  (CRT 27412).
- It **does not** prove Port 1's code causes the bind difference. Port 1 adds
  logging only and does not alter control flow, so a CI-built Port 1 is expected
  to behave like a locally built Port 1. Testing it is still worthwhile only to
  confirm that expectation; it cannot by itself find the cause.

**The remaining unknown is the runtime environment, not the binary.** Given a
CI-built binary that provably contains the same code, if it still fails to bind
on a given machine while the v0.1.0 artifact binds, the difference must come from
the environment (adapter count, whether netenv loaded, `Fake Ethernet` presence),
not from the DLL.

## 1. The original finding (still valid for CI-vs-local)

`git diff v0.1.0 main -- src/` produces **no output**. The source is identical. That was
taken to mean the two DLLs are equivalent, and every subsequent A/B relied on it.

They are not equivalent. The `v0.1.0` binary that binds successfully is the **GitHub
Release artifact, built by CI on a different toolchain**. A local build of the same tag
does **not** bind.

| property | release v0.1.0 (binds) | local build of v0.1.0 (does not bind) | Port 1 |
|---|---|---|---|
| source | `v0.1.0` = `f4a9262` | `v0.1.0` = `f4a9262` | `main` + Port 1 |
| x86 size | 150528 | 134144 | 134656 |
| x64 size | 184832 | 165888 | 165888 |
| x86 SHA256 | `8BCA7F78B2D916D6…` | `037E98E6AA8584A8…` | `990E96735FC84434…` |
| x64 SHA256 | `005A654D00244D1A…` | `9B551EECF3922DAD…` | `A53FCCC9587DC125…` |
| imports (x86) | 105 | 99 | 99 |
| `EncodePointer` | imported | absent | absent |
| Rich CRT build | **33145** | **27412** | **27412** |

The local v0.1.0 rebuild and Port 1 have **identical Rich headers**, which is the point:
they are the same build. The release binary is a different build of the same source.

Note the x64 row: local v0.1.0 and Port 1 are both 165888 bytes but have **different
hashes**. Same source shape, different bytes — a direct demonstration that byte-level
equality must be checked, not inferred from a diff of the sources.

## 2. How it was found

The controlled A/B on 2026-10-13 compared a locally built v0.1.0 against Port 1:

| log | binary | chusanApp `BIND` lines | Setting bind |
|---|---|---|---|
| `references/issues/log_v0.1.0/..._093817_pid25188` | CI-built v0.1.0 | 0 (feature absent) | **2, successful** |
| `references/issues/log_port1/..._094037_pid22192` | local Port 1 | **0** | **none** |
| `references/issues/log_port1/..._094037_pid10832` | local Port 1, amdaemon | 77 | — |

Both Child runs used identical configuration (`force_limited_broadcast=1`, byte-identical
`CONFIG` lines), identical adapter enumeration (13 real adapters, no `Fake Ethernet`, so
netenv was inactive in both), and the same ~20.7 s retry cadence. The only difference was
which binary was loaded.

Rebuilding `v0.1.0` locally from the same tag and diffing its PE import table against the
release artifact then produced the numbers above.

## 3. Where the difference lives

The PE **Rich header** records which toolset contributed which object files. Decoding it
(`tools/dump_rich.ps1`):

| entry | release | local |
|---|---|---|
| `0x103` (CRT obj) | build **33145** | build **27412** |
| `0x104` (CRT obj) | build **33145** | build **27412** |
| `0x105` (CRT obj) | build **33145** | build **27412** |
| `0x101` | build **33145** | build **27412** |
| `0x103`/`0x104`/`0x105` | build 35207 | build 35207 |
| `0x105`, `0x102` | 35228 | 35228 |

So the **C/C++ compiler is the same** (35207 / 35228, i.e. `cl.exe` 19.44.35228, matching
the local `Microsoft (R) C/C++ Optimizing Compiler 19.44.35228`). What differs is the
**static CRT library**.

### 3.1 Which group is the CRT, verified locally

A one-line DLL built here with each option identifies the roles:

| build | `27412` group | `35207` group |
|---|---|---|
| `/MT` (static CRT) | present | present |
| `/MD` (dynamic CRT) | **absent** | present |

The `27412` group appears only under `/MT`, and `/MD` replaces it with
`0x93 / 30729` (`Utc1900_C`, the dynamic UCRT). That makes the `27412`/`33145` entries the
static CRT (`libucrt.lib` + `libvcruntime.lib` + `libcmt.lib`) and the `35207`/`35228`
entries the compiler itself. The hook DLLs carry both groups, which is consistent.

### 3.2 Why the CRT can differ from the compiler

Microsoft versions the static CRT separately from the compiler. From the CRT library
documentation: *"The vcruntime library version needs to match the version of the compiler
you're using"*, and *"Every executable image (EXE or DLL) can have its own statically
linked CRT... The version of the CRT statically included in or dynamically loaded by a
particular image depends on the version of the tools and libraries it was built with."*
A single process may therefore load several CRTs, *"each with its own CRT... may use a
different allocator, may have different internal structure layouts"*.

The official compiler table lists `_MSC_VER` and the `14.xx` toolset version (14.26 =
VS2019 16.6, 14.28 = VS2019 16.8/16.9, 14.44 = VS2022 17.14). **Those numbers are not the
Rich header build numbers.** 35207/35228 match the local `cl.exe` 19.44.35228, so the
compiler entries are identifiable; **27412 and 33145 are only known to be two different
builds of the static CRT, and which MSVC versions produced them is not established here.**
This host has only toolset 14.44 installed, so it cannot be determined by building.

The size delta is 16384 bytes for x86 and 18944 for x64, consistent with a different static
CRT plus the extra `Fls*`/`EncodePointer`/`InitializeCriticalSectionEx` imports that the
33145 CRT pulls in.

Consequence: the CI runner image carries a **mixed toolchain** — a current compiler with
an older static CRT. `build.bat` selects whatever `VsDevCmd` resolves, so the CRT version
is a property of the runner image and can change without any change to the repository.

## 4. Why this matters to the hook

`build.bat` links `/MT` (static CRT). The hook depends on CRT and Win32 primitives whose
implementation differs between the two builds:

- `SRWLOCK g_log_lock = SRWLOCK_INIT` and `SRWLOCK g_state_lock = SRWLOCK_INIT` — static
  initialization, and every log line takes `g_log_lock` exclusively.
- `EncodePointer`/`DecodePointer` hardening, present only in the release build.
- The `Fls*` fibre-local-storage path used by the CRT for thread-local state.

Any of these could change behaviour in a hook that runs inside a third-party process and
is loaded from a launcher that may itself install hooks. **None of this is proven to be
the cause of the bind failure.** It is the first thing that differs and therefore the
first thing to eliminate.

## 5. Pitfalls this investigation hit

1. **Assuming source equality implies binary equality.** `git diff v0.1.0 main -- src/`
   being empty says nothing about the artifacts. Compare hashes and Rich headers.
2. **Comparing a CI artifact against a local build.** Every "v0.1.0 works / branch doesn't"
   claim made before 2026-10-13 was comparing two different toolchains.
3. **Trusting a version label instead of a hash.** `v0.1.0` names a tag, not a binary.
4. **Reading counts out of a filtered log with the wrong field index.** Log lines are
   tab-separated with the category at index 4, not 3. Counting with the wrong index
   produced a spurious "the new code did not run" conclusion. Match on the category
   column, not a substring: `bind_skipped` contains `bind`.
5. **Inferring control flow from a counting argument that was never measured.** The
   "one socket vs two sockets" test was used before being checked against the logs; when
   checked, all three cases were 1:1 and it carried no information.
6. **Matching a vtable slot against a field offset.** `isRetryEnable` printed via vtable
   slot `+0x50` was briefly treated as the field at offset `+0x50`. They are unrelated.
7. **Reading a raw byte-diff percentage as a measure of program difference.** CI Port 1
   vs CI main differ in 83.6 % of bytes, but 94.9 % of `.text` 4-byte words are shared
   and the string sets differ by exactly the two new log strings. A code insertion shifts
   every later byte; position-wise diffing cannot distinguish that from a rewrite.
   Compare shift-insensitively (word multiset, or string sets) before concluding.
8. **Assuming two builds differ because the source differs.** The correct comparison of
   CI v0.1.0 against CI main is 99.98 % identical bytes, all 31 differences explained by
   the Rich XOR key and the PE timestamp.

## 6. Next step

**Original step 1–3 are obsolete.** Reproducing CRT 33145 locally, or building Port 1
on CI, was the proposed prerequisite. Both CI artifacts now exist (§0), so both sides
of the comparison come from the same runner image. That work is unnecessary.

The open question is no longer the toolchain. It is:

1. Run the CI-built Port 1 artifact and the CI-built `main`/v0.1.0 artifact on the same
   machine under the same conditions, and record the `ADAPTER` section plus the
   `BIND`-category line count (category column index 4, never a substring match).
2. If CI-built Port 1 still does not bind while CI-built main does, the binary is
   exonerated and the **environment** is the variable: adapter count, netenv
   installation order, `Fake Ethernet` presence.
3. Only then return to the porting queue (`docs/porting-plan.md`), starting at
   `db6d49a` — the directed-broadcast fix — which addresses a real, independently
   verified defect regardless of the bind question.

## 7. Tools added

- `tools/dump_imports.ps1` — decodes the PE import directory, per DLL and per symbol.
- `tools/dump_rich.ps1` — decodes the Rich header, XOR-decoding the compid/build pairs.

Both take a path and print plain text. Run them on any candidate DLL before comparing
builds; the Rich header's first four entries are the fastest toolchain fingerprint.

They require **PowerShell 7+** (`pwsh`); Windows PowerShell 5.1 cannot parse them. Invoke
from the repository root so the relative path resolves:

```powershell
pwsh -File tools\dump_rich.ps1    -Path build\chusan_network_hook_x86.dll
pwsh -File tools\dump_imports.ps1 -Path build\chusan_network_hook_x86.dll
```

Expected output for the local build — note `27412`:

```text
RICH_HEADER_FOUND key=0x8DD52DFB span=96
  0x103    27412   10
  0x105    27412   139
  0x104    27412   18
  0x103    35207   18
```