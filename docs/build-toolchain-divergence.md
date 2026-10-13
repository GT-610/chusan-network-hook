# Build toolchain divergence: the v0.1.0 release binary is not a local build

**Status: confirmed by binary evidence. Root cause of the bind investigation's dead end.**

## 1. The finding

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

## 6. Next step (needs a machine)

Reproduce the CI binary locally, then bisect between the two builds.

1. Determine which toolset directory the CI runner resolved. The `windows-2022` image
   plus run `35078996453` used `VsDevCmd.bat`; the Rich header says CRT build 33145, which
   pins it to a specific MSVC version directory.
2. Build the same tag with that toolset/CRT on this machine and confirm the Rich header
   reports 33145 and the size returns to 150528/184832. If it does, the two builds become
   directly comparable and every difference from that point is a real code difference.
3. If the local host cannot produce 33145, run the experiment the other way: build Port 1
   **on CI** and test that artifact, so both sides come from the same image.
4. Only after the build is held constant does a Port 1 A/B mean anything.

Until step 1 or 3 completes, the bind question has no controlled experiment available,
and no further log reading will answer it.

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