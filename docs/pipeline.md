# steam-monitor pipeline

Every 15 min CI polls the stable + beta win64 manifests. On a new build it
downloads the DLLs, re-resolves all hook signatures from scratch, and
publishes per-SHA TOMLs. Same entry schema as the legacy feed
(`[FNV-hash] / name / rva / sig`), so the client only needs a URL swap.
IPC interface data goes to `ipc/steamclient/<sha>.toml` in the upstream IPC
schema (`interface_id` / `vtable_rva` plus per-method `method_index` /
`funcHash` / `wrapper_rva` / `fencepost` / `argc`).

1. `tools/fetch_client.py` → `bins/<channel>/` (exit 2 = already published, skip)
2. `tools/resolve_patterns.py` → `pattern/<side>/<sha256>.toml` (any FAIL = nonzero exit)
3. `tools/resolve_ipc.py` → `ipc/steamclient/<sha256>.toml` (any FAIL = nonzero exit)
4. Any FAIL → nothing published, an issue is filed, re-run via `workflow_dispatch`
5. On success: `README.md` is re-rendered (knap, do not hand-edit) and committed with `pattern/` + `ipc/`

Blocked-run triage notes:
- Duplicate prevention: one open issue per beta SHA pair; a green publish
  closes leftover issues whose title SHAs are now published.
- `steamclient` anchor collisions: candidates can be pinned by prologue
  bytes via `PROLOGUE_PINS` in `tools/resolve_patterns.py` (worked example:
  the 1792192922 beta twins for `CUtlBufferEnsureCapacity`).
- IPC funcHash/fencepost re-rolls: when a wrapper fails its hash check,
  extract the new constants from the wrapper's outgoing-buffer writes —
  each `mov dword ptr [..], imm32` followed by the 4-byte append helper
  (`call <helper>`); first immediate is funcHash, second is fencepost.
  Update the channel's `IPC_CONSTANTS` entry in `tools/resolve_ipc.py` and
  re-run with the same `--channel`.
- Phase-2 window misses: `p2_findcreate` scans the 64KB page holding
  `KeyValues_ReadAsBinary`, assuming the KeyValues helpers stay on one page.
  When the block shifts and the two land on opposite sides of a boundary
  (1792711043 beta: `ReadAsBinary` at 0xDA0AE0, `FindOrCreateKey` at
  0xD9DEC0), the window is empty and the picker falls back one page down.
  A `0 <name> cands` failure from a phase-2 rule is worth checking against
  page alignment before touching thresholds or anchors.
- Issue filing needs the repository's Issues feature enabled. With issues
  disabled, `gh issue list` and `gh issue create` return 410 and the triage
  step fails on its own, hiding the resolve failure it exists to report.

No TOMLs are shipped or fetched — every hook derives from the DLLs alone.
`tools/migrate_patterns.py` is a seed-era analysis aid, not in the pipeline.

## Local run

```sh
python3 -m unittest discover -s tests
python3 tools/fetch_client.py --out bins/ --channels stable beta
python3 tools/resolve_patterns.py resolve \
  --dll bins/stable/steamclient64.dll --side steamclient --out-dir pattern/
python3 tools/resolve_ipc.py resolve \
  --dll bins/stable/steamclient64.dll --channel stable --out-dir ipc/
```
