# pigsydust scripts

## Regenerating `DeviceClass` from a new SAL Pixie app release

The `DeviceClass` enum in `pigsydust/device_class.py` mirrors the
`DeviceType → (type, stype)` table compiled into SAL's Android app. When
SAL ships a new release that adds hardware classes, the enum needs to be
regenerated.

1. Pull the APK (e.g. via APKPure) and extract `lib/arm64-v8a/libapp.so`.
2. Run [blutter](https://github.com/worawit/blutter) against that `.so`:
   ```
   python3 ~/src/blutter/blutter.py path/to/lib/arm64-v8a out_dir
   ```
   This produces `asm/pixie_sdk/pixie_sdk.dart` and `pp.txt`, which
   `extract_devicetype_table.py` consumes.
3. Before running the extractor, check that the `FUNC_BASE` and
   `JUMP_TABLE_SIZE` constants at the top of
   `extract_devicetype_table.py` still match the new binary. Find the
   function with:
   ```
   grep -n "static _ getTypeStype(" out_dir/asm/pixie_sdk/pixie_sdk.dart
   ```
   Bump `FUNC_BASE` to the `**` entry address. The jump-table size is
   the number of `DeviceType` enum members (count entries in `pp.txt`
   matching `DeviceType@`).
4. Run the extractor and commit the refreshed table:
   ```
   python3 scripts/extract_devicetype_table.py out_dir > scripts/devicetype_table.txt
   ```
5. Reconcile `src/pigsydust/device_class.py` against the new table —
   add any new members, retire any that have been removed upstream, and
   bump the library version. The Home Assistant integration
   (`ha-pigsydust`) must then add translation strings for the new
   members in `strings.json`.
