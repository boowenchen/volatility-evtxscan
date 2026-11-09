# evtxscan — recover Windows event logs from memory

`windows.evtxscan` is a Volatility 3 plugin that finds Windows event log (EVTX) data in a memory image,
verifies it, parses every record, and writes the recovered chunks back out as `.evtx` files that Event
Viewer, `wevtutil`, EvtxECmd or python-evtx open directly.

Volatility 2 had `evtlogs` for the XP-era `.evt` format. Volatility 3 has nothing for the EVTX format
used since Vista, although event logs are one of the first things an investigator asks for and one of the
first things an intruder deletes.

## Why memory

- The EventLog service memory-maps each `.evtx` file it writes, so recently used 64 KiB chunks sit in its
  address space.
- Pages of log files also live in the file cache and in freed physical memory. Chunks of logs the service
  is not currently holding, of older parts of a log, or of a log that has since been cleared or deleted
  can still be there.

`evtxscan` reads both.

## How it works

1. **Find chunks.** Scans the VADs of the svchost process hosting the EventLog service (selected from
   its command line, or by `--pid`) for the `ElfChnk\0` signature. With `--physical` it also scans the
   whole physical address space.
2. **Check them.** Validates the chunk header CRC32 and the record-data CRC32 and reports both, so you
   can see which chunks are intact. Header fields must be self-consistent before a hit is accepted.
3. **Parse records.** Walks records by their `**\0\0` signature and requires the length to be repeated at
   the end of each record. A paged-out (zeroed) page therefore only loses the records it held; records
   after it are still recovered. Records are rendered with python-evtx, and the plugin reports time
   created, event ID, channel, provider and event data.
4. **Collapse duplicates.** The same chunk is often mapped and cached several times. Copies are merged,
   preferring a copy whose checksum verifies, and records are de-duplicated by channel, record ID and
   timestamp.
5. **Flag what the service does not hold.** A record found only in physical memory is marked
   `channel not mapped` when the service has no chunk of that log mapped, or `older than mapped chunks`
   when it predates everything the service holds for that log. These are the records a live triage tool
   reading `C:\Windows\System32\winevt\Logs` through the service would not show you. Log-clear events
   (Security 1102, System 104) are flagged as `log cleared`.
6. **Rebuild files** (`--dump`). Verified chunks are grouped by channel, ordered by record ID, split into
   generations where record ranges overlap, and wrapped in a freshly built EVTX file header with a valid
   checksum. One file is written per channel (and per generation).

## Usage

```bash
pip install volatility3 python-evtx
vol -f memory.raw -p plugins windows.evtxscan.EvtxScan              # EventLog service memory
vol -f memory.raw -p plugins windows.evtxscan.EvtxScan --physical   # plus all physical memory
vol -f memory.raw -p plugins -o out windows.evtxscan.EvtxScan --physical --dump
vol -f memory.raw -p plugins windows.evtxscan.EvtxScan --records false   # one row per chunk
```

| Option | Meaning |
|---|---|
| `--pid` | Scan these processes instead of auto-detecting the EventLog svchost |
| `--physical` | Also scan physical memory |
| `--dump` | Write verified chunks as `recovered-<channel>.evtx` |
| `--records false` | List chunks (record range, header/data CRC) instead of records |
| `--all-chunks` | Do not collapse duplicate chunk copies or duplicate records |

Columns: `Source` (PID or physical), `Offset`, `FirstRecord`/`LastRecord`, `HeaderCRC`, `DataCRC`,
`TimeCreated` (UTC), `EventID`, `Channel`, `Provider`, `Note`, `Data`.

Without python-evtx installed the plugin still lists every record's ID and timestamp.

## Results on public memory images

All three images are public and free to download; their hashes are in
[`evidence/results.json`](evidence/results.json), and the full record lists are the CSVs in `evidence/`.

| Image | OS | Records | From EventLog process | From physical only | Channels | Time |
|---|---|---:|---:|---:|---:|---:|
| [MemLabs Lab 1](https://github.com/stuxnet999/MemLabs) | Windows 7 SP1 x64 | 1,037 | 827 | 210 | 24 (9 only in physical) | 7 s |
| [DFIR Madness Case 001](https://dfirmadness.com/the-stolen-szechuan-sauce/) DESKTOP-SDN1RPT | Windows 10 19041 | 225 | 52 | 173 | 42 (34 only in physical) | 12 s |
| DFIR Madness Case 001 CITADEL-DC01 | Windows Server 2012 R2 | 17,882 | 2,330 | 15,552 | 49 (24 only in physical) | 58 s |

Times are full runs with `--physical --dump` on a laptop.

**The intrusion in Case 001 shows up.** In the domain controller's memory, `--physical` recovers 19
`RdpCoreTS/Operational` records of RDP connections from `194.61.24.102` at 03:20–03:21 UTC on
2020-09-19, including event 139 failures (`ResultCode=0x80090304`) during the brute force. The
EventLog service had no chunk of that log mapped; those records came from physical memory only.

```text
physical  2020-09-19 03:20:25.797 UTC  131  RdpCoreTS/Operational  channel not mapped  ConnType=TCP; ClientIP=194.61.24.102:39868
physical  2020-09-19 03:20:25.797 UTC  139  RdpCoreTS/Operational  channel not mapped  ResultCode=0x80090304; IPString=194.61.24.102
```

**Recovered files open in Windows.** Every `.evtx` written by `--dump` on the three images was opened
with Windows' own `wevtutil qe /lf:true`: 47 files, 1,838 events read, no file rejected
([`evidence/wevtutil-check.json`](evidence/wevtutil-check.json)). On MemLabs Lab 1 the Security file
returns the same 81 records the plugin lists.

Some records do not render (shown with channel `-`): their chunk is missing the page holding a template
they reference. They are still listed with record ID and timestamp so the gap is visible.

## Tests

```bash
pip install pytest python-evtx
pytest tests
```

The unit tests use one verified chunk recovered from MemLabs Lab 1 (the Known Folders log, 49 records).
They check the checksums, all 49 records and their fields, header and data tampering, recovery after a
zeroed page, the length-repeat check, the rebuilt file (verified and re-read with python-evtx), chunk
ordering, and the XML summary. Breaking the data checksum check, the length-repeat check, the chunk
ordering or the skip-past-damage loop each makes the suite fail ([`evidence/mutation.txt`](evidence/mutation.txt)).

## Limits

- Records whose template definition sits in a missing page cannot be rendered (they are listed, not
  dropped).
- Chunks with failed checksums are listed but not written to `.evtx`, because Event Viewer stops at the
  first damaged chunk.
- `older than mapped chunks` says the EventLog service did not hold that part of the log at capture time.
  On its own it does not prove the log was cleared; check for 1102/104 events and compare with the disk
  copy.
- Tested on Windows 7, Windows 10 and Server 2012 R2 images.

## License

Volatility Software License 1.0, the same license as Volatility 3.
