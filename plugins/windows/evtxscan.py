# This file is Copyright 2026 boowenchen and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
"""Recover Windows event log (EVTX) records from memory.

On Vista and later the EventLog service memory-maps each .evtx file and keeps recently used 64 KiB chunks
in its address space, and chunk-sized remnants also linger in physical memory after the file is cleared
or deleted. This plugin finds those chunks, checks them, parses the records they contain and can write
them back out as .evtx files that standard tools open.
"""
import datetime
import logging
import re
import struct
import zlib
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

try:
    import Evtx.Evtx as evtx_lib

    # python-evtx logs a warning for every damaged record; the plugin reports those itself.
    logging.getLogger("Evtx.Evtx").setLevel(logging.ERROR)
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False

CHUNK_MAGIC = b"ElfChnk\x00"
CHUNK_SIZE = 0x10000
CHUNK_HEADER_SIZE = 0x200
RECORD_MAGIC = b"\x2a\x2a\x00\x00"
FILE_HEADER_SIZE = 0x1000
EPOCH_1601 = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
# Event ids written when a log is cleared: Security 1102, any other log 104 (in System).
CLEAR_EVENTS = {"Security": ("1102",), "System": ("104",)}


# ---------------------------------------------------------------------------
# Format helpers. They take plain bytes so they can be tested without a memory image.
# ---------------------------------------------------------------------------


class ChunkInfo:
    """The fields of an EVTX chunk header we use, plus checksum results."""

    def __init__(self, data: bytes):
        self.data = data
        (
            self.first_record_num,
            self.last_record_num,
            self.first_record_id,
            self.last_record_id,
            self.header_size,
            self.last_record_offset,
            self.free_space_offset,
            self.data_crc,
        ) = struct.unpack_from("<QQQQIIII", data, 8)
        self.header_crc = struct.unpack_from("<I", data, 0x7C)[0]

    @property
    def header_ok(self) -> bool:
        computed = zlib.crc32(self.data[:0x78] + self.data[0x80:CHUNK_HEADER_SIZE]) & 0xFFFFFFFF
        return computed == self.header_crc

    @property
    def data_ok(self) -> bool:
        if not CHUNK_HEADER_SIZE <= self.free_space_offset <= CHUNK_SIZE:
            return False
        computed = zlib.crc32(self.data[CHUNK_HEADER_SIZE : self.free_space_offset]) & 0xFFFFFFFF
        return computed == self.data_crc

    @property
    def plausible(self) -> bool:
        """Header fields are self-consistent even if a page of the chunk is missing."""
        return (
            self.header_size == 0x80
            and self.first_record_id <= self.last_record_id
            and self.last_record_id - self.first_record_id < 0x10000
            and CHUNK_HEADER_SIZE <= self.free_space_offset <= CHUNK_SIZE
            and CHUNK_HEADER_SIZE <= self.last_record_offset < self.free_space_offset
        )

    def key(self) -> Tuple[int, int, int]:
        return (self.first_record_id, self.last_record_id, self.data_crc)


def filetime_to_datetime(ft: int) -> Optional[datetime.datetime]:
    if not ft:
        return None
    try:
        return EPOCH_1601 + datetime.timedelta(microseconds=ft // 10)
    except OverflowError:
        return None


def iter_record_spans(data: bytes, start: int = CHUNK_HEADER_SIZE, end: Optional[int] = None) -> Iterator[Tuple[int, int, int, int]]:
    """Yields (offset, size, record_id, filetime) for every record whose size is repeated at its end.

    Walking by magic instead of by the previous record's length lets us skip over a zeroed (paged-out)
    page and still pick up the records after it.
    """
    end = len(data) if end is None else min(end, len(data))
    pos = start
    while True:
        pos = data.find(RECORD_MAGIC, pos, end)
        if pos < 0 or pos + 24 > end:
            return
        size = struct.unpack_from("<I", data, pos + 4)[0]
        if 24 + 4 <= size <= CHUNK_SIZE and pos + size <= end:
            if struct.unpack_from("<I", data, pos + size - 4)[0] == size:
                record_id, filetime = struct.unpack_from("<QQ", data, pos + 8)
                yield pos, size, record_id, filetime
                pos += size
                continue
        pos += 4


_EVENT_ID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
_PROVIDER = re.compile(r'<Provider Name="([^"]*)"')
_CHANNEL = re.compile(r"<Channel>([^<]*)</Channel>")
_COMPUTER = re.compile(r"<Computer>([^<]*)</Computer>")
_DATA = re.compile(r"<Data(?: Name=\"([^\"]*)\")?>([^<]*)</Data>")


def summarize_xml(xml: str) -> Dict[str, str]:
    def first(rx):
        m = rx.search(xml)
        return m.group(1) if m else ""

    data = []
    for name, value in _DATA.findall(xml):
        if value:
            data.append(f"{name}={value}" if name else value)
    return {
        "event_id": first(_EVENT_ID),
        "provider": first(_PROVIDER),
        "channel": first(_CHANNEL),
        "computer": first(_COMPUTER),
        "data": "; ".join(data)[:240],
    }


def parse_chunk_records(data: bytes) -> Iterator[dict]:
    """Parses each record of a chunk with python-evtx. Records that fail to render are still reported with
    their id and timestamp, so a damaged chunk is visible rather than silently dropped."""
    chunk = evtx_lib.ChunkHeader(data, 0) if HAS_EVTX else None
    for offset, size, record_id, filetime in iter_record_spans(data):
        row = {"offset": offset, "record_id": record_id, "time": filetime_to_datetime(filetime), "xml": None}
        if chunk is not None:
            try:
                row["xml"] = evtx_lib.Record(data, offset, chunk).xml()
            except Exception as excp:  # malformed or partially paged-out record
                vollog.debug(f"record {record_id} at {offset:#x} did not render: {excp}")
        row.update(summarize_xml(row["xml"] or ""))
        yield row


def build_evtx_file(chunks: List[bytes]) -> bytes:
    """Wraps recovered chunks in a fresh EVTX file header, ordered by first record id."""
    infos = sorted((ChunkInfo(c) for c in chunks), key=lambda i: i.first_record_id)
    if not infos:
        raise ValueError("no chunks")
    next_record_id = infos[-1].last_record_id + 1
    header = bytearray(FILE_HEADER_SIZE)
    struct.pack_into(
        "<8sQQQIHHH",
        header,
        0,
        b"ElfFile\x00",
        0,
        len(infos) - 1,
        next_record_id,
        0x80,
        1,
        3,
        FILE_HEADER_SIZE,
    )
    struct.pack_into("<H", header, 0x2A, len(infos))
    struct.pack_into("<I", header, 0x78, 0)  # flags: clean, not full
    struct.pack_into("<I", header, 0x7C, zlib.crc32(bytes(header[:0x78])) & 0xFFFFFFFF)
    return bytes(header) + b"".join(i.data for i in infos)


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class EvtxScan(interfaces.plugins.PluginInterface):
    """Recovers Windows event log (EVTX) chunks and records from process or physical memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]
            ),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(3, 0, 0)),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to scan (default: svchost.exe processes hosting the EventLog service)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="physical",
                description="Also scan physical memory, which finds chunks of cleared or deleted logs",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="all-chunks",
                description="List every chunk copy instead of collapsing duplicates",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="records",
                description="List individual records instead of chunks",
                default=True,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Write recovered chunks as one .evtx file per channel",
                default=False,
                optional=True,
            ),
        ]

    # -- discovery --

    def _eventlog_processes(self) -> List[interfaces.objects.ObjectInterface]:
        pids = self.config.get("pid")
        procs = list(
            pslist.PsList.list_processes(
                context=self.context,
                kernel_module_name=self.config["kernel"],
                filter_func=pslist.PsList.create_pid_filter(pids),
            )
        )
        if pids:
            return procs
        selected = []
        for proc in procs:
            name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
            if name.lower() != "svchost.exe":
                continue
            try:
                peb = proc.get_peb()
                cmdline = peb.ProcessParameters.CommandLine.get_string()
            except exceptions.InvalidAddressException:
                cmdline = ""
            # The EventLog service runs in this group on Vista through Windows 10; on Windows 11 it may get
            # its own svchost (-s EventLog). Unreadable command lines are scanned too rather than missed.
            if not cmdline or "LocalServiceNetworkRestricted" in cmdline or "EventLog" in cmdline:
                selected.append(proc)
        return selected

    def _scan_layer(self, layer_name: str, sections: Optional[List[Tuple[int, int]]]) -> Iterator[Tuple[int, bytes]]:
        layer = self.context.layers[layer_name]
        kwargs = {"sections": sections} if sections else {}
        for offset in layer.scan(
            context=self.context,
            scanner=scanners.BytesScanner(CHUNK_MAGIC),
            progress_callback=self._progress_callback,
            **kwargs,
        ):
            yield offset, layer.read(offset, CHUNK_SIZE, pad=True)

    def _chunks(self) -> Iterator[Tuple[str, int, ChunkInfo]]:
        for proc in self._eventlog_processes():
            pid = int(proc.UniqueProcessId)
            try:
                layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue
            sections = [(vad.get_start(), vad.get_size()) for vad in proc.get_vad_root().traverse() if vad.get_size()]
            for offset, data in self._scan_layer(layer_name, sections):
                info = ChunkInfo(data)
                if info.plausible:
                    yield f"PID {pid}", offset, info
        if self.config.get("physical"):
            kernel = self.context.modules[self.config["kernel"]]
            phys = self.context.layers[kernel.layer_name].config["memory_layer"]
            for offset, data in self._scan_layer(phys, None):
                info = ChunkInfo(data)
                if info.plausible:
                    yield "physical", offset, info

    # -- output --

    def _generator(self):
        if not HAS_EVTX:
            vollog.warning("python-evtx is not installed (pip install python-evtx); records will show ids and times only")

        # Collapse identical chunk copies (the same chunk is often mapped and cached several times), keeping a
        # copy whose data checksum verifies when there is one.
        copies: List[Tuple[str, int, ChunkInfo]] = list(self._chunks())
        best: Dict[Tuple[int, int, int], Tuple[str, int, ChunkInfo]] = {}
        for item in copies:
            k = item[2].key()
            if k not in best or (item[2].data_ok and not best[k][2].data_ok) or (
                item[0] != "physical" and best[k][0] == "physical"
            ):
                best[k] = item
        chunks = copies if self.config.get("all-chunks") else list(best.values())

        parsed = [(src, off, info, list(parse_chunk_records(info.data))) for src, off, info in chunks]

        # The lowest record id the EventLog service has mapped for each channel. A record that turns up only in
        # physical memory below it comes from a part of the log the service no longer holds (the file cache, an
        # older generation of the log, or a cleared log); a channel with no mapped chunks at all is flagged too.
        live_min: Dict[str, int] = {}
        for src, _, _, rows in parsed:
            if src == "physical":
                continue
            for r in rows:
                if r["channel"]:
                    live_min[r["channel"]] = min(live_min.get(r["channel"], r["record_id"]), r["record_id"])
        seen_records = set()

        for src, offset, info, rows in parsed:
            if not self.config.get("records"):
                yield 0, (
                    src, format_hints.Hex(offset), info.first_record_id, info.last_record_id,
                    info.header_ok, info.data_ok, renderers.NotApplicableValue(), renderers.NotApplicableValue(),
                    renderers.NotApplicableValue(), "", "", "",
                )
                continue
            for row in rows:
                rec_key = (row["channel"], row["record_id"], row["time"])
                if row["channel"] and rec_key in seen_records and not self.config.get("all-chunks"):
                    continue
                seen_records.add(rec_key)
                note = ""
                if src == "physical":
                    lm = live_min.get(row["channel"])
                    if lm is None and row["channel"]:
                        note = "channel not mapped"
                    elif lm is not None and row["record_id"] < lm:
                        note = "older than mapped chunks"
                if row["event_id"] in CLEAR_EVENTS.get(row["channel"], ()):
                    note = (note + "; " if note else "") + "log cleared"
                yield 0, (
                    src,
                    format_hints.Hex(offset + row["offset"]),
                    row["record_id"],
                    row["record_id"],
                    info.header_ok,
                    info.data_ok,
                    row["time"] or renderers.UnparsableValue(),
                    int(row["event_id"]) if row["event_id"] else renderers.UnparsableValue(),
                    row["channel"] or renderers.UnparsableValue(),
                    row["provider"],
                    note,
                    row["data"],
                )
        if self.config.get("dump"):
            self._dump(info for _, _, info, _ in parsed)

    def _dump(self, infos: Iterable[ChunkInfo]):
        """Writes verified chunks as .evtx files. Event Viewer stops reading a file at the first chunk whose
        checksums fail and expects record ranges to ascend, so damaged chunks are left out (they are still
        listed in the plugin output) and overlapping ranges from different log generations go to separate
        files."""
        by_channel: Dict[str, List[ChunkInfo]] = {}
        skipped = 0
        for info in infos:
            if not (info.header_ok and info.data_ok):
                skipped += 1
                continue
            channel = next((r["channel"] for r in parse_chunk_records(info.data) if r["channel"]), "unknown")
            by_channel.setdefault(channel, []).append(info)
        for channel, chunks in by_channel.items():
            generations: List[List[ChunkInfo]] = []
            for info in sorted(chunks, key=lambda i: (i.first_record_id, i.last_record_id)):
                for gen in generations:
                    if info.first_record_id > gen[-1].last_record_id:
                        gen.append(info)
                        break
                else:
                    generations.append([info])
            base = "recovered-" + re.sub(r"[^A-Za-z0-9._-]+", "_", channel)
            for n, gen in enumerate(generations):
                name = base + (f".gen{n + 1}" if n else "") + ".evtx"
                with self.open(name) as fh:
                    fh.write(build_evtx_file([i.data for i in gen]))
                vollog.info(f"wrote {name} ({len(gen)} chunks)")
        if skipped:
            vollog.info(f"{skipped} chunks with failed checksums were not written")

    def run(self):
        return renderers.TreeGrid(
            [
                ("Source", str),
                ("Offset", format_hints.Hex),
                ("FirstRecord", int),
                ("LastRecord", int),
                ("HeaderCRC", bool),
                ("DataCRC", bool),
                ("TimeCreated", datetime.datetime),
                ("EventID", int),
                ("Channel", str),
                ("Provider", str),
                ("Note", str),
                ("Data", str),
            ],
            self._generator(),
        )
