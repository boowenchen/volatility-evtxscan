"""Tests for the format helpers in evtxscan. The fixture is one verified chunk (the Known Folders API
Service log, 49 records) recovered from the public MemLabs Lab 1 memory image."""
import importlib.util
import struct
import zlib
from pathlib import Path

import Evtx.Evtx as evtx_lib
import pytest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("evtxscan", HERE.parent / "plugins" / "windows" / "evtxscan.py")
evtxscan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evtxscan)

CHUNK = (HERE / "fixtures" / "knownfolders-chunk.bin").read_bytes()


def test_fixture_checksums_verify():
    info = evtxscan.ChunkInfo(CHUNK)
    assert info.header_ok and info.data_ok and info.plausible
    assert (info.first_record_id, info.last_record_id) == (1, 49)


def test_all_records_parse_with_fields():
    rows = list(evtxscan.parse_chunk_records(CHUNK))
    assert [r["record_id"] for r in rows] == list(range(1, 50))
    assert all(r["event_id"] == "1002" for r in rows)
    assert all(r["channel"] == "Microsoft-Windows-Known Folders API Service" for r in rows)
    assert rows[0]["time"].isoformat().startswith("2019-12-05T02:45:19")
    assert "FolderId=" in rows[0]["data"]


def test_flipped_byte_fails_data_checksum_only():
    bad = bytearray(CHUNK)
    bad[0x300] ^= 0xFF
    info = evtxscan.ChunkInfo(bytes(bad))
    assert info.header_ok and not info.data_ok


def test_flipped_header_byte_fails_header_checksum():
    bad = bytearray(CHUNK)
    bad[0x20] ^= 0x01  # last record id
    assert not evtxscan.ChunkInfo(bytes(bad)).header_ok


def test_records_after_a_missing_page_are_still_found():
    damaged = bytearray(CHUNK)
    damaged[0x1000:0x2000] = b"\x00" * 0x1000  # a paged-out 4 KiB page
    spans = list(evtxscan.iter_record_spans(bytes(damaged)))
    ids = [s[2] for s in spans]
    full_ids = [s[2] for s in evtxscan.iter_record_spans(CHUNK)]
    lost = set(full_ids) - set(ids)
    assert lost, "zeroing a page must remove the records it held"
    assert len(lost) <= 10
    assert max(ids) == 49, "records after the hole are recovered"


def test_record_size_must_repeat_at_end():
    tampered = bytearray(CHUNK)
    off, size, _, _ = next(evtxscan.iter_record_spans(CHUNK))
    struct.pack_into("<I", tampered, off + size - 4, size + 8)
    ids = [s[2] for s in evtxscan.iter_record_spans(bytes(tampered))]
    assert 1 not in ids and 2 in ids


def test_built_file_reads_back_with_python_evtx():
    data = evtxscan.build_evtx_file([CHUNK])
    assert data[:8] == b"ElfFile\x00"
    assert struct.unpack_from("<I", data, 0x7C)[0] == zlib.crc32(data[:0x78]) & 0xFFFFFFFF
    fh = evtx_lib.FileHeader(data, 0)
    assert fh.verify()
    records = [r for c in fh.chunks() for r in c.records()]
    assert len(records) == 49


def test_built_file_orders_chunks_and_sets_next_record():
    second = bytearray(CHUNK)
    # A second chunk with a later id range; only the header fields matter for ordering.
    struct.pack_into("<QQ", second, 0x18, 50, 98)
    struct.pack_into("<I", second, 0x7C, zlib.crc32(bytes(second[:0x78] + second[0x80:0x200])) & 0xFFFFFFFF)
    data = evtxscan.build_evtx_file([bytes(second), CHUNK])
    assert data[0x1000 + 0x18 : 0x1000 + 0x20] == struct.pack("<Q", 1)
    assert struct.unpack_from("<Q", data, 0x18)[0] == 99
    assert struct.unpack_from("<H", data, 0x2A)[0] == 2


def test_build_rejects_empty():
    with pytest.raises(ValueError):
        evtxscan.build_evtx_file([])


def test_summarize_xml():
    xml = (
        '<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>1102</EventID>'
        "<Channel>Security</Channel><Computer>PC</Computer></System>"
        '<EventData><Data Name="SubjectUserName">alice</Data><Data>x</Data></EventData></Event>'
    )
    s = evtxscan.summarize_xml(xml)
    assert s == {
        "event_id": "1102",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "PC",
        "data": "SubjectUserName=alice; x",
    }
    assert "1102" in evtxscan.CLEAR_EVENTS["Security"]
