from __future__ import annotations

from kingsec.infrastructure.backup.compression import ZipCompressionService


class TestZipCompressionService:
    def test_compress_decompress(self) -> None:
        svc = ZipCompressionService()
        original = b"hello world " * 100
        compressed = svc.compress(original)
        assert len(compressed) < len(original)
        decompressed = svc.decompress(compressed)
        assert decompressed == original

    def test_empty_data(self) -> None:
        svc = ZipCompressionService()
        compressed = svc.compress(b"")
        decompressed = svc.decompress(compressed)
        assert decompressed == b""
