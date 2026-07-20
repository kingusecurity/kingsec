from __future__ import annotations

import gzip

from kingsec.application.ports.outbound import BackupCompressionPort


class ZipCompressionService(BackupCompressionPort):
    def compress(self, data: bytes) -> bytes:
        return gzip.compress(data)

    def decompress(self, data: bytes) -> bytes:
        return gzip.decompress(data)
