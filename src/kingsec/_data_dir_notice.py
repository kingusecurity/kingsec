"""Shared "announce the resolved database path" helper.

Used by all three entrypoints that touch the database - ``kingsec-migrate``,
``kingsec-bootstrap``, and the running server - so an operator never has to
run ``load_settings()`` out-of-band to learn which database a command is
about to act on.

Before this existed, a silent fallback to the default data directory
(``Path.home() / ".kingsec"``) when ``KINGSEC_STORAGE__DATA_DIR`` was unset
produced a real, previously-unidentified incident: a command appeared to
succeed while silently acting on a different, unintended database. See
docs/STATUS.md for the record of that incident.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from kingsec.infrastructure.config import Settings

DATA_DIR_ENV_VAR = "KINGSEC_STORAGE__DATA_DIR"


def announce_data_dir(settings: Settings, *, stream: TextIO | None = None) -> None:
    """Print the resolved data directory before any database action.

    If ``KINGSEC_STORAGE__DATA_DIR`` was not set, this says so explicitly -
    a silent default is what caused the incident; an announced default is
    fine.
    """
    stream = stream if stream is not None else sys.stderr
    data_dir = settings.storage.data_dir
    if DATA_DIR_ENV_VAR in os.environ:
        print(f"Using database directory: {data_dir}", file=stream)
    else:
        print(
            f"NOTICE: {DATA_DIR_ENV_VAR} is not set - using the default "
            f"database directory: {data_dir}",
            file=stream,
        )
