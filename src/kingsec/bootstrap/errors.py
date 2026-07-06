"""Bootstrap-specific errors.

We subclass Module 2.3's ``KingSecError`` here rather than adding a new class to
2.3 itself. That keeps 2.3 untouched while proving the design intent: any
package can extend the hierarchy with its own unique code. ``KS-BOOT-001`` is
registered in the global code registry automatically at import.
"""

from __future__ import annotations

from kingsec.shared.errors import KingSecError


class BootstrapError(KingSecError):
    """The application failed to compose or manage its lifecycle correctly.

    Raised for composition-time problems (a missing dependency registration, an
    un-creatable data directory, lifecycle misuse). These are operator/developer
    errors, so the internal ``message`` is specific while the user-facing message
    stays generic.
    """

    code = "KS-BOOT-001"
    default_user_message = "The application failed to start correctly."
