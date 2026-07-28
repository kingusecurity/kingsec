from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.license import License, LicenseStatus


class LicenseValidator(ABC):

    @abstractmethod
    def validate(self, license: License) -> LicenseStatus: ...

    @abstractmethod
    def verify_signature(self, license: License) -> bool: ...

    @abstractmethod
    def check_expiration(self, license: License) -> LicenseStatus: ...

    @abstractmethod
    def has_feature(self, license: License, feature: str) -> bool: ...

    @abstractmethod
    def detect_clock_rollback(self, license: License) -> bool: ...

    @abstractmethod
    def compute_signature(self, license: License) -> str: ...
