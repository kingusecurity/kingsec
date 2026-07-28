from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.license import License


class LicenseRepository(ABC):

    @abstractmethod
    def save(self, license: License) -> None: ...

    @abstractmethod
    def find_active(self) -> License | None: ...

    @abstractmethod
    def find_by_key(self, license_key: str) -> License | None: ...

    @abstractmethod
    def list_all(self) -> list[License]: ...

    @abstractmethod
    def delete(self, license_id: str) -> None: ...

    @abstractmethod
    def exists(self) -> bool: ...
