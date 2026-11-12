"""Small structural interfaces for host-side services and test doubles."""
from typing import Any, Callable, Protocol


class ScriptHandle(Protocol):
    @property
    def is_destroyed(self) -> bool: ...
    def load(self) -> None: ...
    def unload(self) -> None: ...
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...


class SessionHandle(Protocol):
    def create_script(self, source: str) -> ScriptHandle: ...
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...


class DeviceMetadata(Protocol):
    id: str
    name: str
    type: str
    def query_system_parameters(self) -> dict[str, Any]: ...


class ModuleSource(Protocol):
    path: str
    Name: str
    Code: str


class ModuleCatalog(Protocol):
    staged: list[Any]
    def compile(self) -> str: ...
