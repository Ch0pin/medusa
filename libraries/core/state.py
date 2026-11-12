"""Instance-owned state with legacy attribute adapters at the CLI boundary."""
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar, overload

from libraries.core.contracts import DeviceMetadata, ScriptHandle
from libraries.core.modules import ModuleManager


@dataclass
class DeviceState:
    connection: DeviceMetadata | None = None
    identity: str | None = None
    controller: Any = None
    packages: list[Any] = field(default_factory=list)
    package_range: str = ''
    # iOS uses Frida application objects where Android uses dictionaries.
    app_info: Any = field(default_factory=dict)
    system_libraries: list[Any] = field(default_factory=list)
    app_libraries: list[Any] = field(default_factory=list)


@dataclass
class SessionState:
    script: ScriptHandle | None = None
    pid: int | str | None = None
    detached: bool = True
    current_package: str | None = None
    native_handler: Any = None
    native_functions: list[Any] = field(default_factory=list)
    libname: str | None = None
    agent_script_path: str | None = None
    # Only files exclusively created by this CLI instance are registered here.
    # None means the user has not yet made a keep/discard decision.
    agent_files: dict[str, bool | None] = field(default_factory=dict)


@dataclass
class ApplicationState:
    device: DeviceState = field(default_factory=DeviceState)
    session: SessionState = field(default_factory=SessionState)
    modules: ModuleManager = field(default_factory=ModuleManager)
    snippets: list[str] = field(default_factory=list)
    modified: bool = False


T = TypeVar('T')


class StateAttribute(Generic[T]):
    """Forward an established parser attribute to its one authoritative owner."""
    def __init__(self, *path: str):
        self.path = path

    @overload
    def __get__(self, instance: None, owner: type | None = None) -> 'StateAttribute[T]': ...

    @overload
    def __get__(self, instance: Any, owner: type | None = None) -> T: ...

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        value = instance.state
        for name in self.path:
            value = getattr(value, name)
        return value

    def __set__(self, instance: Any, value: T) -> None:
        target = instance.state
        for name in self.path[:-1]:
            target = getattr(target, name)
        setattr(target, self.path[-1], value)
