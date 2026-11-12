"""Cleanup of explicitly owned agent files; never discover files by glob."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class CleanupResult:
    removed: list[Path] = field(default_factory=list)
    errors: dict[Path, str] = field(default_factory=dict)


def cleanup_agent_files(
    owned: dict[str, bool | None],
    choose_keep: Callable[[Path], bool] | None = None,
) -> CleanupResult:
    result = CleanupResult()
    for filename, keep in list(owned.items()):
        path = Path(filename)
        if keep is True:
            continue
        try:
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if keep is None:
                if info.st_size == 0:
                    keep = False
                elif choose_keep is None:
                    # On an error/interruption, preserve work without opening prompts.
                    continue
                else:
                    keep = choose_keep(path)
                owned[filename] = keep
            if not keep:
                path.unlink(missing_ok=True)
                result.removed.append(path)
        except OSError as exc:
            result.errors[path] = str(exc)
    return result
