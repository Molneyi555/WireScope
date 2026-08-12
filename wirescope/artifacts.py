from __future__ import annotations

import errno
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator, Optional, TextIO, Union


PathLike = Union[str, os.PathLike]
PRIVATE_FILE_MODE = 0o600


class ArtifactSecurityError(OSError):
    """Raised when an output path cannot satisfy the private-artifact policy."""


def _path(value: PathLike) -> Path:
    return Path(value)


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _inspect_destination(path: Path, allow_missing: bool = True) -> Optional[os.stat_result]:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise
    if stat.S_ISLNK(info.st_mode):
        raise ArtifactSecurityError(errno.ELOOP, f"refusing symlink artifact destination: {path}", str(path))
    if not stat.S_ISREG(info.st_mode):
        raise ArtifactSecurityError(errno.EINVAL, f"artifact destination is not a regular file: {path}", str(path))
    return info


def _secure_open(path: Path, *, append: bool) -> int:
    _ensure_parent(path)
    _inspect_destination(path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ArtifactSecurityError(errno.ENOTSUP, "this platform cannot refuse artifact symlinks safely", str(path))
    flags = os.O_WRONLY | os.O_CREAT | nofollow | getattr(os, "O_CLOEXEC", 0)
    flags |= os.O_APPEND if append else os.O_TRUNC
    try:
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise ArtifactSecurityError(errno.ELOOP, f"refusing symlink artifact destination: {path}", str(path)) from exc
        raise
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ArtifactSecurityError(errno.EINVAL, f"artifact destination is not a regular file: {path}", str(path))
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != PRIVATE_FILE_MODE:
            raise ArtifactSecurityError(errno.EACCES, f"artifact permissions are not owner-only: {path}", str(path))
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


@contextmanager
def private_text_stream(
    destination: PathLike,
    *,
    append: bool = False,
    encoding: str = "utf-8",
    newline: Optional[str] = None,
) -> Iterator[TextIO]:
    """Open a private regular text artifact for truncating writes or append."""

    path = _path(destination)
    descriptor = _secure_open(path, append=append)
    try:
        stream = os.fdopen(descriptor, "a" if append else "w", encoding=encoding, newline=newline)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    try:
        yield stream
    finally:
        stream.close()


@contextmanager
def private_binary_stream(destination: PathLike, *, append: bool = False) -> Iterator[BinaryIO]:
    """Open a private regular binary artifact for truncating writes or append."""

    path = _path(destination)
    descriptor = _secure_open(path, append=append)
    try:
        stream = os.fdopen(descriptor, "ab" if append else "wb")
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    try:
        yield stream
    finally:
        stream.close()


def _temporary_artifact(destination: Path) -> tuple[int, Path]:
    _ensure_parent(destination)
    descriptor, raw_path = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent))
    temporary = Path(raw_path)
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE:
            raise ArtifactSecurityError(errno.EACCES, f"temporary artifact is not private: {temporary}", str(temporary))
        return descriptor, temporary
    except Exception:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _sync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


@contextmanager
def atomic_text_writer(
    destination: PathLike,
    *,
    encoding: str = "utf-8",
    newline: Optional[str] = None,
) -> Iterator[TextIO]:
    """Build a private text artifact and atomically replace its destination."""

    path = _path(destination)
    _inspect_destination(path)
    descriptor, temporary = _temporary_artifact(path)
    try:
        stream = os.fdopen(descriptor, "w", encoding=encoding, newline=newline)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
    replaced = False
    try:
        yield stream
        stream.flush()
        os.fsync(stream.fileno())
        stream.close()
        _inspect_destination(path)
        os.replace(temporary, path)
        replaced = True
        verify_private_artifact(path)
        _sync_directory(path.parent)
    finally:
        if not stream.closed:
            stream.close()
        if not replaced:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


@contextmanager
def atomic_binary_writer(destination: PathLike) -> Iterator[BinaryIO]:
    """Build a private binary artifact and atomically replace its destination."""

    path = _path(destination)
    _inspect_destination(path)
    descriptor, temporary = _temporary_artifact(path)
    try:
        stream = os.fdopen(descriptor, "wb")
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
    replaced = False
    try:
        yield stream
        stream.flush()
        os.fsync(stream.fileno())
        stream.close()
        _inspect_destination(path)
        os.replace(temporary, path)
        replaced = True
        verify_private_artifact(path)
        _sync_directory(path.parent)
    finally:
        if not stream.closed:
            stream.close()
        if not replaced:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def atomic_write_text(destination: PathLike, data: str, *, encoding: str = "utf-8") -> None:
    with atomic_text_writer(destination, encoding=encoding) as stream:
        stream.write(data)


def atomic_write_bytes(destination: PathLike, data: bytes) -> None:
    with atomic_binary_writer(destination) as stream:
        stream.write(data)


def verify_private_artifact(destination: PathLike, *, repair_mode: bool = True) -> Path:
    """Verify a regular non-symlink artifact and, by default, enforce mode 0600."""

    path = _path(destination)
    _inspect_destination(path, allow_missing=False)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ArtifactSecurityError(errno.ENOTSUP, "this platform cannot refuse artifact symlinks safely", str(path))
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise ArtifactSecurityError(errno.ELOOP, f"refusing symlink artifact destination: {path}", str(path)) from exc
        raise
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ArtifactSecurityError(errno.EINVAL, f"artifact destination is not a regular file: {path}", str(path))
        if repair_mode:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
        mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
        if mode != PRIVATE_FILE_MODE:
            raise ArtifactSecurityError(errno.EACCES, f"artifact permissions are {mode:#o}, expected 0o600: {path}", str(path))
    finally:
        os.close(descriptor)
    return path


@contextmanager
def external_artifact(destination: PathLike) -> Iterator[Path]:
    """Prepare and post-verify a private path written by an external process."""

    path = _path(destination)
    with private_binary_stream(path):
        pass
    try:
        yield path
    finally:
        verify_private_artifact(path, repair_mode=True)
