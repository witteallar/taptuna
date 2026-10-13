"""Нативное ядро taptuna: диспатчер Rust/Python fallback.

Если PROTOLAB_NATIVE=0 или модуль _native не импортируется — используется Python-заглушка,
которая бросает NotImplementedError на каждый вызов.
"""

from __future__ import annotations

import os
import sys
from typing import Any


# Флаг отключения нативного ядра (как в ТЗ §12.3)
_NATIVE_DISABLED = os.environ.get("PROTOLAB_NATIVE") == "0"

# Попытка импорта Rust-модуля
_native = None
if not _NATIVE_DISABLED:
    try:
        from taptuna import _native as _native_module  # type: ignore
        _native = _native_module
    except ImportError:
        _native = None


class _NativeFallback:
    """Python fallback: выбрасывает NotImplementedError на любом вызове."""

    def __init__(self):
        self._version = "0.1.0-fallback"
        self._native_available = False
        self._native_disabled = _NATIVE_DISABLED

    def __getattr__(self, name: str) -> Any:
        if name == "__version__":
            return self._version
        if name == "is_native_available":
            return lambda: self._native_available
        if name == "get_backend_info":
            return lambda: {
                "native_available": self._native_available,
                "native_disabled": self._native_disabled,
                "version": self._version,
            }
        def _not_implemented(*args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError(
                f"taptuna._native.{name} not implemented in Python fallback. "
                f"Build native module with 'maturin develop' or set PROTOLAB_NATIVE=1."
            )
        return _not_implemented

    def __dir__(self) -> list[str]:
        return ["__version__", "is_native_available", "get_backend_info", "reassembly", "framing", "extract", "safe_eval"]


# Экспортируем либо нативный модуль, либо fallback
if _native is not None:
    # Реэкспорт публичного API из Rust
    __version__ = getattr(_native, "__version__", "0.1.0-native")

    # Реэкспорт функций из нативного модуля
    def is_native_available() -> bool:
        return True

    def get_backend_info() -> dict[str, Any]:
        return {
            "native_available": True,
            "native_disabled": _NATIVE_DISABLED,
            "version": __version__,
        }
else:
    # Используем fallback instance
    _fallback = _NativeFallback()
    __version__ = _fallback._version
    is_native_available = _fallback.is_native_available
    get_backend_info = _fallback.get_backend_info

    # Подменяем модуль на fallback для остальных атрибутов
    sys.modules[__name__] = _fallback  # type: ignore