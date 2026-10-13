"""Кастомные исключения для taptuna. Всегда конвертируются в JSON-ответ."""

from __future__ import annotations


class ProtocolLabError(Exception):
    """Базовая ошибка приложения. Всегда конвертируется в JSON-ответ."""
    http_status = 400

    def __init__(self, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        return {"error": {"code": self.code, "message": self.message, "details": self.details}}


class TsharkNotFoundError(ProtocolLabError):
    """tshark не найден или не запускается."""
    http_status = 500


class ProjectAlreadyExistsError(ProtocolLabError):
    """Попытка повторного init существующего проекта."""
    http_status = 409


class ProjectNotFoundError(ProtocolLabError):
    """Проект не найден."""
    http_status = 404


class CaptureNotFoundError(ProtocolLabError):
    """Запись (capture) не найдена."""
    http_status = 404


class ValidationError(ProtocolLabError):
    """Ошибка валидации входных данных."""
    http_status = 400


class NotImplementedYetError(ProtocolLabError):
    """Функциональность не реализована на этом этапе."""
    http_status = 501