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
    http_status = 500