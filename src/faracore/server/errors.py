# src/faracore/server/errors.py
from __future__ import annotations

from enum import Enum
from typing import Optional, Dict, Any
from fastapi import HTTPException, status


class ErrorCode(str, Enum):
    """Standard error codes for the API."""
    # Action errors
    ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
    ACTION_NOT_EXECUTABLE = "ACTION_NOT_EXECUTABLE"
    ACTION_REQUIRES_APPROVAL = "ACTION_REQUIRES_APPROVAL"
    
    # Authentication errors
    UNAUTHORIZED = "UNAUTHORIZED"
    
    # Validation errors
    VALIDATION_ERROR = "VALIDATION_ERROR"
    
    # System errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class APIException(HTTPException):
    """Custom API exception with error codes."""
    
    def __init__(
        self,
        error_code: ErrorCode,
        detail: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        extra: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.error_code = error_code
        self.extra = extra or {}


# Convenience exception classes
class ActionNotFoundError(APIException):
    def __init__(self, action_id: str):
        super().__init__(
            ErrorCode.ACTION_NOT_FOUND,
            f"Action not found: {action_id}",
            status_code=status.HTTP_404_NOT_FOUND,
            extra={"action_id": action_id},
        )


class ActionNotExecutableError(APIException):
    def __init__(self, action_id: str, current_status: str):
        super().__init__(
            ErrorCode.ACTION_NOT_EXECUTABLE,
            f"Action is not executable in status: {current_status}",
            status_code=status.HTTP_400_BAD_REQUEST,
            extra={"action_id": action_id, "status": current_status},
        )


class UnauthorizedError(APIException):
    def __init__(self, detail: str = "Missing or invalid authentication"):
        super().__init__(
            ErrorCode.UNAUTHORIZED,
            detail,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class ValidationError(APIException):
    def __init__(self, detail: str, field: Optional[str] = None):
        extra = {"field": field} if field else {}
        super().__init__(
            ErrorCode.VALIDATION_ERROR,
            detail,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            extra=extra,
        )
