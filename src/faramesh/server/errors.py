# src/faramesh/server/errors.py
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional

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
        """
        Action not found error with helpful suggestions.
        """
        # Truncate ID for display if it's a full UUID
        display_id = action_id[:8] + "..." if len(action_id) > 8 else action_id
        detail = (
            f"Action '{display_id}' not found. "
            f"Check that the action ID is correct. "
            f"Use the /v1/actions endpoint to list all actions."
        )
        
        super().__init__(
            ErrorCode.ACTION_NOT_FOUND,
            detail,
            status_code=status.HTTP_404_NOT_FOUND,
            extra={"action_id": action_id},
        )


class ActionNotExecutableError(APIException):
    def __init__(self, action_id: str, current_status: str):
        """
        Action cannot be executed in its current status.
        
        Provides clear explanation of why action cannot be executed and what status is required.
        """
        # Provide clear, actionable error message
        status_explanations = {
            "pending_approval": "Action requires human approval before execution. Use the /approval endpoint to approve or deny.",
            "denied": "Action was denied and cannot be executed.",
            "failed": "Action has already failed and cannot be re-executed. Use /replay to create a new action.",
            "succeeded": "Action has already completed successfully.",
            "executing": "Action is currently executing. Wait for it to complete.",
            "timeout": "Action timed out and cannot be re-executed. Use /replay to create a new action.",
        }
        
        explanation = status_explanations.get(
            current_status,
            f"Action is in '{current_status}' status and cannot be executed. "
            f"Actions can only be executed when status is 'allowed' or 'approved'."
        )
        
        detail = f"Action {action_id[:8]}... cannot be executed: {explanation}"
        
        super().__init__(
            ErrorCode.ACTION_NOT_EXECUTABLE,
            detail,
            status_code=status.HTTP_400_BAD_REQUEST,
            extra={"action_id": action_id, "status": current_status},
        )


class UnauthorizedError(APIException):
    def __init__(self, detail: str = "Missing or invalid authentication"):
        """
        Authentication/authorization error with clear guidance.
        """
        if not detail or detail == "Missing or invalid authentication":
            detail = (
                "Authentication required. "
                "Include a valid Authorization header: 'Authorization: Bearer <token>'. "
                "Contact your administrator for an API token."
            )
        
        super().__init__(
            ErrorCode.UNAUTHORIZED,
            detail,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class ValidationError(APIException):
    def __init__(self, detail: str, field: Optional[str] = None):
        """
        Create a validation error with clear, actionable message.
        
        Args:
            detail: Clear error message explaining what failed and how to fix it
            field: Optional field name that failed validation
        """
        # Ensure error message is clear and actionable
        if not detail:
            detail = "Validation failed. Please check your input and try again."
        elif not detail.endswith('.'):
            detail = detail + "."
        
        # Add helpful guidance if not already present
        helpful_indicators = ['check', 'please', 'use', 'contact', 'refresh', 'try', 'fix', 'correct']
        if not any(word in detail.lower() for word in helpful_indicators):
            if field:
                detail = f"{detail} Please check the '{field}' field and ensure it meets the requirements."
            else:
                detail = f"{detail} Please check your input and try again."
        
        extra = {"field": field} if field else {}
        super().__init__(
            ErrorCode.VALIDATION_ERROR,
            detail,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            extra=extra,
        )
