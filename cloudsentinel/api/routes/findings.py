"""
Finding routes: AI-assisted explanation of a single scanner finding.
"""

import logging
from functools import lru_cache
from typing import Annotated, Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Path

from cloudsentinel.api.routes.scans import get_scan_service
from cloudsentinel.api.schemas import ErrorResponse, ExplanationResponse, IamDataRequest
from cloudsentinel.llm import (
    LLMError,
    LLMInvalidResponseError,
    LLMNotConfiguredError,
    LLMProviderError,
    LLMTimeoutError,
    LLMUnavailableError,
    build_provider,
)
from cloudsentinel.services.explanation_service import ExplanationService
from cloudsentinel.services.scan_service import ScanService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["findings"])

FINDING_ID_PATTERN = r"^fnd_[0-9a-f]{16}(-\d+)?$"
NOT_CONFIGURED_DETAIL = "AI explanations are not configured"

# Generic client-facing messages; provider details stay in server logs
_ERROR_RESPONSES = (
    (LLMNotConfiguredError, 503, NOT_CONFIGURED_DETAIL),
    (LLMUnavailableError, 503, "AI provider is temporarily unavailable, try again later"),
    (LLMTimeoutError, 504, "AI provider timed out"),
    (LLMInvalidResponseError, 502, "AI provider returned an invalid response"),
    (LLMProviderError, 502, "AI provider request failed"),
)


@lru_cache(maxsize=1)
def get_explanation_service() -> ExplanationService:
    """One ExplanationService per process, configured from environment variables."""
    return ExplanationService(build_provider())


def _http_error(exc: LLMError) -> HTTPException:
    for error_type, status_code, detail in _ERROR_RESPONSES:
        if isinstance(exc, error_type):
            return HTTPException(status_code=status_code, detail=detail)
    return HTTPException(status_code=502, detail="AI provider request failed")


@router.post(
    "/findings/{finding_id}/explain",
    response_model=ExplanationResponse,
    responses={
        404: {"model": ErrorResponse, "description": "Finding not found for the supplied IAM data"},
        502: {"model": ErrorResponse, "description": "AI provider error or invalid AI response"},
        503: {"model": ErrorResponse, "description": "AI not configured or provider unavailable"},
        504: {"model": ErrorResponse, "description": "AI provider timed out"},
    },
)
def explain_finding(
    finding_id: Annotated[str, Path(pattern=FINDING_ID_PATTERN, description="finding_id from POST /scans")],
    iam_data: IamDataRequest,
    scan_service: ScanService = Depends(get_scan_service),
    explanation_service: ExplanationService = Depends(get_explanation_service),
) -> Dict[str, Any]:
    """
    Explain one finding in plain language. The body is the same IAM data sent
    to POST /scans; the finding is re-derived by the scanner, not trusted
    from the client.
    """
    if not explanation_service.is_available:
        raise HTTPException(status_code=503, detail=NOT_CONFIGURED_DETAIL)

    finding = scan_service.find_finding(iam_data.model_dump(), finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found for the supplied IAM data")

    try:
        return explanation_service.explain(finding)
    except LLMError as exc:
        logger.warning("AI explanation failed for %s: %s: %s", finding_id, type(exc).__name__, exc)
        raise _http_error(exc) from None
