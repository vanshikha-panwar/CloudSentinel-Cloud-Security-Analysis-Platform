"""
Scan routes. Handlers stay thin: validation here, scanning in ScanService,
storage in ScanRepository.
"""

import logging
from functools import lru_cache
from typing import Annotated, Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response

from cloudsentinel.api.schemas import ErrorResponse, IamDataRequest, ScanListResponse, ScanReport, StoredScanReport
from cloudsentinel.db import PersistenceError, ScanRepository, get_db_path
from cloudsentinel.services.scan_service import ScanService, validate_filters

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scans"])

SCAN_ID_PATTERN = r"^scn_[0-9a-f]{32}$"
SCAN_ID_HEADER = "X-Scan-Id"
HISTORY_UNAVAILABLE_DETAIL = "Scan history is unavailable"


@lru_cache(maxsize=1)
def get_scan_service() -> ScanService:
    """One shared ScanService per process, so rules config is loaded once."""
    return ScanService()


@lru_cache(maxsize=1)
def get_scan_repository() -> ScanRepository:
    """One shared repository per process, using CLOUDSENTINEL_DB_PATH."""
    return ScanRepository(get_db_path())


@router.post("/scans", response_model=ScanReport)
def create_scan(
    iam_data: IamDataRequest,
    response: Response,
    min_severity: Optional[str] = Query(None, description="Minimum severity: CRITICAL, HIGH, MEDIUM, LOW or INFO"),
    entity_type: Optional[str] = Query(None, description="Entity type: USER, ROLE, GROUP or ACCOUNT"),
    service: ScanService = Depends(get_scan_service),
    repository: ScanRepository = Depends(get_scan_repository),
) -> Dict[str, Any]:
    """
    Scan uploaded IAM data and return the report. No AWS calls are made.

    The report is also saved to scan history; its ID is returned in the
    X-Scan-Id header. If saving fails, the report is still returned
    (without the header).
    """
    try:
        validate_filters(min_severity, entity_type)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    report = service.run_scan(iam_data.model_dump(), min_severity=min_severity, entity_type=entity_type)

    try:
        response.headers[SCAN_ID_HEADER] = repository.save_scan(report)
    except PersistenceError as exc:
        logger.error("Scan report not saved to history: %s", exc)

    return report


@router.get(
    "/scans",
    response_model=ScanListResponse,
    responses={503: {"model": ErrorResponse, "description": "Scan history database unavailable"}},
)
def list_scans(
    limit: int = Query(20, ge=1, le=100, description="Maximum number of scans to return"),
    offset: int = Query(0, ge=0, description="Number of scans to skip"),
    repository: ScanRepository = Depends(get_scan_repository),
) -> Dict[str, Any]:
    """List stored scans, newest first."""
    try:
        scans = repository.list_scans(limit=limit, offset=offset)
    except PersistenceError as exc:
        logger.error("Could not list scan history: %s", exc)
        raise HTTPException(status_code=503, detail=HISTORY_UNAVAILABLE_DETAIL)
    return {"limit": limit, "offset": offset, "scans": scans}


@router.get(
    "/scans/{scan_id}",
    response_model=StoredScanReport,
    responses={
        404: {"model": ErrorResponse, "description": "Scan not found"},
        503: {"model": ErrorResponse, "description": "Scan history database unavailable"},
    },
)
def get_scan(
    scan_id: Annotated[str, Path(pattern=SCAN_ID_PATTERN, description="scan_id from the X-Scan-Id header")],
    repository: ScanRepository = Depends(get_scan_repository),
) -> Dict[str, Any]:
    """Return a stored scan report with its findings, exactly as originally returned."""
    try:
        stored = repository.get_scan(scan_id)
    except PersistenceError as exc:
        logger.error("Could not read scan history: %s", exc)
        raise HTTPException(status_code=503, detail=HISTORY_UNAVAILABLE_DETAIL)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return stored
