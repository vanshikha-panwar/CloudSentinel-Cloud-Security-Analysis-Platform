"""
Scan routes. Handlers stay thin: validation here, scanning in ScanService.
"""

from functools import lru_cache
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from cloudsentinel.api.schemas import IamDataRequest, ScanReport
from cloudsentinel.services.scan_service import ScanService, validate_filters

router = APIRouter(tags=["scans"])


@lru_cache(maxsize=1)
def get_scan_service() -> ScanService:
    """One shared ScanService per process, so rules config is loaded once."""
    return ScanService()


@router.post("/scans", response_model=ScanReport)
def create_scan(
    iam_data: IamDataRequest,
    min_severity: Optional[str] = Query(None, description="Minimum severity: CRITICAL, HIGH, MEDIUM, LOW or INFO"),
    entity_type: Optional[str] = Query(None, description="Entity type: USER, ROLE, GROUP or ACCOUNT"),
    service: ScanService = Depends(get_scan_service),
) -> Dict[str, Any]:
    """Scan uploaded IAM data and return the report. No AWS calls are made."""
    try:
        validate_filters(min_severity, entity_type)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return service.run_scan(iam_data.model_dump(), min_severity=min_severity, entity_type=entity_type)
