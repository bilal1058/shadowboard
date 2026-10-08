"""API Router for Security Audit Reports (JSON, PDF, SARIF)."""

from fastapi import APIRouter, HTTPException, Depends, Response
from typing import Dict, Any, List
import aiosqlite

from app.db.session import get_db
from app.api.endpoints.scans import get_scan_details, export_scan_pdf, list_scans
from app.api.endpoints.integrations import export_scan_sarif

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("", response_model=List[Dict[str, Any]])
async def list_reports(db: aiosqlite.Connection = Depends(get_db)):
    """List historical audit reports across completed scans."""
    return await list_scans(db)


@router.get("/{scan_id}", response_model=Dict[str, Any])
async def get_report(scan_id: int, db: aiosqlite.Connection = Depends(get_db)):
    """Retrieve full security audit report for a given scan."""
    return await get_scan_details(scan_id, db)


@router.get("/scan/{scan_id}", response_model=Dict[str, Any])
async def get_scan_report(scan_id: int, db: aiosqlite.Connection = Depends(get_db)):
    """Alias for /reports/{scan_id}."""
    return await get_scan_details(scan_id, db)


@router.get("/{scan_id}/pdf")
async def get_report_pdf(scan_id: int, db: aiosqlite.Connection = Depends(get_db)):
    """Download boardroom-ready PDF security audit report."""
    return await export_scan_pdf(scan_id, db)


@router.get("/{scan_id}/sarif")
async def get_report_sarif(scan_id: int, db: aiosqlite.Connection = Depends(get_db)):
    """Download OASIS SARIF 2.1.0 document for GitHub Code Scanning."""
    return await export_scan_sarif(scan_id, db)
