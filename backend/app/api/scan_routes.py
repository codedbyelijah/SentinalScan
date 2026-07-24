import logging
import re
from datetime import datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from fastapi.responses import Response

from app.api.models import (
    StartScanRequest,
    StartScanResponse,
    ScanStatusResponse,
    ScanResultsResponse,
    ScheduleScanRequest,
    ScheduleScanResponse,
    ScheduleStatusResponse,
    CancelScheduleResponse,
    FindingResponse,
    ScanStatus,
    ScheduleInterval,
    ReportFormat,
)
from app.api.scan_state_manager import ScanStateManager
from app.models.enums import ScanMode
from app.models.scan_request import ScanRequest
from app.models.target import Target
from app.models.scan_result import ScanResult
from app.models.risk_analysis_result import RiskAnalysisResult
from app.services.target_validator import TargetValidator, ValidationError
from app.services.scan_configuration import ScanConfiguration, ScanConfigurationError
from app.orchestrator.scan_orchestrator import ScanOrchestrator
from app.services.result_normalizer import ResultNormalizer, ResultNormalizationError
from app.services.risk_analyzer import RiskAnalyzer, RiskAnalysisError
from app.services.scan_scheduler import ScanScheduler, ScheduleInterval as SchedulerInterval, ScanSchedulerError
from app.reports.report_generator import ReportGenerator, ReportGenerationError
from app.reports.report_export import ReportExport, ReportExportError
from app.scanners.scan_module import ScanModule


logger = logging.getLogger(__name__)

# Global instances (will be initialized on app startup)
scan_state_manager: ScanStateManager | None = None
scan_orchestrator: ScanOrchestrator | None = None
scan_scheduler: ScanScheduler | None = None
scan_configuration: ScanConfiguration | None = None
target_validator: TargetValidator | None = None
result_normalizer: ResultNormalizer | None = None
risk_analyzer: RiskAnalyzer | None = None
report_generator: ReportGenerator | None = None
report_export: ReportExport | None = None
available_modules: list[str] = []


router = APIRouter(prefix="/api", tags=["scans"])


def _sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks.
    
    Removes path separators and other unsafe characters.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        Sanitized filename
    """
    # Remove path separators and other unsafe characters
    sanitized = re.sub(r'[\\/:*?"<>|]', '_', filename)
    # Remove any remaining path components
    sanitized = sanitized.replace('..', '').replace('.', '_')
    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    return sanitized


def initialize_dependencies(
    modules: list[ScanModule],
    output_dir: str = "./reports"
) -> None:
    """
    Initialize global dependencies for the API routes.
    
    This should be called during application startup.
    
    Args:
        modules: List of available scan modules
        output_dir: Directory for report generation
    """
    global scan_state_manager, scan_orchestrator, scan_scheduler
    global scan_configuration, target_validator, result_normalizer, risk_analyzer
    global report_generator, report_export, available_modules
    
    # Initialize services
    target_validator = TargetValidator()
    scan_configuration = ScanConfiguration([m.__class__.__name__ for m in modules])
    scan_orchestrator = ScanOrchestrator(modules)
    scan_scheduler = ScanScheduler(scan_orchestrator)
    scan_state_manager = ScanStateManager()
    result_normalizer = ResultNormalizer()
    risk_analyzer = RiskAnalyzer()
    report_generator = ReportGenerator(output_dir=output_dir)
    report_export = ReportExport(output_dir=output_dir)
    
    available_modules = [m.__class__.__name__ for m in modules]
    
    # Start the scheduler
    scan_scheduler.start()
    
    logger.info("API dependencies initialized")


def shutdown_dependencies() -> None:
    """Shutdown global dependencies."""
    global scan_scheduler
    if scan_scheduler:
        scan_scheduler.shutdown()
    logger.info("API dependencies shutdown")


async def execute_scan_task(scan_id: str, scan_request: ScanRequest) -> None:
    """
    Background task to execute a scan.
    
    Args:
        scan_id: The scan ID
        scan_request: The scan request
    """
    global scan_orchestrator, scan_state_manager, result_normalizer, risk_analyzer
    
    if not scan_state_manager or not scan_orchestrator:
        logger.error(f"Scan {scan_id}: Dependencies not initialized")
        return
    
    try:
        # Update status to running
        await scan_state_manager.update_status(scan_id, ScanStatus.RUNNING)
        
        # Execute scan
        results = await scan_orchestrator.execute_scan(scan_request)
        
        # Normalize results
        try:
            result_normalizer.normalize(results)
        except ResultNormalizationError as e:
            logger.warning(f"Scan {scan_id}: Result normalization failed: {e}")
        
        # Add results to state
        for result in results:
            await scan_state_manager.add_module_result(scan_id, result)
        
        # Analyze risk
        risk_analysis = risk_analyzer.analyze(results)
        await scan_state_manager.set_risk_analysis(scan_id, risk_analysis)
        
        # Update status to completed
        await scan_state_manager.update_status(scan_id, ScanStatus.COMPLETED)
        
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        await scan_state_manager.set_error(scan_id, str(e))


# Endpoints

@router.post("/scan/start", response_model=StartScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(request: StartScanRequest, background_tasks: BackgroundTasks) -> StartScanResponse:
    """
    Start a new scan.
    
    Validates the target, creates a scan request, and executes the scan
    in the background. Returns immediately with a scan ID.
    """
    global target_validator, scan_configuration, scan_orchestrator, scan_state_manager, available_modules
    
    if not all([target_validator, scan_configuration, scan_orchestrator, scan_state_manager]):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API dependencies not initialized"
        )
    
    try:
        # Validate target
        target = target_validator.validate(request.target)
        
        # Prepare scan request
        if request.scan_mode == ScanMode.FULL:
            scan_request = scan_configuration.create_full_scan(target)
        else:
            scan_request = scan_configuration.create_custom_scan(target, request.enabled_modules)
        
        # Create scan state
        total_modules = len(available_modules) if request.scan_mode == ScanMode.FULL else len(request.enabled_modules)
        scan_id = await scan_state_manager.create_scan(request.target, total_modules)
        
        # Execute scan in background
        background_tasks.add_task(execute_scan_task, scan_id, scan_request)
        
        return StartScanResponse(
            scan_id=scan_id,
            status=ScanStatus.PENDING,
            message="Scan started successfully"
        )
        
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target: {e.message}"
        )
    except ScanConfigurationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan configuration: {e.message}"
        )
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start scan"
        )


@router.get("/scan/status/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str) -> ScanStatusResponse:
    """
    Get the status of a scan.
    
    Returns the current status, progress, and timing information.
    """
    global scan_state_manager
    
    if not scan_state_manager:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API dependencies not initialized"
        )
    
    scan_state = await scan_state_manager.get_scan(scan_id)
    
    if not scan_state:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return ScanStatusResponse(
        scan_id=scan_state.scan_id,
        status=scan_state.status,
        target=scan_state.target,
        start_time=scan_state.start_time,
        end_time=scan_state.end_time,
        duration_seconds=scan_state.duration_seconds,
        modules_completed=scan_state.modules_completed,
        total_modules=scan_state.total_modules,
        error=scan_state.error
    )


@router.get("/scan/results/{scan_id}", response_model=ScanResultsResponse)
async def get_scan_results(scan_id: str) -> ScanResultsResponse:
    """
    Get the results of a completed scan.
    
    Returns all findings and risk analysis.
    """
    global scan_state_manager
    
    if not scan_state_manager:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API dependencies not initialized"
        )
    
    scan_state = await scan_state_manager.get_scan(scan_id)
    
    if not scan_state:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan_state.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan not completed. Current status: {scan_state.status.value}"
        )
    
    if not scan_state.risk_analysis:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Risk analysis not available"
        )
    
    # Convert findings to response model
    findings = [
        FindingResponse(
            title=f.title,
            description=f.description,
            severity=f.severity,
            category=f.category.value,
            affected_target=f.affected_target,
            recommendation=f.recommendation
        )
        for result in scan_state.results
        for f in result.findings
    ]
    
    return ScanResultsResponse(
        scan_id=scan_state.scan_id,
        target=scan_state.target,
        overall_risk=scan_state.risk_analysis.overall_risk,
        total_findings=len(findings),
        findings=findings,
        scan_duration=scan_state.duration_seconds or 0.0,
        generated_at=datetime.now()
    )


@router.post("/scan/schedule", response_model=ScheduleScanResponse, status_code=status.HTTP_201_CREATED)
async def schedule_scan(request: ScheduleScanRequest) -> ScheduleScanResponse:
    """
    Schedule a scan for future execution.
    
    Supports one-time and recurring schedules.
    """
    global target_validator, scan_configuration, scan_scheduler
    
    if not all([target_validator, scan_configuration, scan_scheduler]):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API dependencies not initialized"
        )
    
    try:
        # Validate target
        target = target_validator.validate(request.target)
        
        # Prepare scan request
        if request.scan_mode == ScanMode.FULL:
            scan_request = scan_configuration.create_full_scan(target)
        else:
            scan_request = scan_configuration.create_custom_scan(target, request.enabled_modules)
        
        # Schedule scan
        if request.schedule_type == "one_time":
            if not request.run_at:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="run_at is required for one-time schedules"
                )
            job_id = scan_scheduler.schedule_one_time(scan_request, request.run_at)
        elif request.schedule_type == "recurring":
            if not request.interval:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="interval is required for recurring schedules"
                )
            # Convert API interval to scheduler interval
            interval_map = {
                ScheduleInterval.HOURLY: SchedulerInterval.HOURLY,
                ScheduleInterval.DAILY: SchedulerInterval.DAILY,
                ScheduleInterval.WEEKLY: SchedulerInterval.WEEKLY,
                ScheduleInterval.CUSTOM: SchedulerInterval.CUSTOM,
            }
            scheduler_interval = interval_map[request.interval]
            job_id = scan_scheduler.schedule_recurring(
                scan_request,
                scheduler_interval,
                interval_value=request.interval_value
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid schedule_type: {request.schedule_type}"
            )
        
        return ScheduleScanResponse(
            job_id=job_id,
            message="Scan scheduled successfully"
        )
        
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target: {e.message}"
        )
    except ScanConfigurationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan configuration: {e.message}"
        )
    except ScanSchedulerError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException:
        # Re-raise HTTPException (validation errors)
        raise
    except Exception as e:
        logger.error(f"Error scheduling scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to schedule scan"
        )


@router.delete("/scan/schedule/{job_id}", response_model=CancelScheduleResponse)
async def cancel_scheduled_scan(job_id: str) -> CancelScheduleResponse:
    """
    Cancel a scheduled scan.
    
    Removes the job from the scheduler.
    """
    global scan_scheduler
    
    if not scan_scheduler:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API dependencies not initialized"
        )
    
    cancelled = scan_scheduler.cancel_job(job_id)
    
    return CancelScheduleResponse(
        cancelled=cancelled,
        message="Job cancelled" if cancelled else "Job not found"
    )


@router.get("/scan/schedule/status", response_model=ScheduleStatusResponse)
async def get_schedule_status() -> ScheduleStatusResponse:
    """
    Get the status of the scan scheduler.
    
    Returns information about scheduled jobs.
    """
    global scan_scheduler
    
    if not scan_scheduler:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API dependencies not initialized"
        )
    
    status = scan_scheduler.get_status()
    
    return ScheduleStatusResponse(
        running=status['running'],
        job_count=status['job_count'],
        jobs=status['jobs']
    )


@router.get("/report/export")
async def export_report(target_identifier: str, format: ReportFormat) -> Response:
    """
    Export a report for a target.
    
    Returns the report file in the specified format.
    """
    global report_export
    
    if not report_export:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API dependencies not initialized"
        )
    
    try:
        if format == ReportFormat.PDF:
            content = report_export.export_by_target(target_identifier, "pdf")
            media_type = "application/pdf"
            extension = "pdf"
        elif format == ReportFormat.HTML:
            content = report_export.export_by_target(target_identifier, "html")
            media_type = "text/html"
            extension = "html"
        elif format == ReportFormat.JSON:
            content = report_export.export_by_target(target_identifier, "json")
            media_type = "application/json"
            extension = "json"
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported format: {format}"
            )
        
        if content is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found for the specified target"
            )
        
        # Return the file
        safe_filename = _sanitize_filename(target_identifier)
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename={safe_filename}_report.{extension}"
            }
        )
        
    except ReportExportError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error exporting report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export report"
        )
