import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.scan_routes import router, initialize_dependencies, shutdown_dependencies
from app.scanners.port_scanner import PortScanner
from app.scanners.http_probe import HttpProbe
from app.scanners.security_header_scanner import SecurityHeaderScanner
from app.scanners.http_method_scanner import HTTPMethodScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.technology_detector import TechnologyDetector
from app.scanners.content_discovery import ContentDiscovery


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    # Startup
    logger.info("Starting SentinelScan API...")
    
    # Initialize scan modules
    # Note: ServiceDetection excluded as it requires open_ports from PortScanner results
    modules = [
        PortScanner(start_port=1, end_port=1024, timeout=1.0),
        HttpProbe(timeout=10.0),
        SecurityHeaderScanner(timeout=10.0),
        HTTPMethodScanner(timeout=10.0),
        SSLScanner(timeout=10.0),
        TechnologyDetector(timeout=10.0),
        ContentDiscovery(timeout=10.0),
    ]
    
    # Initialize API dependencies
    initialize_dependencies(modules, output_dir="./reports")
    
    logger.info("SentinelScan API started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down SentinelScan API...")
    shutdown_dependencies()
    logger.info("SentinelScan API shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="SentinelScan API",
    description="Automated web and port auditing system",
    version="1.0.0",
    lifespan=lifespan
)

# Include router
app.include_router(router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "SentinelScan API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}
