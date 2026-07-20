import asyncio
import logging
import time
from typing import List

from app.models.enums import ScanMode, Status
from app.models.scan_request import ScanRequest
from app.models.scan_result import ScanResult
from app.scanners.scan_module import ScanModule

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Coordinates the execution of scan modules.
    
    The orchestrator runs scan modules concurrently, collects results,
    and handles errors without stopping the entire scan when individual
    modules fail.
    """
    
    def __init__(self, modules: List[ScanModule]):
        """
        Initialize the orchestrator with available scan modules.
        
        Args:
            modules: List of ScanModule instances to coordinate
        """
        self.modules = {module.__class__.__name__: module for module in modules}
        logger.info(f"ScanOrchestrator initialized with {len(self.modules)} modules")
    
    async def execute_scan(self, scan_request: ScanRequest) -> List[ScanResult]:
        """
        Execute scan for the given request.
        
        Args:
            scan_request: The scan request containing target and configuration
            
        Returns:
            List of ScanResult objects from completed modules
        """
        logger.info(f"Starting scan for target: {scan_request.target.normalized_target}")
        logger.info(f"Scan mode: {scan_request.scan_mode}")
        
        # Determine which modules to run
        modules_to_run = self._get_modules_to_run(scan_request)
        logger.info(f"Executing {len(modules_to_run)} modules: {list(modules_to_run.keys())}")
        
        # Execute modules concurrently
        results = await self._run_modules_concurrently(modules_to_run, scan_request.target)
        
        logger.info(f"Scan completed. {len(results)} results collected")
        return results
    
    def _get_modules_to_run(self, scan_request: ScanRequest) -> dict:
        """
        Determine which modules should run based on scan mode.
        
        Args:
            scan_request: The scan request containing mode and enabled modules
            
        Returns:
            Dictionary of module_name -> ScanModule to execute
        """
        if scan_request.scan_mode == ScanMode.FULL:
            # Run all available modules
            return self.modules.copy()
        elif scan_request.scan_mode == ScanMode.CUSTOM:
            # Run only enabled modules
            enabled_modules = {}
            for module_name in scan_request.enabled_modules:
                if module_name in self.modules:
                    enabled_modules[module_name] = self.modules[module_name]
                else:
                    logger.warning(f"Module '{module_name}' not found in available modules")
            return enabled_modules
        else:
            logger.error(f"Unknown scan mode: {scan_request.scan_mode}")
            return {}
    
    async def _run_modules_concurrently(
        self, 
        modules: dict, 
        target
    ) -> List[ScanResult]:
        """
        Run scan modules concurrently using asyncio.gather.
        
        Args:
            modules: Dictionary of module_name -> ScanModule to execute
            target: The target to scan
            
        Returns:
            List of ScanResult objects from successfully completed modules
        """
        if not modules:
            logger.warning("No modules to execute")
            return []
        
        # Create tasks for all modules
        tasks = []
        for module_name, module in modules.items():
            task = self._run_single_module(module, target)
            tasks.append(task)
        
        # Run all tasks concurrently, collecting exceptions instead of raising
        results_with_exceptions = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Separate successful results from exceptions
        successful_results = []
        for i, result in enumerate(results_with_exceptions):
            if isinstance(result, Exception):
                module_name = list(modules.keys())[i]
                logger.error(f"Module '{module_name}' failed: {str(result)}")
            elif isinstance(result, ScanResult):
                successful_results.append(result)
            else:
                logger.warning(f"Unexpected result type from module: {type(result)}")
        
        return successful_results
    
    async def _run_single_module(self, module: ScanModule, target) -> ScanResult:
        """
        Execute a single scan module with timing and logging.
        
        Args:
            module: The ScanModule instance to execute
            target: The target to scan
            
        Returns:
            ScanResult from the module
            
        Raises:
            Exception: If the module execution fails
        """
        module_name = module.__class__.__name__
        logger.info(f"Starting module: {module_name}")
        
        start_time = time.time()
        try:
            result = await module.scan(target)
            elapsed = time.time() - start_time
            logger.info(f"Completed module: {module_name} in {elapsed:.2f}s (status: {result.status})")
            return result
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Module {module_name} failed after {elapsed:.2f}s: {str(e)}")
            # Return a failed result instead of raising
            return ScanResult(
                module_name=module_name,
                status=Status.FAILED,
                execution_time=elapsed,
                findings=[]
            )
