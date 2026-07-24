import json
from pathlib import Path
from typing import Any


class ReportExportError(Exception):
    """Raised when report export fails."""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class ReportExport:
    """
    Service for exporting generated security assessment reports.
    
    Locates and exports PDF, HTML, and JSON reports from the configured output directory.
    """
    
    def __init__(self, output_dir: str = "./reports"):
        """
        Initialize the report export service.
        
        Args:
            output_dir: Directory where reports are stored
            
        Note:
            If the directory does not exist, the service will gracefully handle
            this by returning empty results from list_reports() and raising
            appropriate errors from export methods.
        """
        self.output_dir = Path(output_dir)
        
        # Validate that if the path exists, it is a directory
        if self.output_dir.exists() and not self.output_dir.is_dir():
            raise ReportExportError(f"Output path is not a directory: {output_dir}")
    
    def export_by_filename(self, filename: str) -> bytes | dict[str, Any]:
        """
        Export a report by exact filename.
        
        Args:
            filename: The exact filename of the report to export
            
        Returns:
            bytes for PDF/HTML reports, dict for JSON reports
            
        Raises:
            ReportExportError: If the file does not exist or cannot be read
        """
        # Validate filename to prevent path traversal attacks
        if not filename or not isinstance(filename, str):
            raise ReportExportError("Filename must be a non-empty string")
        
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ReportExportError("Filename cannot contain path traversal characters")
        
        file_path = self.output_dir / filename
        
        if not file_path.exists():
            raise ReportExportError(f"Report file not found: {filename}")
        
        if not file_path.is_file():
            raise ReportExportError(f"Path is not a file: {filename}")
        
        # Determine format from file extension
        if filename.endswith(".json"):
            return self._export_json(file_path)
        elif filename.endswith(".pdf") or filename.endswith(".html"):
            return self._export_binary(file_path)
        else:
            raise ReportExportError(f"Unsupported file format: {filename}")
    
    def search_by_target(self, target_identifier: str, format: str = "pdf") -> bytes | dict[str, Any]:
        """
        Search for reports by target identifier and export the most recent match.
        
        Args:
            target_identifier: The target identifier to search for (substring match)
            format: The report format to export (pdf, html, or json)
            
        Returns:
            bytes for PDF/HTML reports, dict for JSON reports
            
        Raises:
            ReportExportError: If no matching report is found or format is invalid
        """
        # Validate target_identifier to prevent overly broad matching
        if not target_identifier or not isinstance(target_identifier, str):
            raise ReportExportError("Target identifier must be a non-empty string")
        
        if len(target_identifier) < 3:
            raise ReportExportError("Target identifier must be at least 3 characters long")
        
        if format not in ["pdf", "html", "json"]:
            raise ReportExportError(f"Invalid format: {format}. Must be pdf, html, or json")
        
        # Find all matching files
        matching_files = []
        for file_path in self.output_dir.glob(f"*.{format}"):
            if target_identifier in file_path.name:
                matching_files.append(file_path)
        
        if not matching_files:
            raise ReportExportError(
                f"No {format} reports found for target: {target_identifier}"
            )
        
        # Sort by modification time (most recent first)
        matching_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        
        # Export the most recent match
        most_recent = matching_files[0]
        
        if format == "json":
            return self._export_json(most_recent)
        else:
            return self._export_binary(most_recent)
    
    def list_reports(self) -> list[dict[str, Any]]:
        """
        List all available reports in the output directory.
        
        Returns:
            List of report metadata dictionaries with filename, format, size, and modification time
        """
        reports = []
        
        for file_path in self.output_dir.glob("report_*.*"):
            if file_path.suffix in [".pdf", ".html", ".json"]:
                stat = file_path.stat()
                reports.append({
                    "filename": file_path.name,
                    "format": file_path.suffix[1:],  # Remove the dot
                    "size": stat.st_size,
                    "modified": stat.st_mtime
                })
        
        # Sort by modification time (most recent first)
        reports.sort(key=lambda r: r["modified"], reverse=True)
        
        return reports
    
    def _export_binary(self, file_path: Path) -> bytes:
        """
        Export a binary file (PDF or HTML).
        
        Args:
            file_path: Path to the file to export
            
        Returns:
            File contents as bytes
            
        Raises:
            ReportExportError: If the file cannot be read
        """
        try:
            with open(file_path, "rb") as f:
                return f.read()
        except IOError as e:
            raise ReportExportError(f"Failed to read file {file_path.name}: {str(e)}")
    
    def _export_json(self, file_path: Path) -> dict[str, Any]:
        """
        Export a JSON file as a parsed dictionary.
        
        Args:
            file_path: Path to the JSON file to export
            
        Returns:
            Parsed JSON data as a dictionary
            
        Raises:
            ReportExportError: If the file cannot be read or parsed
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ReportExportError(f"Failed to parse JSON file {file_path.name}: {str(e)}")
        except IOError as e:
            raise ReportExportError(f"Failed to read file {file_path.name}: {str(e)}")
