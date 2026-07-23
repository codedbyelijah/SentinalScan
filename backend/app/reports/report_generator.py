import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, Template
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from app.models.enums import ScanMode, Severity
from app.models.risk_analysis_result import RiskAnalysisResult
from app.models.target import Target


class ReportGenerationError(Exception):
    """Raised when report generation fails."""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class ReportMetadata:
    """Metadata about a generated report."""
    
    def __init__(self, format: str, file_path: str, file_size: int, generated_at: datetime):
        self.format = format
        self.file_path = file_path
        self.file_size = file_size
        self.generated_at = generated_at
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "generated_at": self.generated_at.isoformat()
        }


class ReportGenerator:
    """
    Service for generating security assessment reports.
    
    Generates PDF, HTML, and JSON reports from scan results and risk analysis data.
    """
    
    def __init__(self, output_dir: str = "./reports"):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory where reports will be saved
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup Jinja2 environment for HTML templates
        self.jinja_env = Environment()
    
    def generate(
        self,
        risk_analysis: RiskAnalysisResult,
        target: Target,
        scan_mode: ScanMode,
        enabled_modules: list[str],
        scan_duration: float
    ) -> dict[str, ReportMetadata]:
        """
        Generate reports in all formats (PDF, HTML, JSON).
        
        Args:
            risk_analysis: Risk analysis result from RiskAnalyzer
            target: The target that was scanned
            scan_mode: Scan mode used (Full Scan or Custom Scan)
            enabled_modules: List of enabled scan modules
            scan_duration: Total scan duration in seconds
            
        Returns:
            Dictionary mapping format names to ReportMetadata objects
            
        Raises:
            ReportGenerationError: If report generation fails
        """
        generated_at = datetime.now(timezone.utc)
        
        # Generate filename with timestamp and target identifier
        timestamp = generated_at.strftime("%Y%m%d_%H%M%S")
        target_identifier = self._sanitize_target_identifier(target.normalized_target)
        base_filename = f"report_{timestamp}_{target_identifier}"
        
        # Prepare report data
        report_data = {
            "target": target,
            "scan_mode": scan_mode,
            "enabled_modules": enabled_modules,
            "scan_duration": scan_duration,
            "risk_analysis": risk_analysis,
            "generated_at": generated_at
        }
        
        # Generate reports in all formats
        metadata = {}
        
        try:
            # PDF report
            pdf_path = self.output_dir / f"{base_filename}.pdf"
            self._generate_pdf(pdf_path, report_data)
            metadata["pdf"] = ReportMetadata(
                "pdf",
                str(pdf_path),
                pdf_path.stat().st_size,
                generated_at
            )
            
            # HTML report
            html_path = self.output_dir / f"{base_filename}.html"
            self._generate_html(html_path, report_data)
            metadata["html"] = ReportMetadata(
                "html",
                str(html_path),
                html_path.stat().st_size,
                generated_at
            )
            
            # JSON report
            json_path = self.output_dir / f"{base_filename}.json"
            self._generate_json(json_path, report_data)
            metadata["json"] = ReportMetadata(
                "json",
                str(json_path),
                json_path.stat().st_size,
                generated_at
            )
            
            return metadata
            
        except Exception as e:
            raise ReportGenerationError(f"Failed to generate reports: {str(e)}")
    
    def _sanitize_target_identifier(self, target: str) -> str:
        """
        Sanitize target identifier for use in filenames.
        
        Args:
            target: The target string to sanitize
            
        Returns:
            Sanitized target identifier safe for filenames
        """
        # Remove protocol, replace special characters with underscores
        sanitized = target.replace("://", "_").replace("/", "_").replace(":", "_")
        sanitized = "".join(c if c.isalnum() or c in "._-" else "_" for c in sanitized)
        return sanitized[:50]  # Limit length
    
    def _generate_pdf(self, file_path: Path, report_data: dict[str, Any]) -> None:
        """
        Generate PDF report using reportlab.
        
        Args:
            file_path: Path where PDF will be saved
            report_data: Report data dictionary
        """
        doc = SimpleDocTemplate(str(file_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=18,
            spaceAfter=30,
            textColor="#2c3e50"
        )
        
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            spaceAfter=12,
            textColor="#34495e"
        )
        
        # Title
        story.append(Paragraph("Security Assessment Report", title_style))
        story.append(Spacer(1, 0.2 * inch))
        
        # Scan Summary
        story.append(Paragraph("Scan Summary", heading_style))
        story.append(Spacer(1, 0.1 * inch))
        
        summary_data = [
            ["Target:", report_data["target"].normalized_target],
            ["Scan Mode:", report_data["scan_mode"].value],
            ["Scan Duration:", f"{report_data['scan_duration']:.2f} seconds"],
            ["Generated At:", report_data["generated_at"].strftime("%Y-%m-%d %H:%M:%S UTC")]
        ]
        
        summary_table = Table(summary_data, colWidths=[1.5 * inch, 4 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), "#f8f9fa"),
            ("TEXTCOLOR", (0, 0), (-1, 0), "#2c3e50"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), "#ffffff"),
            ("GRID", (0, 0), (-1, -1), 0.5, "#e0e0e0")
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # Risk Summary
        story.append(Paragraph("Risk Summary", heading_style))
        story.append(Spacer(1, 0.1 * inch))
        
        risk_data = [
            ["Overall Risk:", report_data["risk_analysis"].overall_risk.value],
            ["Total Findings:", str(report_data["risk_analysis"].total_findings)],
            ["Warnings (MEDIUM):", str(report_data["risk_analysis"].warnings)],
            ["Errors (HIGH/CRITICAL):", str(report_data["risk_analysis"].errors)]
        ]
        
        risk_table = Table(risk_data, colWidths=[2 * inch, 3.5 * inch])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), "#f8f9fa"),
            ("TEXTCOLOR", (0, 0), (-1, 0), "#2c3e50"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), "#ffffff"),
            ("GRID", (0, 0), (-1, -1), 0.5, "#e0e0e0")
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # Security Summary
        story.append(Paragraph("Security Summary", heading_style))
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(report_data["risk_analysis"].security_summary, styles["Normal"]))
        story.append(Spacer(1, 0.3 * inch))
        
        # Scan Configuration
        story.append(Paragraph("Scan Configuration", heading_style))
        story.append(Spacer(1, 0.1 * inch))
        
        config_data = [["Enabled Modules:"]]
        for module in report_data["enabled_modules"]:
            config_data.append([f"• {module}"])
        
        config_table = Table(config_data, colWidths=[5.5 * inch])
        config_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), "#f8f9fa"),
            ("TEXTCOLOR", (0, 0), (-1, 0), "#2c3e50"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), "#ffffff"),
            ("VALIGN", (0, 1), (-1, -1), "TOP")
        ]))
        story.append(config_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # Findings
        story.append(Paragraph("Findings", heading_style))
        story.append(Spacer(1, 0.1 * inch))
        
        for result in report_data["risk_analysis"].results:
            for finding in result.findings:
                story.append(Paragraph(f"<b>{finding.title}</b>", styles["Normal"]))
                story.append(Paragraph(f"Severity: {finding.severity.value}", styles["Normal"]))
                story.append(Paragraph(f"Category: {finding.category.value}", styles["Normal"]))
                story.append(Paragraph(f"Target: {finding.affected_target}", styles["Normal"]))
                story.append(Spacer(1, 0.05 * inch))
                story.append(Paragraph(finding.description, styles["Normal"]))
                story.append(Spacer(1, 0.05 * inch))
                story.append(Paragraph(f"<b>Recommendation:</b> {finding.recommendation}", styles["Normal"]))
                story.append(Spacer(1, 0.2 * inch))
        
        doc.build(story)
    
    def _generate_html(self, file_path: Path, report_data: dict[str, Any]) -> None:
        """
        Generate HTML report using Jinja2.
        
        Args:
            file_path: Path where HTML will be saved
            report_data: Report data dictionary
        """
        # Create a simple HTML template
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {{ target.normalized_target }}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
        }
        .summary-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .summary-table th, .summary-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        .summary-table th {
            background-color: #f8f9fa;
            color: #2c3e50;
            width: 200px;
        }
        .finding {
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 20px;
            margin: 15px 0;
            background-color: #fafafa;
        }
        .finding-title {
            font-weight: bold;
            font-size: 18px;
            color: #2c3e50;
        }
        .severity {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
        }
        .severity-CRITICAL { background-color: #e74c3c; color: white; }
        .severity-HIGH { background-color: #e67e22; color: white; }
        .severity-MEDIUM { background-color: #f39c12; color: white; }
        .severity-LOW { background-color: #3498db; color: white; }
        .severity-INFO { background-color: #95a5a6; color: white; }
        .recommendation {
            background-color: #e8f4f8;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Assessment Report</h1>
        
        <h2>Scan Summary</h2>
        <table class="summary-table">
            <tr><th>Target</th><td>{{ target.normalized_target }}</td></tr>
            <tr><th>Scan Mode</th><td>{{ scan_mode.value }}</td></tr>
            <tr><th>Scan Duration</th><td>{{ "%.2f"|format(scan_duration) }} seconds</td></tr>
            <tr><th>Generated At</th><td>{{ generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</td></tr>
        </table>
        
        <h2>Risk Summary</h2>
        <table class="summary-table">
            <tr><th>Overall Risk</th><td>{{ risk_analysis.overall_risk.value }}</td></tr>
            <tr><th>Total Findings</th><td>{{ risk_analysis.total_findings }}</td></tr>
            <tr><th>Warnings (MEDIUM)</th><td>{{ risk_analysis.warnings }}</td></tr>
            <tr><th>Errors (HIGH/CRITICAL)</th><td>{{ risk_analysis.errors }}</td></tr>
        </table>
        
        <h2>Security Summary</h2>
        <p>{{ risk_analysis.security_summary }}</p>
        
        <h2>Scan Configuration</h2>
        <table class="summary-table">
            <tr><th>Enabled Modules</th><td>
                {% for module in enabled_modules %}
                    {{ module }}{% if not loop.last %}, {% endif %}
                {% endfor %}
            </td></tr>
        </table>
        
        <h2>Findings</h2>
        {% for result in risk_analysis.results %}
            {% for finding in result.findings %}
                <div class="finding">
                    <div class="finding-title">
                        {{ finding.title }}
                        <span class="severity severity-{{ finding.severity.value }}">{{ finding.severity.value }}</span>
                    </div>
                    <p><strong>Category:</strong> {{ finding.category.value }}</p>
                    <p><strong>Target:</strong> {{ finding.affected_target }}</p>
                    <p>{{ finding.description }}</p>
                    <div class="recommendation">
                        <strong>Recommendation:</strong> {{ finding.recommendation }}
                    </div>
                </div>
            {% endfor %}
        {% endfor %}
    </div>
</body>
</html>
        """
        
        template = Template(template_str)
        html_content = template.render(**report_data)
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    
    def _generate_json(self, file_path: Path, report_data: dict[str, Any]) -> None:
        """
        Generate JSON report.
        
        Args:
            file_path: Path where JSON will be saved
            report_data: Report data dictionary
        """
        # Convert report data to JSON-serializable format
        json_data = {
            "target": {
                "original_input": report_data["target"].original_input,
                "normalized_target": report_data["target"].normalized_target,
                "target_type": report_data["target"].target_type.value,
                "protocol": report_data["target"].protocol
            },
            "scan_mode": report_data["scan_mode"].value,
            "enabled_modules": report_data["enabled_modules"],
            "scan_duration": report_data["scan_duration"],
            "generated_at": report_data["generated_at"].isoformat(),
            "risk_analysis": {
                "overall_risk": report_data["risk_analysis"].overall_risk.value,
                "security_summary": report_data["risk_analysis"].security_summary,
                "total_findings": report_data["risk_analysis"].total_findings,
                "warnings": report_data["risk_analysis"].warnings,
                "errors": report_data["risk_analysis"].errors
            },
            "findings": []
        }
        
        for result in report_data["risk_analysis"].results:
            for finding in result.findings:
                json_data["findings"].append({
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "category": finding.category.value,
                    "affected_target": finding.affected_target,
                    "recommendation": finding.recommendation,
                    "module_name": result.module_name
                })
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
