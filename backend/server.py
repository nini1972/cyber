import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import List
from dotenv import load_dotenv
from agents import Agent, Runner, trace

from context import SECURITY_RESEARCHER_INSTRUCTIONS, get_analysis_prompt, enhance_summary
from mcp_servers import run_semgrep_scan, format_semgrep_results_for_agent

load_dotenv()

app = FastAPI(title="Cybersecurity Analyzer API")

# Configure CORS for development and production
cors_origins = [
    "http://localhost:3000",    # Local development
    "http://frontend:3000",     # Docker development
]

# In production, allow same-origin requests (static files served from same domain)
if os.getenv("ENVIRONMENT") == "production":
    cors_origins.append("*")  # Allow all origins in production since we serve frontend from same domain

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    code: str


class SecurityIssue(BaseModel):
    title: str = Field(description="Brief title of the security vulnerability")
    description: str = Field(
        description="Detailed description of the security issue and its potential impact"
    )
    code: str = Field(
        description="The specific vulnerable code snippet that demonstrates the issue"
    )
    fix: str = Field(description="Recommended code fix or mitigation strategy")
    cvss_score: float = Field(description="CVSS score from 0.0 to 10.0 representing severity")
    severity: str = Field(description="Severity level: critical, high, medium, or low")


class SecurityReport(BaseModel):
    summary: str = Field(description="Executive summary of the security analysis")
    issues: List[SecurityIssue] = Field(description="List of identified security vulnerabilities")


def validate_request(request: AnalyzeRequest) -> None:
    """Validate the analysis request."""
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="No code provided for analysis")


def check_api_keys() -> None:
    """Verify required API keys are configured."""
    if not os.getenv("OPENAI_API_KEY"):
        raise HTTPException(status_code=500, detail="OpenAI API key not configured")


def create_security_agent() -> Agent:
    """Create and configure the security analysis agent."""
    return Agent(
        name="Security Researcher",
        instructions=SECURITY_RESEARCHER_INSTRUCTIONS,
        model="gpt-4.1-mini",
        output_type=SecurityReport,
    )


async def run_security_analysis(code: str) -> SecurityReport:
    """Execute the security analysis workflow."""
    print("[DEBUG] Starting security analysis workflow...")

    # Run semgrep scan
    print("[DEBUG] Running semgrep scan...")
    semgrep_results = run_semgrep_scan(code)
    formatted_results = format_semgrep_results_for_agent(semgrep_results)
    print(f"[DEBUG] Semgrep results: {formatted_results[:200]}...")

    # Run AI analysis with semgrep results
    with trace("Security Researcher"):
        print("[DEBUG] Creating security agent...")
        agent = create_security_agent()
        print("[DEBUG] Running agent analysis...")
        result = await Runner.run(agent, input=get_analysis_prompt(code, formatted_results))
        print("[DEBUG] Agent analysis completed")
        return result.final_output_as(SecurityReport)


def format_analysis_response(code: str, report: SecurityReport) -> SecurityReport:
    """Format the final analysis response."""
    enhanced_summary = enhance_summary(len(code), report.summary)
    return SecurityReport(summary=enhanced_summary, issues=report.issues)


@app.post("/api/analyze", response_model=SecurityReport)
async def analyze_code(request: AnalyzeRequest) -> SecurityReport:
    """
    Analyze Python code for security vulnerabilities using OpenAI Agents and Semgrep.

    This endpoint combines static analysis via Semgrep with AI-powered security analysis
    to provide comprehensive vulnerability detection and remediation guidance.
    """
    print("[DEBUG] /api/analyze endpoint called")
    validate_request(request)
    print("[DEBUG] Request validated")
    check_api_keys()
    print("[DEBUG] API keys checked")

    try:
        report = await run_security_analysis(request.code)
        print("[DEBUG] Analysis completed successfully")
        return format_analysis_response(request.code, report)
    except Exception as e:
        print(f"[DEBUG] Error in analyze_code: {type(e).__name__}: {str(e)}")
        import traceback
        print(f"[DEBUG] Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"message": "Cybersecurity Analyzer API"}


@app.get("/network-test")
async def network_test():
    """Test network connectivity to Semgrep API."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get("https://semgrep.dev/api/v1/")
            return {
                "semgrep_api_reachable": True,
                "status_code": response.status_code,
                "response_size": len(response.content)
            }
    except Exception as e:
        return {
            "semgrep_api_reachable": False,
            "error": str(e)
        }


@app.get("/semgrep-test")
async def semgrep_test():
    """Test if semgrep CLI can be installed and run."""
    import subprocess
    import tempfile
    import os

    try:
        # Test if we can run semgrep via uvx
        result = subprocess.run(
            ["uvx", "--quiet", "semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=60
        )

        return {
            "semgrep_available": True,
            "version_check": result.returncode == 0,
            "version_output": result.stdout,
            "version_error": result.stderr
        }

    except subprocess.TimeoutExpired:
        return {
            "semgrep_available": False,
            "error": "Timeout during semgrep version check"
        }
    except Exception as e:
        return {
            "semgrep_available": False,
            "error": str(e)
        }


@app.get("/env-check")
async def env_check():
    """Check environment variables configuration."""
    return {
        "OPENAI_API_KEY": {
            "set": bool(os.getenv("OPENAI_API_KEY")),
            "length": len(os.getenv("OPENAI_API_KEY", "")),
            "prefix": os.getenv("OPENAI_API_KEY", "")[:7] + "..." if os.getenv("OPENAI_API_KEY") else None
        },
        "SEMGREP_APP_TOKEN": {
            "set": bool(os.getenv("SEMGREP_APP_TOKEN")),
            "length": len(os.getenv("SEMGREP_APP_TOKEN", "")),
            "prefix": os.getenv("SEMGREP_APP_TOKEN", "")[:7] + "..." if os.getenv("SEMGREP_APP_TOKEN") else None
        },
        "ENVIRONMENT": os.getenv("ENVIRONMENT", "not set")
    }


# Mount static files for frontend without shadowing API routes
if os.path.exists("static"):
    static_dir = "static"

    # Serve static assets under /static to avoid colliding with API paths
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        index_path = os.path.join(static_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        raise HTTPException(status_code=404, detail="Index file not found")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # Try to serve the exact file if it exists
        file_path = os.path.join(static_dir, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)

        # Fallback to index.html for client-side routing
        index_path = os.path.join(static_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)

        raise HTTPException(status_code=404, detail="Page not found")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
