import argparse
import sys
from pathlib import Path
import uvicorn

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main():
    parser = argparse.ArgumentParser(description="Run Cypher AI MITRE ATT&CK Backend Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host IP to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for local development")
    args = parser.parse_args()

    print("=" * 70)
    print(" CYPHER AI - MITRE ATT&CK REST API SERVER")
    print("=" * 70)
    print(f" -> Listening at: http://{args.host}:{args.port}")
    print(f" -> OpenAPI Docs: http://{args.host}:{args.port}/docs")
    print(f" -> ReDoc Docs:   http://{args.host}:{args.port}/redoc")
    print("=" * 70)

    uvicorn.run(
        "src.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
