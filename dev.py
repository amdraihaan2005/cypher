import os
import subprocess
import sys
import time
from dotenv import load_dotenv

load_dotenv()


def terminate_process(proc: subprocess.Popen) -> None:
    """Terminate a subprocess and its entire child process tree cleanly."""
    if proc.poll() is None:
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def main() -> None:
    print("==================================================")
    print("      Starting Cypher AI Development Environment  ")
    print("==================================================")
    print("Backend:  http://localhost:8000 (API & Docs)")
    print("Frontend: http://localhost:5173 (React UI)")
    print("Press Ctrl+C to terminate both servers.\n")

    backend = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.api.app:app", "--reload", "--port", "8000"]
    )
    frontend = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd="frontend",
        shell=True,
    )

    try:
        while True:
            b_poll = backend.poll()
            f_poll = frontend.poll()
            if b_poll is not None:
                print(f"\n[dev.py] Backend exited unexpectedly with code {b_poll}")
                break
            if f_poll is not None:
                print(f"\n[dev.py] Frontend exited unexpectedly with code {f_poll}")
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[dev.py] Gracefully shutting down Cypher AI development servers...")
    finally:
        terminate_process(backend)
        terminate_process(frontend)
        print("[dev.py] Dev servers stopped cleanly.")


if __name__ == "__main__":
    main()
