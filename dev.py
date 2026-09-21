import subprocess
import sys

backend = subprocess.Popen([sys.executable, "scripts/run_server.py"])
frontend = subprocess.Popen(["npm", "run", "dev"], cwd="frontend", shell=True)

try:
    backend.wait()
    frontend.wait()
except KeyboardInterrupt:
    backend.kill()
    frontend.kill()
