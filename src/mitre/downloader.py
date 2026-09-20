import os
import requests
from pathlib import Path
from typing import Optional

ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_RAW_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "mitre" / "raw"
DEFAULT_RAW_FILE = DEFAULT_RAW_DIR / "enterprise-attack.json"


def download_enterprise_attack(
    output_path: Optional[Path] = None,
    force_download: bool = False
) -> Path:
    """
    Downloads the official MITRE Enterprise ATT&CK STIX bundle if not already present.
    
    Args:
        output_path: Path where the file should be saved. Defaults to data/mitre/raw/enterprise-attack.json
        force_download: If True, re-downloads even if the file exists.
        
    Returns:
        Path to the downloaded enterprise-attack.json file.
    """
    target = output_path or DEFAULT_RAW_FILE
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists() and not force_download and target.stat().st_size > 10_000_000:
        print(f"[MITRE Downloader] Using cached STIX bundle at: {target} ({target.stat().st_size / (1024*1024):.2f} MB)")
        return target

    print(f"[MITRE Downloader] Downloading official MITRE Enterprise ATT&CK bundle from {ENTERPRISE_ATTACK_URL}...")
    response = requests.get(ENTERPRISE_ATTACK_URL, stream=True, timeout=60)
    response.raise_for_status()

    total_size = int(response.headers.get("content-length", 0))
    chunk_size = 1024 * 1024  # 1MB chunks
    downloaded = 0

    temp_target = target.with_suffix(".tmp")
    with open(temp_target, "wb") as f:
        for chunk in response.iter_content(chunk_size=chunk_size):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    print(f"\rDownloading: {downloaded / (1024*1024):.1f}MB / {total_size / (1024*1024):.1f}MB ({percent:.1f}%)", end="", flush=True)
                else:
                    print(f"\rDownloading: {downloaded / (1024*1024):.1f}MB", end="", flush=True)

    print("\n[MITRE Downloader] Download complete. Validating...")
    if temp_target.stat().st_size < 1_000_000:
        temp_target.unlink(missing_ok=True)
        raise ValueError(f"Downloaded file is suspiciously small ({temp_target.stat().st_size} bytes). Download may have failed.")

    if target.exists():
        target.unlink()
    temp_target.rename(target)
    print(f"[MITRE Downloader] Saved STIX bundle to: {target} ({target.stat().st_size / (1024*1024):.2f} MB)")
    return target


if __name__ == "__main__":
    download_enterprise_attack()
