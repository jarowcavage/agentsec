"""Check the HTTP service and persist an empty scan without contacting upstream providers."""

import argparse
import json
from pathlib import Path
from urllib.request import Request, urlopen


def read(url: str, *, payload: bytes | None = None):
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    with urlopen(Request(url, data=payload, headers=headers), timeout=8) as response:
        return response.status, json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--save", type=Path)
    mode.add_argument("--verify", type=Path)
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    status, health = read(f"{base}/health")
    assert status == 200 and health["status"] == "ok"
    status, sample = read(f"{base}/sample")
    assert status == 200 and sample["bomFormat"] == "CycloneDX"
    if args.save:
        payload = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []})
        status, scan = read(f"{base}/api/scans", payload=payload.encode())
        assert status == 201 and scan["findings"] == []
        args.save.write_text(scan["id"])
    else:
        scan_id = args.verify.read_text().strip()
        status, scan = read(f"{base}/api/scans/{scan_id}")
        assert status == 200 and scan["id"] == scan_id and scan["component_count"] == 0
    print("Service smoke check passed.")


if __name__ == "__main__":
    main()
