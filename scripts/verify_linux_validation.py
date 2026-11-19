"""Opt-in Linux sandbox acceptance. Real PyPI downloads; no AI or GitHub writes."""

import asyncio
import json
import tempfile
from pathlib import Path

from agentsec.investigation.tools import prepare, validate_folder


async def main():
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        candidate = await prepare(work)
        (work / "after/requirements.txt").write_text(f"urllib3=={candidate}\n")
        before = validate_folder(work / "before")
        after = validate_folder(work / "after")
        assert before["checks"] == after["checks"] == 3
        assert not before["passed"] and after["passed"], (before, after)
        print(json.dumps({"before": before, "after": after, "candidate": candidate}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
