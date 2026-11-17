import asyncio
import re
from collections.abc import Callable, Iterable
from time import perf_counter

import httpx
from packageurl import PackageURL
from pydantic import BaseModel, Field, ValidationError

from .sbom import Package

BATCH_SIZE = 50
MAX_PAGES = 10
MAX_ADVISORIES = 250
ADVISORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


class OSVError(RuntimeError):
    pass


class Severity(BaseModel):
    type: str
    score: str


class AdvisoryRef(BaseModel):
    id: str


class BatchResult(BaseModel):
    vulns: list[AdvisoryRef] = Field(default_factory=list)
    next_page_token: str | None = None


class BatchPage(BaseModel):
    results: list[BatchResult]


class RangeEvent(BaseModel):
    fixed: str | None = None


class AffectedRange(BaseModel):
    events: list[RangeEvent] = Field(default_factory=list)


class AffectedPackage(BaseModel):
    purl: str | None = None


class Affected(BaseModel):
    package: AffectedPackage = Field(default_factory=AffectedPackage)
    ranges: list[AffectedRange] = Field(default_factory=list)


class Advisory(BaseModel):
    id: str
    summary: str = ""
    details: str = ""
    aliases: list[str] = Field(default_factory=list)
    severity: list[Severity] = Field(default_factory=list)
    affected: list[Affected] = Field(default_factory=list)
    withdrawn: str | None = None


class Finding(BaseModel):
    id: int
    advisory_id: str
    url: str
    package: Package
    summary: str
    details: str
    aliases: list[str]
    severity: list[Severity]
    fixed_candidates: list[str]


def coordinates(purl: str) -> tuple[str, str | None, str] | None:
    try:
        parsed = PackageURL.from_string(purl)
    except (ValueError, TypeError):
        return None
    return parsed.type, parsed.namespace, parsed.name


def fixed_candidates(package: Package, advisory: Advisory) -> list[str]:
    # OSV resolves the installed version. These are package-level range endpoints
    # across branches, so callers still need to choose and verify an upgrade.
    identity = coordinates(package.purl)
    values = {
        event.fixed
        for affected in advisory.affected
        if affected.package.purl and coordinates(affected.package.purl) == identity
        for span in affected.ranges
        for event in span.events
        if event.fixed
    }
    return sorted(values)[:20]


Observer = Callable[[str, float], None]


class OSVClient:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def request(self, method: str, path: str, *, observe: Observer | None = None, **kwargs):
        for attempt in range(3):
            started = perf_counter()
            try:
                response = await self.client.request(method, path, **kwargs)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as error:
                status = error.response.status_code
                reason = f"http_{status}"
                if status not in {429, 500, 502, 503, 504}:
                    raise OSVError(f"OSV lookup failed (HTTP {status}).") from error
            except httpx.RequestError as error:
                reason = "timeout" if isinstance(error, httpx.TimeoutException) else "network"
            except ValueError as error:
                raise OSVError("OSV returned invalid JSON.") from error
            if observe:
                observe(("retry_" if attempt < 2 else "failed_") + reason, (perf_counter() - started) * 1000)
            if attempt < 2:
                await asyncio.sleep(0.25 * 2**attempt)
        raise OSVError("OSV is temporarily unavailable. Run the scan again.")

    async def batch(self, packages: Iterable[Package], observe: Observer | None) -> dict[str, set[str]]:
        pending = {package.purl: None for package in packages}
        matches: dict[str, set[str]] = {purl: set() for purl in pending}
        for _ in range(MAX_PAGES):
            if not pending:
                return matches
            queries = [
                {"package": {"purl": purl}, **({"page_token": token} if token else {})}
                for purl, token in pending.items()
            ]
            response = await self.request(
                "POST", "/v1/querybatch", json={"queries": queries}, observe=observe
            )
            page = BatchPage.model_validate(response)
            if len(page.results) != len(pending):
                raise OSVError("OSV returned a result count that does not match the query.")
            next_page = {}
            for (purl, previous_token), result in zip(pending.items(), page.results, strict=True):
                matches[purl].update(vuln.id for vuln in result.vulns)
                if result.next_page_token:
                    if result.next_page_token == previous_token:
                        raise OSVError("OSV returned a repeated page token.")
                    next_page[purl] = result.next_page_token
            pending = next_page
        if pending:
            raise OSVError("OSV pagination exceeded the scan limit.")
        return matches

    async def enrich(self, packages: list[Package], *, observe: Observer | None = None) -> list[Finding]:
        try:
            async with asyncio.timeout(45):
                return await self._enrich(packages, observe)
        except ValidationError as error:
            raise OSVError("OSV returned data in an unexpected format.") from error
        except TimeoutError as error:
            raise OSVError("OSV scan timed out. Try a smaller SBOM.") from error

    async def _enrich(self, packages: list[Package], observe: Observer | None) -> list[Finding]:
        matches = {}
        for start in range(0, len(packages), BATCH_SIZE):
            matches.update(await self.batch(packages[start : start + BATCH_SIZE], observe))
        ids = sorted(set().union(*matches.values()))
        if len(ids) > MAX_ADVISORIES or sum(map(len, matches.values())) > MAX_ADVISORIES:
            raise OSVError("The scan matched too many advisories. Try a smaller SBOM.")
        if any(not ADVISORY_ID.fullmatch(identifier) for identifier in ids):
            raise OSVError("OSV returned an invalid advisory ID.")

        async def fetch(identifier: str) -> Advisory:
            record = await self.request("GET", f"/v1/vulns/{identifier}", observe=observe)
            advisory = Advisory.model_validate(record)
            if advisory.id != identifier:
                raise OSVError("OSV returned the wrong advisory record.")
            return advisory

        advisories = {}
        for start in range(0, len(ids), 8):
            results = await asyncio.gather(
                *(fetch(identifier) for identifier in ids[start : start + 8]), return_exceptions=True
            )
            for result in results:
                if isinstance(result, BaseException):
                    raise result
                advisories[result.id] = result

        findings = []
        for package in packages:
            for identifier in sorted(matches[package.purl]):
                advisory = advisories[identifier]
                if advisory.withdrawn:
                    continue
                findings.append(
                    Finding(
                        id=len(findings) + 1,
                        advisory_id=identifier,
                        url=f"https://osv.dev/vulnerability/{identifier}",
                        package=package,
                        summary=advisory.summary[:300] or identifier,
                        details=advisory.details[:3000],
                        aliases=advisory.aliases[:12],
                        severity=advisory.severity[:6],
                        fixed_candidates=fixed_candidates(package, advisory),
                    )
                )
        return findings
