from collections import deque
from dataclasses import dataclass, field
from typing import Literal

from packageurl import PackageURL
from pydantic import BaseModel, Field, ValidationError

MAX_UPLOAD = 2 * 1024 * 1024
MAX_COMPONENTS = 250
SUPPORTED_TYPES = {"cargo", "composer", "gem", "golang", "maven", "npm", "nuget", "pypi"}


class InvalidSBOM(ValueError):
    pass


class Component(BaseModel):
    name: str = Field(min_length=1, max_length=512)
    version: str | None = Field(default=None, max_length=512)
    purl: str | None = Field(default=None, max_length=1024)
    ref: str | None = Field(default=None, alias="bom-ref", max_length=1024)
    components: list["Component"] = Field(default_factory=list)


class Metadata(BaseModel):
    component: Component | None = None


class Dependency(BaseModel):
    ref: str = Field(min_length=1, max_length=1024)
    dependsOn: list[str] = Field(default_factory=list)


class CycloneDX(BaseModel):
    bomFormat: Literal["CycloneDX"]
    specVersion: Literal["1.4", "1.5", "1.6", "1.7"]
    metadata: Metadata = Field(default_factory=Metadata)
    components: list[Component] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)


class Package(BaseModel):
    name: str
    purl: str
    version: str
    refs: list[str]
    relationships: list[Literal["direct", "transitive", "unknown"]]


class Skipped(BaseModel):
    name: str
    reason: str


@dataclass
class Inventory:
    component_count: int
    packages: list[Package] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)


def parse_sbom(data: bytes) -> Inventory:
    try:
        bom = CycloneDX.model_validate_json(data.removeprefix(b"\xef\xbb\xbf"))
    except ValidationError as error:
        raise InvalidSBOM("Expected a valid CycloneDX 1.4–1.7 JSON inventory.") from error

    root = bom.metadata.component
    root_ref = root.ref if root else None
    components = list(bom.components)
    if root:
        components.extend(root.components)
    for component in components:
        if len(components) > MAX_COMPONENTS:
            break
        components.extend(component.components)
    if len(components) > MAX_COMPONENTS:
        raise InvalidSBOM(f"Use an SBOM with at most {MAX_COMPONENTS} components.")

    refs = [component.ref for component in components if component.ref]
    if root_ref:
        refs.append(root_ref)
    if len(refs) != len(set(refs)):
        raise InvalidSBOM("Duplicate CycloneDX bom-ref values make dependencies ambiguous.")

    edges = {dependency.ref: dependency.dependsOn for dependency in bom.dependencies}
    if len(edges) != len(bom.dependencies):
        raise InvalidSBOM("Duplicate CycloneDX dependency entries make relationships ambiguous.")
    distances: dict[str, int] = {}
    if root_ref:
        distances[root_ref] = 0
        queue = deque([root_ref])
        while queue:
            parent = queue.popleft()
            for child in edges.get(parent, []):
                if child not in distances:
                    distances[child] = distances[parent] + 1
                    queue.append(child)

    inventory = Inventory(component_count=len(components))
    unique: dict[str, Package] = {}
    for component in components:
        try:
            purl = package_identity(component)
        except ValueError as error:
            inventory.skipped.append(Skipped(name=component.name, reason=str(error)))
            continue
        key = purl.to_string()
        package = unique.get(key)
        if package is None:
            package = Package(name=component.name, purl=key, version=purl.version, refs=[], relationships=[])
            unique[key] = package
        if component.ref:
            package.refs.append(component.ref)
        distance = distances.get(component.ref or "")
        relationship = {1: "direct", None: "unknown"}.get(distance, "transitive")
        if relationship not in package.relationships:
            package.relationships.append(relationship)
    inventory.packages = list(unique.values())
    return inventory


def package_identity(component: Component) -> PackageURL:
    if not component.purl:
        raise ValueError("Missing package URL (purl).")
    try:
        purl = PackageURL.from_string(component.purl)
    except (ValueError, TypeError) as error:
        raise ValueError("Invalid package URL.") from error
    if purl.type not in SUPPORTED_TYPES:
        raise ValueError(f"Unsupported package URL type: {purl.type}.")
    if purl.version and component.version and purl.version != component.version:
        raise ValueError("SBOM version conflicts with the version in the package URL.")
    version = purl.version or component.version
    if not version or any(character.isspace() or not character.isprintable() for character in version):
        raise ValueError("Missing or invalid package version.")
    return PackageURL(type=purl.type, namespace=purl.namespace, name=purl.name, version=version)
